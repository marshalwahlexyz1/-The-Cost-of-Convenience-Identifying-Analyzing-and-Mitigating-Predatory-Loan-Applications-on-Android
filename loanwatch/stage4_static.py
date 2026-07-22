"""
Stage 4: Static analysis — find API call sites in APK bytecode (Androguard)

Scans the APK bytecode for invocations and string constants matching
the API identifiers from Stage 3. Returns source class/method pairs
that will be fed to FlowDroid as taint sources.
"""
import json
import re
import warnings
warnings.filterwarnings("ignore")

from androguard.misc import AnalyzeAPK


# Prefixes to skip — Android SDK + well-known third-party libraries
# that legitimately use ContentResolver/MediaStore but are not data sources
_SAFE = (
    "Landroid/", "Ljava/", "Ljavax/", "Lkotlin/",
    "Lcom/google/android/", "Ldalvik/",
    # AndroidX / support libraries
    "Landroidx/",
    # Image loading
    "Lcom/bumptech/glide/",
    # Analytics / crash
    "Lcom/google/firebase/",
    "Lcom/crashlytics/", "Lio/fabric/",
    # Social SDKs
    "Lcom/facebook/", "Lcom/twitter/",
    # HTTP libraries (these are sinks, not sources)
    "Lokhttp3/", "Lretrofit2/",
    # OkGo HTTP library internals (db/cache ops that use query() are not data sources)
    "Lcom/lzy/okgo/db/", "Lcom/lzy/okgo/cookie/", "Lcom/lzy/okgo/convert/",
)


def _is_safe(name: str) -> bool:
    return any(name.startswith(s) for s in _SAFE)


def _iter_instructions(method_obj):
    try:
        if method_obj and method_obj.get_code():
            yield from method_obj.get_code().get_bc().get_instructions()
    except Exception:
        return


def run(apk_path: str, api_targets: list, verbose: bool = True) -> dict:
    """
    api_targets: list from Stage 3 — [{permission, data_type, identifiers}, ...]

    Returns:
        {
          "sources": [
            {
              "source_class": "Lji;",
              "source_method": "sd",
              "matched_api": "ContactsContract",
              "permission": "READ_CONTACTS",
              "data_type": "contacts",
              "call_type": "invocation"   # or "string_constant"
            },
            ...
          ]
        }
    """
    if verbose:
        print("[Stage 4] Loading APK for static analysis...")

    apk, _, analysis = AnalyzeAPK(apk_path)

    # Build flat lookup: identifier_lower → {permission, data_type}
    lookup = {}
    for target in api_targets:
        for ident in target.get("identifiers", []):
            lookup[ident.lower()] = {
                "permission": target["permission"],
                "data_type":  target["data_type"],
                "identifier": ident,
            }

    if verbose:
        print(f"[Stage 4] Scanning bytecode for {len(lookup)} API identifiers...")

    sources = []
    seen = set()

    for cls in analysis.get_classes():
        if _is_safe(cls.name):
            continue

        for m in cls.get_methods():
            try:
                for ins in _iter_instructions(m.get_method()):
                    name = ins.get_name()
                    ops  = ins.get_operands()
                    if not ops:
                        continue

                    last = ops[-1]
                    value = str(last[-1]) if isinstance(last, tuple) else str(last)
                    value_lower = value.lower()

                    call_type = None
                    if name.startswith("invoke"):
                        call_type = "invocation"
                    elif name in ("const-string", "const-string/jumbo"):
                        call_type = "string_constant"
                    else:
                        continue

                    for ident_lower, meta in lookup.items():
                        if ident_lower in value_lower:
                            key = (cls.name, m.name, meta["permission"])
                            if key in seen:
                                break
                            seen.add(key)
                            sources.append({
                                "source_class":      cls.name,
                                "source_method":     m.name,
                                "source_descriptor": m.descriptor,
                                "matched_api":       meta["identifier"],
                                "permission":        meta["permission"],
                                "data_type":         meta["data_type"],
                                "call_type":         call_type,
                                "matched_value":     value[:120],
                            })
                            break
            except Exception:
                continue

    # Deduplicate by (class, method) keeping first match
    deduped = []
    seen_cm = set()
    for s in sources:
        k = (s["source_class"], s["source_method"])
        if k not in seen_cm:
            seen_cm.add(k)
            deduped.append(s)

    if verbose:
        print(f"[Stage 4] Found {len(deduped)} source methods:")
        for s in deduped:
            print(f"   • {s['source_class']}->{s['source_method']}  "
                  f"[{s['data_type']}]  via {s['matched_api']}")

    return {"sources": deduped}
