"""
Stage 6: LLM-generated Frida instrumentation script

Uses confirmed taint sources (from Stage 5) to prompt the LLM to generate
a targeted Frida script that hooks those exact methods and logs exfiltrated data.
The script is entirely derived from prior stages — nothing is hardcoded.
"""
import json
import os
import re

from groq import Groq

# Groq retired llama-3.3-70b-versatile; override with LOANWATCH_MODEL.
MODEL = os.environ.get("LOANWATCH_MODEL", "llama-3.3-70b-versatile")


def _dalvik_to_java(dalvik_class: str) -> str:
    """Convert Lcom/example/Foo; → com.example.Foo"""
    return dalvik_class.lstrip("L").rstrip(";").replace("/", ".")


def run(confirmed_sources: list, app_name: str, package: str,
        groq_api_key: str, verbose: bool = True) -> dict:
    """
    confirmed_sources: list from Stage 5 — methods confirmed to collect/exfiltrate data
    app_name, package: from Stage 2 manifest info

    Returns:
        {
          "frida_script": "Java.perform(function() { ... })",
          "hooked_methods": [{class, method, purpose}, ...]
        }
    """
    if not confirmed_sources:
        return {
            "frida_script": "// No confirmed sources to instrument.",
            "hooked_methods": [],
        }

    if verbose:
        print("[Stage 6] Generating Frida script from confirmed sources...")

    # Prioritise app-specific (non-library) classes; cap at 15 to stay within token limits
    def _priority(s):
        cls = s.get("source_class", "")
        # Short obfuscated names (e.g. Lji;, Llq;) or app package = highest priority
        bare = cls.lstrip("L").rstrip(";")
        if len(bare) <= 3 or "loancloud" in cls or "easycash" in cls:
            return 0
        return 1

    dedupe_key = lambda s: (s.get("source_class", ""), s.get("source_method", ""))
    seen_keys = set()
    ranked = []
    for s in sorted(confirmed_sources, key=_priority):
        k = dedupe_key(s)
        if k not in seen_keys:
            seen_keys.add(k)
            ranked.append(s)
    confirmed_sources = ranked[:15]

    # Build a structured summary of what to hook
    hooks_summary = []
    for s in confirmed_sources:
        java_class          = _dalvik_to_java(s.get("source_class", ""))
        method              = s.get("source_method", "")
        source_params       = s.get("source_params", [])        # exact param types from FlowDroid
        dispatcher_class    = s.get("dispatcher_class", "")     # app method that calls network
        dispatcher_method   = s.get("dispatcher_method", "")
        dispatcher_params   = s.get("dispatcher_params", [])
        sink_class          = s.get("sink_class", "")           # actual network API class
        sink_method         = s.get("sink_method", "")
        data_type           = s.get("data_type", "unknown")
        permission          = s.get("permission", "")
        hooks_summary.append({
            "source_class":       java_class,
            "source_method":      method,
            "source_params":      source_params,       # use for .overload(...) in Frida
            "dispatcher_class":   dispatcher_class,    # intermediate app method
            "dispatcher_method":  dispatcher_method,
            "dispatcher_params":  dispatcher_params,  # use for .overload(...) on dispatcher
            "sink_class":         sink_class,          # network API
            "sink_method":        sink_method,
            "data_type":          data_type,
            "permission":         permission,
        })

    client = Groq(api_key=groq_api_key)

    prompt = f"""You are an Android security researcher writing a Frida dynamic instrumentation script.

Target app: {app_name} (package: {package})

The following confirmed taint paths were found by FlowDroid — each entry describes
the full chain from data collection to network transmission:

{json.dumps(hooks_summary, indent=2)}

For EACH taint path, write hooks at THREE levels:

1. SOURCE hook (source_class.source_method) — where sensitive data is collected.
   - Use .overload(source_params[0], source_params[1], ...) if source_params is non-empty,
     to target the exact method signature and avoid "ambiguous method" errors.
   - Log all arguments and the return value.

2. DISPATCHER hook (dispatcher_class.dispatcher_method) — the app method that packages
   and sends the data to the network. Log its arguments to see the payload being transmitted.

3. SINK hook (sink_class.sink_method) — the actual network call. Log arguments to capture
   the final serialized payload and any URL/endpoint visible in the arguments.

Additional rules:
- Wrap each hook in its own try/catch inside Java.perform() so one failure doesn't break others
- Use setTimeout per hook group (100ms increments) to ensure the app has loaded
- Add a comment above each hook saying what data it captures and why
- Use only standard Frida Java bridge APIs (Java.perform, Java.use)
- Do NOT hardcode any data values — only log what you observe at runtime
- Deduplicate: if dispatcher or sink appears in multiple paths, hook it only once

Output ONLY the Frida JavaScript. No explanation, no markdown fences, no extra text.
"""

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=6144,
    )

    script = resp.choices[0].message.content.strip()
    script = re.sub(r"<think>.*?</think>", "", script, flags=re.S).strip()

    # Strip accidental markdown fences
    script = re.sub(r'^```[a-z]*\n?', '', script, flags=re.MULTILINE)
    script = re.sub(r'\n?```$', '', script, flags=re.MULTILINE)
    script = script.strip()

    if verbose:
        print(f"[Stage 6] Generated Frida script ({len(script)} chars)")
        print(f"[Stage 6] Hooks: {[h['source_class'] + '.' + h['source_method'] for h in hooks_summary]}")

    return {
        "frida_script": script,
        "hooked_methods": hooks_summary,
    }
