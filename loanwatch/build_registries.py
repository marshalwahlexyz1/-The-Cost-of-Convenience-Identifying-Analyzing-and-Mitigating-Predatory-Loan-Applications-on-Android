#!/usr/bin/env python3
"""
Build loanwatch/data/registries.json from the lender lists in LoanApps/.

Sources
  * the paper's dataset (LoanApps/report.csv …): package → country + Approved/Delisted
  * official registry PDFs in LoanApps/LoanPolicyandlist/: lender / app names
  * optional extra CSVs in loanwatch/data/registries/*.csv with columns
        name,package,country,status,source,date
    (add new national lists there without touching code)

Run again after adding or updating a list:
    python3 build_registries.py
"""
import csv
import glob
import json
import os
import re

import fitz  # PyMuPDF

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LISTS = os.path.join(REPO, "LoanApps", "LoanPolicyandlist")
OUT = os.path.join(HERE, "data", "registries.json")

# file name → how to describe it.  kind: licensed | reported | third_party_*
PDF_SOURCES = {
    "kenya LicencedDCPsJune2024.pdf": dict(
        country="Kenya", kind="licensed", date="2024-06-26",
        source="Central Bank of Kenya – Directory of Digital Credit Providers",
        label="Licensed digital credit provider (CBK)"),
    "indonesia Penyelenggara Fintech Lending Berizin di OJK per 9 Oktober 2023.pdf": dict(
        country="Indonesia", kind="licensed", date="2023-10-09",
        source="OJK – Licensed fintech lending providers",
        label="Licensed fintech lender (OJK)"),
    "pakistan Name-of-Digital-Applications-run-by-the-Lending-NBFC-Jan-12-2025.pdf": dict(
        country="Pakistan", kind="licensed", date="2025-01-12",
        source="SECP – Digital lending apps run by licensed NBFCs",
        label="App of a licensed lending NBFC (SECP)"),
    "pakistan List-of-Apps-Reported-as-of-April-15.pdf": dict(
        country="Pakistan", kind="reported", date="2024-04-15",
        source="SECP – Apps reported (illegal digital lending)",
        label="Reported to SECP as illegal lending app"),
    "philipines List of Recorded Online Lending Platforms - Securities and Exchange Commission.pdf": dict(
        country="Philippines", kind="licensed", date="",
        source="SEC Philippines – Recorded online lending platforms",
        label="Recorded online lending platform (SEC)"),
    "RBI-Approved-Loan-Apps-List-In-India-onendf.com-Green-1.pdf": dict(
        country="India", kind="third_party_licensed", date="",
        source="'RBI approved loan apps' list compiled by onendf.com (not an official RBI list)",
        label="On a third-party 'RBI approved' list"),
    "Fake-Loan-App-List-PDF-Updated.pdf": dict(
        country="India", kind="third_party_reported", date="",
        source="'Fake loan app' list (third-party compilation)",
        label="On a third-party 'fake loan app' list"),
}

# Paper dataset CSVs (later files win on conflicts)
DATASET_CSVS = ["report.csv", "Results/mynewreport_modified_corrected_updated.csv"]

_NOISE = re.compile(
    r"postal|telephone|tel:|e-?mail|physical address|p\.?\s?o\.?\s?box|http|www\.|@|\.com|\.co\.|"
    r"^\d+[.)]?$|kep-|^s-\d|page \d|interest rate|loan amount|starting \d|lakh|"
    r"^(no|s#|s\.no\.?|name|link|url|logo|website|company/developer)$", re.I)
_LEGAL = r"\b(limited|ltd|pvt|private|plc|inc|pt|tbk|company|co|llc|corp|corporation|the)\b"


def normalise(name: str) -> str:
    s = re.sub(r"[^a-z0-9 ]+", " ", (name or "").lower())
    s = re.sub(_LEGAL, " ", s)
    return re.sub(r"\s+", " ", s).strip()


# Single words that appear in these lists but are not lender names
_GENERIC = set("""credit cash loan loans money finance financial lending lender lenders sistem
nama perusahaan website android ios konvensional syariah used now apple app store google play
digital nano bank banks fintech services service limited private online peso mobile wallet
pinjaman dana capital investment investments group holdings""".split())


def _pdf_names(path):
    text = "\n".join(p.get_text() for p in fitz.open(path))
    names = []
    pieces = []
    for raw in text.splitlines():
        # some lists put several numbered entries on one line: "Peso2go 154. Jetpeso"
        pieces += re.split(r"\s\d{1,3}\.\s|[“”\"]", raw)
    for raw in pieces:
        line = re.sub(r"\s+", " ", raw).strip(" |–-*:")
        line = re.sub(r"^\d+[.)]?\s+", "", line)          # "12. Name" → "Name"
        if not (3 <= len(line) <= 70) or not re.search(r"[A-Za-z]{3}", line):
            continue
        if _NOISE.search(line) or re.search(r"\d{5,}", line):
            continue
        names.append(line)
    packages = sorted(set(re.findall(r"details\?id=([A-Za-z0-9_.]+)", text)))
    return names, packages


def build():
    data = {"sources": [], "packages": {}, "names": []}

    # 1. Paper dataset: exact package → status
    seen = {}
    for rel in DATASET_CSVS:
        path = os.path.join(REPO, "LoanApps", rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            for row in csv.DictReader(f):
                pkg = (row.get("Package Name") or "").strip()
                cc = (row.get("Country/Classification") or "").split("/")
                if not pkg or len(cc) != 2:
                    continue
                seen[(pkg, cc[0])] = {
                    "country": cc[0], "status": cc[1].lower(),
                    "app_name": (row.get("App Name") or "").strip(),
                    "source": "LoanWatch paper dataset (ASIA CCS '26)",
                    "label": ("On the national approved-lender list when collected"
                              if cc[1].lower() == "approved"
                              else "Delisted / reported by the regulator when collected"),
                }
    for (pkg, _), entry in seen.items():
        data["packages"].setdefault(pkg, []).append(entry)
    data["sources"].append({"source": "LoanWatch paper dataset (ASIA CCS '26)",
                            "entries": len(seen), "kind": "dataset"})

    # 2. Registry PDFs: names (and packages where the PDF links to Play)
    for fname, meta in PDF_SOURCES.items():
        path = os.path.join(LISTS, fname)
        if not os.path.exists(path):
            print(f"  skip (missing): {fname}")
            continue
        names, pkgs = _pdf_names(path)
        uniq = {}
        for n in names:
            k = normalise(n)
            if len(k) >= 4 and k not in uniq and k not in _GENERIC \
                    and not all(w in _GENERIC for w in k.split()):
                uniq[k] = n
        for k, n in uniq.items():
            data["names"].append({"name": n, "key": k, **meta})
        for p in pkgs:
            data["packages"].setdefault(p, []).append({
                "country": meta["country"], "status": meta["kind"], "app_name": "",
                "source": meta["source"], "label": meta["label"], "date": meta["date"]})
        data["sources"].append({**meta, "entries": len(uniq), "packages": len(pkgs), "file": fname})
        print(f"  {fname}: {len(uniq)} names, {len(pkgs)} packages")

    # 3. Optional user-supplied CSVs
    for path in sorted(glob.glob(os.path.join(HERE, "data", "registries", "*.csv"))):
        with open(path, encoding="utf-8", errors="ignore") as f:
            rows = list(csv.DictReader(f))
        for r in rows:
            meta = {"country": r.get("country", ""), "kind": r.get("status", "licensed"),
                    "date": r.get("date", ""), "source": r.get("source", os.path.basename(path)),
                    "label": r.get("label") or f"{r.get('status', 'listed').title()} ({r.get('source', '')})"}
            if r.get("package"):
                data["packages"].setdefault(r["package"].strip(), []).append(
                    {"status": meta["kind"], "app_name": r.get("name", ""), **meta})
            if r.get("name"):
                data["names"].append({"name": r["name"], "key": normalise(r["name"]), **meta})
        data["sources"].append({"source": os.path.basename(path), "entries": len(rows), "kind": "custom"})

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    print(f"Wrote {OUT}: {len(data['packages'])} packages, {len(data['names'])} names")


if __name__ == "__main__":
    build()
