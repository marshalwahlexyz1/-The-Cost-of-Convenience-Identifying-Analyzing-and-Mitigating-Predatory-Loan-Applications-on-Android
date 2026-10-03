"""
Stage 1: Policy PDF → LLM → Prohibited permissions

Reads the regulatory PDF, locates the relevant clause,
and asks the LLM to extract prohibited data types and their
corresponding Android permissions.

If no clause number is given (clause_num=None), the whole document is
searched for data-access language instead, so policies from any regulator
can be used without knowing the clause in advance.
"""
import json
import os
import re

import fitz  # PyMuPDF
from groq import Groq

# Groq retired llama-3.3-70b-versatile; override with LOANWATCH_MODEL.
MODEL = os.environ.get("LOANWATCH_MODEL", "llama-3.3-70b-versatile")


# Words that signal a data-access rule; used to pick excerpts in auto mode
_DATA_KEYWORDS = (
    "contact", "call log", "phone book", "phonebook", "photo", "gallery",
    "image", "media", "camera", "microphone", "audio", "location", "gps",
    "sms", "text message", "messages", "calendar", "device", "storage",
    "file", "personal data", "personal information", "access", "permission",
    "harvest", "collect", "consent", "privacy",
)
_MAX_POLICY_CHARS = 12000   # keeps the prompt inside Groq free-tier limits


def _extract_pdf_text(pdf_path: str) -> str:
    if pdf_path.lower().endswith((".txt", ".md")):
        with open(pdf_path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    doc = fitz.open(pdf_path)
    return "\n".join(page.get_text() for page in doc)


def _clean(text: str) -> str:
    """Drop form-fill underscores and collapse whitespace."""
    text = re.sub(r"_{3,}", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _relevant_excerpts(text: str, limit: int = _MAX_POLICY_CHARS) -> str:
    """Return the whole policy if it is short, otherwise the paragraphs that
    mention user data, in document order, up to `limit` characters."""
    text = _clean(text)
    if len(text) <= limit:
        return text
    paras = [p.strip() for p in re.split(r"\n\s*\n|\n(?=\s*\(?\d{1,3}[.)]\s)", text)
             if p.strip()]
    scored = []
    for i, p in enumerate(paras):
        low = p.lower()
        score = sum(low.count(k) for k in _DATA_KEYWORDS)
        if score:
            scored.append((score, i, p))
    keep, total = set(), 0
    for score, i, p in sorted(scored, key=lambda x: -x[0]):
        if total + len(p) > limit:
            continue
        keep.add(i)
        total += len(p)
    return "\n\n".join(paras[i] for i in sorted(keep)) or text[:limit]


def _normalise_permission(p: str) -> str:
    return p.strip().replace("android.permission.", "").upper()


def _find_clause(text: str, clause_num: int = 15) -> str:
    """Extract text around a numbered clause."""
    pattern = rf"{clause_num}\.\s+.+?(?=\n\s*\d{{1,2}}\.|$)"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(0).strip()
    # Fallback: return ~500 chars around first occurrence of the number
    idx = text.find(f"\n{clause_num}.")
    if idx != -1:
        return text[idx:idx + 600].strip()
    return text[:1000]


def run(pdf_path: str, groq_api_key: str, clause_num=15,
        verbose: bool = True, jurisdiction: str = "Nigerian") -> dict:
    """
    clause_num  : clause to analyse, or None to scan the whole document
    jurisdiction: adjective used in the prompt ("Nigerian", "Kenyan", ...);
                  empty string for a neutral prompt

    Returns:
        {
          "clause_text": "...",
          "prohibited_data": ["call_logs", "contacts", "photos"],
          "permissions": ["READ_CALL_LOG", "READ_CONTACTS", ...],
          "evidence": [{"data_type": "contacts", "quote": "..."}]   # may be empty
        }
    """
    if verbose:
        print("[Stage 1] Reading policy PDF...")

    full_text = _extract_pdf_text(pdf_path)
    if clause_num:
        clause_text = _find_clause(full_text, clause_num)
        label = f"Clause {clause_num}"
    else:
        clause_text = _relevant_excerpts(full_text)
        label = "The data-access provisions"

    if verbose:
        where = f"Clause {clause_num}" if clause_num else "Policy excerpts"
        print(f"[Stage 1] {where}:\n  {_clean(clause_text)[:200]}...")

    client = Groq(api_key=groq_api_key)

    source = f"a {jurisdiction} digital lending regulatory document" if jurisdiction \
        else "a digital lending regulatory or app-store policy document"
    prompt = f"""You are a mobile security compliance expert.

The following is {label} from {source}:

---
{clause_text}
---

Your task:
1. Identify every type of user data that the text PROHIBITS the app from accessing.
   Only include data the text actually restricts; do not add data types it does not mention.
2. For each prohibited data type, list the corresponding Android permissions (use exact permission names like READ_CONTACTS, READ_CALL_LOG, etc.).
3. For each prohibited data type, copy the shortest sentence from the text that supports it.

Respond with ONLY valid JSON in this exact format:
{{
  "prohibited_data": ["call_logs", "contacts", "photos", "gallery"],
  "permissions": ["READ_CALL_LOG", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "CAMERA"],
  "evidence": [{{"data_type": "contacts", "quote": "exact sentence from the text"}}]
}}
"""

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=2048,
    )

    raw = resp.choices[0].message.content.strip()
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip()

    # Extract JSON block
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        result = json.loads(json_match.group(0))
    else:
        result = json.loads(raw)

    result["permissions"] = list(dict.fromkeys(
        _normalise_permission(p) for p in result.get("permissions", []) if p))
    result.setdefault("prohibited_data", [])
    result.setdefault("evidence", [])
    result["clause_text"] = clause_text

    if verbose:
        print(f"[Stage 1] Prohibited data: {result['prohibited_data']}")
        print(f"[Stage 1] Permissions: {result['permissions']}")

    return result
