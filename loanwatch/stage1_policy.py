"""
Stage 1: Policy PDF → LLM → Prohibited permissions

Reads the regulatory PDF, locates the relevant clause,
and asks the LLM to extract prohibited data types and their
corresponding Android permissions.
"""
import json
import re

import fitz  # PyMuPDF
from groq import Groq

MODEL = "llama-3.3-70b-versatile"


def _extract_pdf_text(pdf_path: str) -> str:
    doc = fitz.open(pdf_path)
    return "\n".join(page.get_text() for page in doc)


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


def run(pdf_path: str, groq_api_key: str, clause_num: int = 15,
        verbose: bool = True) -> dict:
    """
    Returns:
        {
          "clause_text": "...",
          "prohibited_data": ["call_logs", "contacts", "photos"],
          "permissions": ["READ_CALL_LOG", "READ_CONTACTS", ...]
        }
    """
    if verbose:
        print("[Stage 1] Reading policy PDF...")

    full_text = _extract_pdf_text(pdf_path)
    clause_text = _find_clause(full_text, clause_num)

    if verbose:
        print(f"[Stage 1] Clause {clause_num}:\n  {clause_text[:200]}...")

    client = Groq(api_key=groq_api_key)

    prompt = f"""You are a mobile security compliance expert.

The following is Clause {clause_num} from a Nigerian digital lending regulatory document:

---
{clause_text}
---

Your task:
1. Identify every type of user data that the clause PROHIBITS the app from accessing.
2. For each prohibited data type, list the corresponding Android permissions (use exact permission names like READ_CONTACTS, READ_CALL_LOG, etc.).

Respond with ONLY valid JSON in this exact format:
{{
  "prohibited_data": ["call_logs", "contacts", "photos", "gallery"],
  "permissions": ["READ_CALL_LOG", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "CAMERA"]
}}
"""

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=512,
    )

    raw = resp.choices[0].message.content.strip()

    # Extract JSON block
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        result = json.loads(json_match.group(0))
    else:
        result = json.loads(raw)

    result["clause_text"] = clause_text

    if verbose:
        print(f"[Stage 1] Prohibited data: {result['prohibited_data']}")
        print(f"[Stage 1] Permissions: {result['permissions']}")

    return result
