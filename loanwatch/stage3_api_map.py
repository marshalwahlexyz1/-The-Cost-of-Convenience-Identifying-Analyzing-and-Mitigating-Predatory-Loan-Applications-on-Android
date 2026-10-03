"""
Stage 3: Permission → Android API identifiers (LLM)

Given the violated permissions, asks the LLM to produce the Android
API class/method identifiers that would be used to access that data.
These become the Androguard search targets in Stage 4.
"""
import json
import os
import re

from groq import Groq

# Groq retired llama-3.3-70b-versatile; override with LOANWATCH_MODEL.
MODEL = os.environ.get("LOANWATCH_MODEL", "llama-3.3-70b-versatile")


def run(violated_permissions: list, prohibited_data: list,
        groq_api_key: str, verbose: bool = True) -> dict:
    """
    Returns:
        {
          "api_targets": [
            {
              "permission": "READ_CONTACTS",
              "data_type": "contacts",
              "identifiers": ["ContactsContract", "getContentResolver", "Contacts/People"]
            },
            ...
          ]
        }
    """
    if verbose:
        print("[Stage 3] Mapping permissions to Android APIs...")

    client = Groq(api_key=groq_api_key)

    prompt = f"""You are an Android security expert.

The following Android permissions were found to be prohibited by a regulatory clause:
{json.dumps(violated_permissions, indent=2)}

These permissions protect access to the following data types:
{json.dumps(prohibited_data, indent=2)}

For each permission, list the Android API identifiers (class names, method names, content URIs,
or string patterns) that an app would use in its bytecode to actually ACCESS that data.
Focus on identifiers that would appear in Dalvik bytecode as method invocations or string constants.

Respond with ONLY valid JSON in this exact format:
{{
  "api_targets": [
    {{
      "permission": "READ_CONTACTS",
      "data_type": "contacts",
      "identifiers": ["ContactsContract", "Contacts/People", "getContentResolver", "query", "Phone/CONTENT_URI"]
    }},
    {{
      "permission": "READ_CALL_LOG",
      "data_type": "call_logs",
      "identifiers": ["CallLog", "Calls/CONTENT_URI", "getContentResolver"]
    }},
    {{
      "permission": "READ_EXTERNAL_STORAGE",
      "data_type": "photos",
      "identifiers": ["MediaStore", "Images/Media", "DIRECTORY_PICTURES", "DIRECTORY_DCIM"]
    }}
  ]
}}

Include only the permissions from the input list. Be specific — list the actual Java class/method names
that appear in Android API calls, not just descriptions.
"""

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=3072,
    )

    raw = resp.choices[0].message.content.strip()
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip()

    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        result = json.loads(json_match.group(0))
    else:
        result = json.loads(raw)

    if verbose:
        for target in result.get("api_targets", []):
            print(f"[Stage 3] {target['permission']} → {target['identifiers']}")

    return result
