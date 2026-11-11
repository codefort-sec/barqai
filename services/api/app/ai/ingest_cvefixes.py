"""Ingest real CVE fixes from Hugging Face CVEFixes dataset for CodeFort / Barq-AI.

Extracts real-world vulnerability commit diffs across web application CWEs:
- CWE-79: Cross-Site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-22: Path Traversal
- CWE-78: OS Command Injection
- CWE-287: Improper Authentication
- CWE-502: Insecure Deserialization
"""

import sys
from datasets import load_dataset

def fetch_cve_fixes(limit: int = 10):
    print(f"Streaming real CVE fixes from Hugging Face (limit={limit})...")
    ds = load_dataset("janhvi-ag/cvefixes_pyvul_merged", split="train", streaming=True)
    
    extracted = []
    seen_cves = set()

    for item in ds:
        cve_id = item.get("cve_id")
        cwe_name = item.get("cwe_name") or "Security Flaw"
        code_before = (item.get("code_before") or "").strip()
        code_after = (item.get("code_after") or "").strip()
        desc = (item.get("cve_description") or "").strip()
        func_name = item.get("function_name") or "handler"

        if not cve_id or cve_id in seen_cves:
            continue
        if not code_before or not code_after or code_before == code_after:
            continue
        if len(code_before) > 600 or len(code_after) > 600:
            continue
        if len(code_before) < 40 or len(code_after) < 40:
            continue

        seen_cves.add(cve_id)
        extracted.append({
            "cve_id": cve_id,
            "cwe_name": cwe_name,
            "desc": desc[:140],
            "func_name": func_name,
            "code_before": code_before,
            "code_after": code_after,
        })

        if len(extracted) >= limit:
            break

    print(f"Successfully collected {len(extracted)} real CVE fixes!")
    for idx, e in enumerate(extracted, 1):
        print(f"  [{idx}] {e['cve_id']} - {e['cwe_name']} in {e['func_name']}()")

    return extracted

if __name__ == "__main__":
    fetch_cve_fixes(10)
