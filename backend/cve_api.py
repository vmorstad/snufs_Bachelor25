# backend/cve_api.py

import time
import requests
import urllib.parse

# NVD v2.0 endpoint and your API key
NVD_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "5b8ed342-47cb-4a2c-a4d2-90d4e1f0a5f9"

def _call_nvd(params):
    """
    Internal: perform a GET against NVD and return the 'CVE_Items' list.
    Raises on non-200.
    """
    params["apiKey"] = NVD_API_KEY
    resp = requests.get(NVD_URL, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json().get("result", {}).get("CVE_Items", [])

def _extract_vulns(items, max_results):
    """
    Given a list of NVD CVE_Item dicts, extract id, cvss, summary,
    sort by cvss desc, and return up to max_results.
    """
    out = []
    for e in items:
        meta   = e["cve"]["CVE_data_meta"]
        vid    = meta["ID"]
        impact = e.get("impact", {})
        # prefer CVSSv3 > v2
        score = None
        if "baseMetricV3" in impact:
            score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        elif "baseMetricV2" in impact:
            score = impact["baseMetricV2"]["cvssV2"]["baseScore"]

        descs = e["cve"]["description"]["description_data"]
        summary = ""
        if descs:
            # pick english if present
            for d in descs:
                if d.get("lang") == "en":
                    summary = d.get("value","")
                    break
            if not summary:
                summary = descs[0].get("value","")
        if len(summary) > 200:
            summary = summary[:200] + "…"

        if score is not None:
            out.append({"id": vid, "cvss": score, "summary": summary})

    out.sort(key=lambda v: v["cvss"], reverse=True)
    return out[:max_results]

def top_cves(term, max_results=5):
    """
    Query NVD for CVEs by keyword:
      1. full term
      2. version-only (if numeric)
      3. name-only
    Return up to max_results unique CVEs sorted by CVSS descending.
    """
    original = term.strip()
    if not original:
        return []

    # build variations
    parts = original.split(None,1)
    variations = [original]
    # if there's a space, add version-only and name-only
    if len(parts) == 2:
        name, version = parts
        variations.append(version)
        variations.append(name)

    seen = set()
    results = []

    for idx, q in enumerate(variations):
        # keywordSearch = q
        params = {"keywordSearch": q, "resultsPerPage": max_results}
        try:
            items = _call_nvd(params)
        except Exception as e:
            print(f"[CVE_API] NVD lookup failed for '{q}': {e}")
            continue

        vulns = _extract_vulns(items, max_results)
        for v in vulns:
            if v["id"] not in seen:
                seen.add(v["id"])
                results.append(v)
                if len(results) >= max_results:
                    return results

        # throttle before next variation
        if idx < len(variations)-1:
            time.sleep(1)

    return results
