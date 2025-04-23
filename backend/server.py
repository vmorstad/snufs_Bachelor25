import time
import requests

# NVD v2.0 endpoint and your API key
NVD_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "5b8ed342-47cb-4a2c-a4d2-90d4e1f0a5f9"

def _call_nvd(params):
    params["apiKey"] = NVD_API_KEY
    resp = requests.get(NVD_URL, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json().get("result", {}).get("CVE_Items", [])

def _extract_vulns(items, max_results):
    out = []
    for e in items:
        vid    = e["cve"]["CVE_data_meta"]["ID"]
        impact = e.get("impact", {})
        score  = None
        if "baseMetricV3" in impact:
            score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        elif "baseMetricV2" in impact:
            score = impact["baseMetricV2"]["cvssV2"]["baseScore"]

        descs = e["cve"]["description"]["description_data"]
        summary = ""
        if descs:
            # pick English if available
            for d in descs:
                if d.get("lang") == "en":
                    summary = d.get("value", "")
                    break
            if not summary:
                summary = descs[0].get("value", "")
        if len(summary) > 200:
            summary = summary[:200] + "…"

        if score is not None:
            out.append({"id": vid, "cvss": score, "summary": summary})

    out.sort(key=lambda v: v["cvss"], reverse=True)
    return out[:max_results]

def top_cves(term, max_results=5):
    """
    Query NVD for CVEs by keywordSearch only:
      1. full term
      2. version-only (if present)
      3. name-only
    Returns up to max_results unique CVEs.
    """
    original = term.strip()
    if not original:
        return []

    # Build up to three variations
    parts = original.split(None, 1)
    variations = [original]
    if len(parts) == 2:
        name, version = parts
        variations.append(version)
        variations.append(name)

    seen = set()
    results = []

    for idx, q in enumerate(variations):
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

        # throttle 1s between variations
        if idx < len(variations) - 1:
            time.sleep(1)

    return results
