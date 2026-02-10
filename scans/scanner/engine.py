from .safety import normalize_url, validate_target_url
from .collectors import collect_headers_and_html, extract_assets, fetch_asset_content
from .analyzers import analyze_headers, analyze_html, analyze_asset
from .fingerprint import fingerprint_stack, detect_versions_from_signals
from .sca import parse_dependencies
from .cve_db import lookup_cves

def run_passive_scan(target_url: str, dep_file_name: str = "", dep_text: str = "") -> dict:
    normalized = normalize_url(target_url)
    ok, reason = validate_target_url(normalized)
    if not ok:
        raise ValueError(reason)

    report = {
        "normalized_url": normalized,
        "final_url": "",
        "signals": [],
        "findings": [],
        "components": [],
        "cves": [],
        "stack": {"primary": "unknown", "confidence": 0, "scores": {}},
    }

    final_url, headers, html = collect_headers_and_html(normalized)
    report["final_url"] = final_url

    f1, s1 = analyze_headers(headers)
    f2, s2 = analyze_html(html)
    report["findings"].extend(f1)
    report["findings"].extend(f2)
    report["signals"].extend(s1 + s2)

    assets = extract_assets(final_url, html)
    for asset_url in assets:
        ctype, content = fetch_asset_content(asset_url)
        f3, s3 = analyze_asset(ctype, content)
        report["findings"].extend(f3)
        report["signals"].extend(s3)

    report["stack"] = fingerprint_stack(report["signals"])

    # URL-only components
    comps = detect_versions_from_signals(report["signals"], headers, html)
    report["components"].extend(comps)

    # White-box SCA (if provided)
    if dep_text and dep_file_name:
        deps = parse_dependencies(dep_file_name, dep_text)
        for name, ver in deps[:50]:
            report["components"].append({"name": name, "version": ver, "confidence": 95})

    # CVE lookup (mock now)
    for c in report["components"]:
        name = c.get("name", "")
        ver = c.get("version", "")
        if not name or not ver:
            continue
        for item in lookup_cves(name, ver):
            report["cves"].append({"component_name": name, **item})

    return report
