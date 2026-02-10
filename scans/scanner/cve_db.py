# Minimal mock CVE database for demo.
# Key: (component_name, version_prefix) -> list of CVEs
MOCK = {
    ("django", "3.2"): [
        {
            "cve_id": "CVE-2023-XXXX",
            "cvss": "7.5",
            "summary": "Demo: Django 3.2.x uchun misol zaiflik (mock).",
            "fixed_in": "3.2.25",
            "references": ["https://example.com/advisory"]
        }
    ]
}

def lookup_cves(name: str, version: str) -> list[dict]:
    name = (name or "").lower()
    version = (version or "").strip()

    hits = []
    for (n, vprefix), items in MOCK.items():
        if n == name and version.startswith(vprefix):
            hits.extend(items)
    return hits
