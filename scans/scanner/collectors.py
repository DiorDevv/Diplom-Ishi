from urllib.parse import urljoin
import httpx
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10.0
MAX_ASSETS = 20
MAX_ASSET_BYTES = 2_000_000  # 2MB

def fetch_url(client: httpx.Client, url: str, method="GET"):
    r = client.request(method, url, follow_redirects=True)
    return r

def collect_headers_and_html(target_url: str):
    with httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "WebSecAnalyzer/1.0"}) as client:
        resp = fetch_url(client, target_url, "GET")
        headers = dict(resp.headers)
        html = resp.text if "text/html" in headers.get("content-type", "") else resp.text
        final_url = str(resp.url)
        return final_url, headers, html

def extract_assets(base_url: str, html: str):
    soup = BeautifulSoup(html, "lxml")
    assets = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            assets.append(urljoin(base_url, src))

    for tag in soup.find_all("link"):
        href = tag.get("href")
        rel = " ".join(tag.get("rel", [])).lower()
        if href and ("stylesheet" in rel or href.endswith(".css")):
            assets.append(urljoin(base_url, href))

    # unique + limit
    uniq = []
    seen = set()
    for a in assets:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq[:MAX_ASSETS]

def fetch_asset_content(asset_url: str):
    with httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "WebSecAnalyzer/1.0"}) as client:
        r = fetch_url(client, asset_url, "GET")
        content = r.content[:MAX_ASSET_BYTES]
        ctype = r.headers.get("content-type", "")
        return ctype, content
