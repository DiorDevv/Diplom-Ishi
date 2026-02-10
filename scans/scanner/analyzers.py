import re

SEC_HEADERS = [
    ("Content-Security-Policy", "CSP yo‘q (XSS riskini oshiradi)."),
    ("Strict-Transport-Security", "HSTS yo‘q (HTTPS majburiy emas)."),
    ("X-Frame-Options", "X-Frame-Options yo‘q (clickjacking risk)."),
    ("X-Content-Type-Options", "X-Content-Type-Options yo‘q (MIME sniffing risk)."),
    ("Referrer-Policy", "Referrer-Policy yo‘q (maxfiylik risk)."),
]

def analyze_headers(headers: dict) -> tuple[list[dict], list[str]]:
    findings = []
    signals = []

    # tech signals
    server = headers.get("server", "") or headers.get("Server", "")
    x_powered = headers.get("x-powered-by", "") or headers.get("X-Powered-By", "")

    if server:
        signals.append(f"server:{server.lower()}")
    if x_powered:
        signals.append(f"x-powered-by:{x_powered.lower()}")

    # security headers
    for h, msg in SEC_HEADERS:
        if h.lower() not in {k.lower() for k in headers.keys()}:
            findings.append({
                "category": "Headers",
                "severity": "LOW",
                "title": f"{h} mavjud emas",
                "description": msg,
                "recommendation": f"{h} headerini sozlang.",
                "evidence": {},
            })

    # cookies flags
    set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
    if set_cookie:
        low = set_cookie.lower()
        if "httponly" not in low:
            findings.append({
                "category": "Cookies",
                "severity": "MEDIUM",
                "title": "Cookie HttpOnly yo‘q",
                "description": "Session cookie’da HttpOnly bo‘lmasa, XSS bo‘lsa cookie o‘g‘irlanishi osonlashadi.",
                "recommendation": "Session cookie uchun HttpOnly yoqing.",
                "evidence": {"set-cookie": set_cookie[:300]},
            })
        if "secure" not in low:
            findings.append({
                "category": "Cookies",
                "severity": "MEDIUM",
                "title": "Cookie Secure yo‘q",
                "description": "Secure bo‘lmasa cookie HTTP orqali ham yuborilishi mumkin.",
                "recommendation": "HTTPS ishlatilsa cookie’larda Secure flagni yoqing.",
                "evidence": {"set-cookie": set_cookie[:300]},
            })
        if "samesite" not in low:
            findings.append({
                "category": "Cookies",
                "severity": "LOW",
                "title": "Cookie SameSite yo‘q",
                "description": "SameSite yo‘q bo‘lsa CSRF xavfi oshadi.",
                "recommendation": "SameSite=Lax/Strict siyosatini ko‘rib chiqing.",
                "evidence": {"set-cookie": set_cookie[:300]},
            })

    return findings, signals

def analyze_html(html: str) -> tuple[list[dict], list[str]]:
    findings = []
    signals = []
    h = html.lower()

    # WordPress signals
    if "wp-content" in h or "wp-includes" in h:
        signals.append("hint:wordpress")

    # Django-ish signals (very weak; just signal)
    if "csrftoken" in h:
        signals.append("hint:django")

    # generator meta
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m:
        gen = m.group(1).strip()
        signals.append(f"meta-generator:{gen.lower()}")

    return findings, signals

def analyze_asset(ctype: str, content: bytes) -> tuple[list[dict], list[str]]:
    findings = []
    signals = []

    text = ""
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return findings, signals

    low = text.lower()

    # Common library banners (signals)
    if "jquery" in low and "/*! jquery" in low:
        signals.append("lib:jquery")
    if "__next_data__" in low:
        signals.append("hint:nextjs")
    if "webpack" in low:
        signals.append("hint:webpack")

    return findings, signals
