import re

def fingerprint_stack(signals: list[str]) -> dict:
    # simple weighted scoring
    score = {"wordpress": 0, "django": 0, "nextjs": 0}
    for s in signals:
        if "hint:wordpress" in s or "wp-" in s:
            score["wordpress"] += 5
        if "hint:django" in s:
            score["django"] += 3
        if "hint:nextjs" in s:
            score["nextjs"] += 4
        if s.startswith("server:"):
            # not a framework, but helpful
            pass

    stack = max(score, key=score.get)
    confidence = min(95, 40 + score[stack] * 10) if score[stack] > 0 else 20
    return {"primary": stack if score[stack] > 0 else "unknown", "confidence": confidence, "scores": score}

def detect_versions_from_signals(signals: list[str], headers: dict, html: str) -> list[dict]:
    components = []

    # server header version (sometimes)
    server = headers.get("server") or headers.get("Server") or ""
    if server:
        components.append({"name": "server", "version": server, "confidence": 40})

    # generator meta (sometimes includes version)
    m = re.search(r'meta-generator:([^\s]+)', " ".join(signals))
    if m:
        components.append({"name": "generator", "version": m.group(1), "confidence": 60})

    # WordPress version sometimes leaks (rare)
    wm = re.search(r'content=["\']wordpress\s*([0-9\.]+)["\']', html, re.I)
    if wm:
        components.append({"name": "wordpress", "version": wm.group(1), "confidence": 80})

    # de-duplicate by name
    uniq = {}
    for c in components:
        key = c["name"]
        if key not in uniq or c["confidence"] > uniq[key]["confidence"]:
            uniq[key] = c
    return list(uniq.values())
