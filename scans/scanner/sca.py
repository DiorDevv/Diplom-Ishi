import json
import re

def parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"([a-zA-Z0-9_\-\.]+)==([0-9][0-9a-zA-Z\.\-]*)", line)
        if m:
            out.append((m.group(1).lower(), m.group(2)))
    return out

def parse_package_lock(text: str) -> list[tuple[str, str]]:
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out

    # npm v7+ packages map
    packages = data.get("packages", {})
    for k, v in packages.items():
        name = v.get("name")
        ver = v.get("version")
        if name and ver:
            out.append((name.lower(), str(ver)))
    return out

def parse_dependencies(file_name: str, file_text: str) -> list[tuple[str, str]]:
    fn = (file_name or "").lower()
    if fn.endswith("requirements.txt"):
        return parse_requirements_txt(file_text)
    if fn.endswith("package-lock.json"):
        return parse_package_lock(file_text)
    # add more parsers later: poetry.lock, yarn.lock, composer.lock...
    return []
