from __future__ import annotations

from pathlib import Path
import re
import sys

TEXT_SUFFIXES = {".md", ".py", ".json", ".toml", ".txt", ".yml", ".yaml"}
RUSSIAN_SPECIFIC = re.compile("[" + "".join(chr(cp) for cp in (1099, 1067, 1101, 1069, 1105, 1025, 1098, 1066)) + "]")
LOCALE_MARKERS = [
    re.compile(r"/ru(?:/|\\b)", re.IGNORECASE),
    re.compile(r"ru-RU", re.IGNORECASE),
    re.compile(r"ru_RU", re.IGNORECASE),
    re.compile(r"lang=[\"']ru[\"']", re.IGNORECASE),
    re.compile(r"hreflang=[\"']ru[\"']", re.IGNORECASE),
]

# Files that contain policy code for detecting prohibited locale markers are excluded
# from the literal marker scan; they remain subject to Russian-specific character scan.
POLICY_CODE = {Path("src/brama_assurance/audit.py"), Path("src/brama_assurance/monitor.py")}


def audit(root: Path) -> list[str]:
    failures: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        if RUSSIAN_SPECIFIC.search(text):
            failures.append(f"Russian-specific Cyrillic character found: {rel}")
        if rel not in POLICY_CODE:
            for marker in LOCALE_MARKERS:
                if marker.search(text):
                    failures.append(f"Russian locale marker found: {rel}")
                    break
        if rel.name == "sanitized-event.schema.json" and ("raw_" + "content" in text or '"content"' in text):
            failures.append(f"Potential raw-content field found: {rel}")
    return failures


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    failures = audit(root)
    if failures:
        print("DDC clean-corpus audit: FAIL")
        for item in failures:
            print(f"- {item}")
        return 1
    print("DDC clean-corpus audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
