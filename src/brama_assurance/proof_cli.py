from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .bundle import verify_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a BRAMA Proofline proof bundle offline")
    parser.add_argument("proof", type=Path, help="path to a JSON proof bundle")
    args = parser.parse_args()
    data = json.loads(args.proof.read_text(encoding="utf-8"))
    report = verify_bundle(data)
    print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
    return 0 if report.integrity_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
