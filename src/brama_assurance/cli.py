from __future__ import annotations

import argparse
import json
from .monitor import run_live, serialize


def main() -> int:
    parser = argparse.ArgumentParser(description="BRAMA Proofline public integrity monitor")
    parser.add_argument("--live", action="store_true", help="perform bounded public checks")
    args = parser.parse_args()
    if not args.live:
        parser.error("--live is required; no implicit network access")
    evidence, findings, errors = run_live()
    print(json.dumps(serialize(evidence, findings, errors), ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
