#!/usr/bin/env python3
"""
Prepare baseline Cloud state for attack-detection demos.

Runs a short in-process ingest/search cycle and persists cloud state through
the normal gateway→cloud path. Start gateway with --cloud-url pointing at a
baseline Cloud service on port 8100 before running camera ingest separately,
or use run.py simulation plus deployment ingest as documented below.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run simulation to seed functional state (optional helper)."
    )
    parser.add_argument("--segments", type=int, default=3)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_py = ROOT / "run.py"
    print("[Demo Prepare] Running simulation to validate the codebase...")
    subprocess.check_call([sys.executable, str(run_py), "--segments", str(args.segments)])
    print(
        "[Demo Prepare] For cloud-backed demos, start roles/cloud.py, roles/gateway.py "
        "with --cloud-url, ingest via roles/camera.py, then replace cloud with a "
        "demo/scenarios/aXX_*.py malicious cloud on the same port."
    )


if __name__ == "__main__":
    main()
