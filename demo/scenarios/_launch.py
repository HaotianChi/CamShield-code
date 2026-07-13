#!/usr/bin/env python3
"""Launch helper for a malicious-cloud attack scenario."""

from __future__ import annotations

import sys
from pathlib import Path


def launch_attack(attack_id: str, argv: list[str] | None = None) -> None:
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from demo.malicious_cloud import main

    args = argv if argv is not None else sys.argv[1:]
    sys.argv = [f"demo/scenarios/{attack_id.lower()}.py", "--attack", attack_id, *args]
    main()
