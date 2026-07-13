#!/usr/bin/env python3
"""Print attack scenarios for detection-coverage demos."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.attacks import list_attacks


def main() -> None:
    for attack in list_attacks():
        print(f"{attack.attack_id}\t{attack.title}")
        print(f"  Injected: {attack.injected_inconsistency}")
        print(f"  Client web: {attack.expected_client_signal}")
        print()


if __name__ == "__main__":
    main()
