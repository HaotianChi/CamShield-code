#!/usr/bin/env python3
"""A8: Cloud attaches wrong ABE capsule."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from demo.scenarios._launch import launch_attack

if __name__ == "__main__":
    launch_attack("A8")
