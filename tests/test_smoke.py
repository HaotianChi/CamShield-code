"""Smoke tests for CI."""

from __future__ import annotations

import unittest
from datetime import datetime

from core.epoch import EpochManager, epoch_window_start
from run import run_simulation


class SmokeTests(unittest.TestCase):
    def test_epoch_hour_boundary(self) -> None:
        ts = int(datetime(2026, 7, 1, 13, 45, 30).timestamp())
        em = EpochManager(epoch_duration_s=3600, epoch_started_at=ts)
        self.assertEqual(em.epoch_started_at, epoch_window_start(ts))

        ts2 = int(datetime(2026, 7, 1, 14, 5, 0).timestamp())
        rotations = em.maybe_rotate_epoch(ts2)
        self.assertEqual(len(rotations), 1)
        self.assertEqual(em.current_epoch(), 2)
        self.assertEqual(datetime.fromtimestamp(em.epoch_started_at).hour, 14)

    def test_simulation_no_charm(self) -> None:
        run_simulation(segments=1, use_charm=False)


if __name__ == "__main__":
    unittest.main()
