"""Tests for Proxmox Backup Server monitoring normalization.

TEACHER NOTE — CHAPTER 5.5
These tests define safe datastore-path parsing, capacity normalization, module
aggregation, and collection-failure behaviour.
CHANGE INSTRUCTIONS: keep fixtures representative of PBS JSON and POSIX df;
test values at each threshold and malformed/failed collection separately.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


PLUGIN_PATH = (
    Path(__file__).resolve().parents[1]
    / "roles"
    / "health_check"
    / "filter_plugins"
    / "pbs_health.py"
)
SPEC = importlib.util.spec_from_file_location("pbs_health", PLUGIN_PATH)
assert SPEC is not None and SPEC.loader is not None
pbs_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pbs_health)


class PbsHealthTests(unittest.TestCase):
    """Verify datastore discovery and capacity severity."""

    def test_datastore_paths_only_accept_absolute_paths(self) -> None:
        output = json.dumps(
            [
                {"name": "backup", "path": "/mnt/datastore/backup"},
                {"name": "invalid", "path": "relative/path"},
            ]
        )
        self.assertEqual(
            pbs_health.pbs_datastore_paths(output),
            [{"name": "backup", "path": "/mnt/datastore/backup"}],
        )

    def test_datastore_capacity_is_normalized(self) -> None:
        configured = json.dumps(
            [{"name": "backup", "path": "/mnt/datastore/backup"}]
        )
        result = pbs_health.pbs_module_result(
            json.dumps([{"package": "proxmox-backup-server", "version": "4.0"}]),
            0,
            configured,
            0,
            [
                {
                    "item": {"name": "backup", "path": "/mnt/datastore/backup"},
                    "rc": 0,
                    "stdout": (
                        "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                        "/dev/sdb1 1000000 850000 150000 85% /mnt/datastore/backup\n"
                    ),
                }
            ],
        )
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["details"]["datastores"][0]["capacity_percent"], 85)
        self.assertEqual(result["details"]["datastores"][0]["available_kib"], 150000)

    def test_failed_datastore_listing_is_unknown(self) -> None:
        result = pbs_health.pbs_module_result("", 1, "", 1, [])
        self.assertEqual(result["status"], "unknown")
        self.assertIn("unavailable", result["summary"])

    def test_filters_are_registered(self) -> None:
        filters = pbs_health.FilterModule().filters()
        self.assertIn("pbs_datastore_paths", filters)
        self.assertIn("pbs_module_result", filters)


if __name__ == "__main__":
    unittest.main()
