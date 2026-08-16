"""Tests for generic ZFS and SMART monitoring normalization."""

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
    / "storage_health.py"
)
SPEC = importlib.util.spec_from_file_location("storage_health", PLUGIN_PATH)
assert SPEC is not None and SPEC.loader is not None
storage_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage_health)


class StorageHealthTests(unittest.TestCase):
    """Verify portable storage parsing and severity decisions."""

    def test_smart_scan_devices_keeps_required_arguments(self) -> None:
        output = json.dumps(
            {
                "devices": [
                    {
                        "name": "/dev/sda",
                        "type": "sat",
                        "protocol": "ATA",
                    },
                    {"type": "sat"},
                ],
            }
        )
        self.assertEqual(
            storage_health.smart_scan_devices(output),
            [{"name": "/dev/sda", "type": "sat", "protocol": "ATA"}],
        )

    def test_smart_pending_sector_is_warning_even_when_overall_passes(self) -> None:
        payload = {
            "model_name": "Example SSD",
            "serial_number": "SERIAL1",
            "smart_status": {"passed": True},
            "temperature": {"current": 40},
            "power_on_time": {"hours": 4706},
            "ata_smart_attributes": {
                "table": [
                    {"name": "Current_Pending_Sector", "raw": {"value": 29}},
                    {"name": "Reallocated_Event_Count", "raw": {"value": 368}},
                ]
            },
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}]
        )
        self.assertEqual(result["status"], "warning")
        device = result["details"]["devices"][0]
        self.assertEqual(device["attributes"]["pending_sectors"], 29)
        self.assertEqual(device["attributes"]["reallocated_events"], 368)

    def test_smart_failed_overall_health_is_critical(self) -> None:
        payload = {"smart_status": {"passed": False}}
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sdb"}, "rc": 8, "stdout": json.dumps(payload)}]
        )
        self.assertEqual(result["status"], "critical")

    def test_smart_invalid_json_is_unknown(self) -> None:
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sdc"}, "rc": 2, "stdout": "not json"}]
        )
        self.assertEqual(result["status"], "unknown")

    def test_zfs_online_pool_is_healthy(self) -> None:
        status_output = """
  pool: tank
 state: ONLINE
  scan: scrub repaired 0B in 00:01:00 with 0 errors
config:
        NAME        STATE     READ WRITE CKSUM
        tank        ONLINE       0     0     0
          mirror-0  ONLINE       0     0     0
            sda     ONLINE       0     0     0
            sdb     ONLINE       0     0     0
"""
        result = storage_health.zfs_module_result(
            status_output,
            "tank\t1000\t400\t600\t40\tONLINE\n",
        )
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["details"]["pools"][0]["capacity_percent"], 40)
        self.assertEqual(result["details"]["devices_requiring_attention"], [])

    def test_zfs_degraded_pool_is_critical(self) -> None:
        status_output = """
  pool: tank
 state: DEGRADED
config:
        NAME        STATE     READ WRITE CKSUM
        tank        DEGRADED     0     0     0
          sda       FAULTED      0     2     0
"""
        result = storage_health.zfs_module_result(
            status_output,
            "tank\t1000\t400\t600\t40\tDEGRADED\n",
        )
        self.assertEqual(result["status"], "critical")
        self.assertEqual(
            result["details"]["devices_requiring_attention"][1]["name"],
            "sda",
        )

    def test_filters_are_registered(self) -> None:
        filters = storage_health.FilterModule().filters()
        self.assertIn("smart_scan_devices", filters)
        self.assertIn("smart_module_result", filters)
        self.assertIn("zfs_module_result", filters)


if __name__ == "__main__":
    unittest.main()
