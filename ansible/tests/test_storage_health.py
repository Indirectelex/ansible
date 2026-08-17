"""Tests for generic ZFS and SMART monitoring normalization.

TEACHER NOTE — CHAPTER 8
Fixtures document evidence confidence, historical counter direction, kernel
corroboration, ZFS health, and the stable Proxmox/QGA/PARTUUID/SMART join.
CHANGE INSTRUCTIONS: every new parser rule or status decision needs healthy,
uncertain, deteriorating, failed-collection, and partial-topology coverage.
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

    def test_uncertain_vendor_attributes_are_watch_not_confirmed_warning(self) -> None:
        payload = {
            "model_name": "Example SSD",
            "serial_number": "SERIAL-LOW",
            "firmware_version": "VENDOR1",
            "smart_status": {"passed": True},
            "ata_smart_attributes": {
                "table": [
                    {"id": 160, "name": "Unknown_Attribute", "raw": {"value": 1}},
                    {"id": 161, "name": "Unknown_Attribute", "raw": {"value": 2}},
                    {"id": 162, "name": "Unknown_Attribute", "raw": {"value": 3}},
                    {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 13}},
                ]
            },
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}],
            observed_at="2026-08-16T01:00:00+00:00",
        )
        device = result["details"]["devices"][0]
        self.assertEqual(result["status"], "watch")
        self.assertEqual(device["assessment"], "watch")
        self.assertEqual(device["interpretation"]["level"], "low")
        self.assertFalse(device["evidence"][0]["confirmed"])

    def test_stable_reallocation_history_is_watch(self) -> None:
        previous = {
            "details": {
                "devices": [
                    {
                        "device": "/dev/sda",
                        "serial": "SERIAL-STABLE",
                        "attributes": {"reallocated_sectors": 12},
                    }
                ]
            }
        }
        payload = {
            "serial_number": "SERIAL-STABLE",
            "smart_status": {"passed": True},
            "ata_smart_attributes": {
                "table": [
                    {"name": "Reallocated_Sector_Ct", "raw": {"value": 12}}
                ]
            },
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}],
            previous_result=previous,
            observed_at="2026-08-16T01:00:00+00:00",
            previous_observed_at="2026-08-15T01:00:00+00:00",
        )
        device = result["details"]["devices"][0]
        self.assertEqual(result["status"], "watch")
        self.assertEqual(device["status"], "watch")
        self.assertEqual(device["evidence"][0]["level"], "watch")
        self.assertFalse(device["evidence"][0]["active"])
        self.assertIn("no active deterioration", result["summary"])

    def test_increasing_reallocation_history_is_warning(self) -> None:
        previous = {
            "details": {
                "devices": [
                    {
                        "device": "/dev/sda",
                        "serial": "SERIAL-GROWING",
                        "attributes": {"reallocated_events": 4},
                    }
                ]
            }
        }
        payload = {
            "serial_number": "SERIAL-GROWING",
            "smart_status": {"passed": True},
            "ata_smart_attributes": {
                "table": [
                    {"name": "Reallocated_Event_Count", "raw": {"value": 6}}
                ]
            },
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}],
            previous_result=previous,
            observed_at="2026-08-16T01:00:00+00:00",
            previous_observed_at="2026-08-15T01:00:00+00:00",
        )
        device = result["details"]["devices"][0]
        self.assertEqual(result["status"], "warning")
        self.assertEqual(device["evidence"][0]["trend"], "increasing")
        self.assertTrue(device["evidence"][0]["active"])

    def test_smart_history_reports_stable_and_increasing_counters(self) -> None:
        previous = {
            "details": {
                "devices": [
                    {
                        "device": "/dev/sda",
                        "serial": "SERIAL1",
                        "attributes": {
                            "pending_sectors": 13,
                            "reallocated_events": 325,
                        },
                        "history": {
                            "first_observed_at": "2026-08-15T01:00:00+00:00",
                            "last_observed_at": "2026-08-15T01:00:00+00:00",
                            "attributes": {
                                "pending_sectors": {
                                    "first_nonzero_at": "2026-08-15T01:00:00+00:00"
                                }
                            },
                        },
                    }
                ]
            }
        }
        payload = {
            "serial_number": "SERIAL1",
            "smart_status": {"passed": True},
            "ata_smart_attributes": {
                "table": [
                    {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 13}},
                    {"id": 196, "name": "Reallocated_Event_Count", "raw": {"value": 330}},
                ]
            },
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}],
            previous_result=previous,
            observed_at="2026-08-16T01:00:00+00:00",
            previous_observed_at="2026-08-15T01:00:00+00:00",
        )
        history = result["details"]["devices"][0]["history"]["attributes"]
        self.assertEqual(history["pending_sectors"]["trend"], "stable")
        self.assertEqual(history["pending_sectors"]["change"], 0)
        self.assertEqual(history["reallocated_events"]["trend"], "increasing")
        self.assertEqual(history["reallocated_events"]["change"], 5)
        self.assertEqual(
            history["reallocated_events"]["first_nonzero_at"],
            "2026-08-15T01:00:00+00:00",
        )

    def test_kernel_io_error_is_confirmed_evidence(self) -> None:
        payload = {
            "serial_number": "SERIAL1",
            "smart_status": {"passed": True},
        }
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sdd"}, "rc": 0, "stdout": json.dumps(payload)}],
            kernel_output="kernel: blk_update_request: I/O error, dev sdd, sector 12",
        )
        device = result["details"]["devices"][0]
        self.assertEqual(device["status"], "warning")
        self.assertEqual(device["kernel_evidence"]["event_count"], 1)
        self.assertTrue(device["evidence"][0]["confirmed"])

    def test_proxmox_passthrough_is_attached_before_live_guest_join(self) -> None:
        payload = {
            "serial_number": "SERIAL1",
            "smart_status": {"passed": True},
        }
        configs = [
            {
                "item": 1000,
                "rc": 0,
                "stdout": (
                    "name: scale\n"
                    "scsi11: /dev/disk/by-id/ata-Example_SERIAL1,backup=0\n"
                ),
            }
        ]
        result = storage_health.smart_module_result(
            [{"item": {"name": "/dev/sda"}, "rc": 0, "stdout": json.dumps(payload)}],
            proxmox_config_results=configs,
        )
        topology = result["details"]["devices"][0]["topology"]
        self.assertEqual(topology["proxmox"]["slot"], "scsi11")
        self.assertNotIn("consumer", topology)
        self.assertNotIn("zfs", topology)

    def test_proxmox_vm_ids_only_returns_qemu_guests(self) -> None:
        output = json.dumps(
            [
                {
                    "vmid": 1000,
                    "type": "qemu",
                    "node": "nimbus",
                    "status": "running",
                },
                {
                    "vmid": 1002,
                    "type": "qemu",
                    "node": "nimbus",
                    "status": "stopped",
                },
                {"vmid": 1001, "type": "qemu", "node": "zebulon"},
                {"vmid": 555, "type": "lxc"},
            ]
        )
        self.assertEqual(
            storage_health.proxmox_vm_ids(output, "nimbus", running_only=True),
            [1000],
        )

    def test_live_qga_topology_joins_slot_partuuid_pool_and_smart(self) -> None:
        configs = [
            {
                "item": 1000,
                "rc": 0,
                "stdout": (
                    "name: scale\n"
                    "scsi3: /dev/disk/by-id/ata-WDC_WD-WCC4N1016847,backup=0\n"
                    "scsi6: /dev/disk/by-id/ata-CT1000_2312E6BDFD96,backup=0\n"
                ),
            }
        ]
        lsblk = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "/dev/sda",
                        "type": "disk",
                        "serial": "drive-scsi0",
                        "children": [
                            {
                                "name": "/dev/sda3",
                                "type": "part",
                                "pkname": "/dev/sda",
                                "partuuid": "boot-uuid",
                            }
                        ],
                    },
                    {
                        "name": "/dev/sdd",
                        "type": "disk",
                        "serial": "drive-scsi3",
                        "children": [
                            {
                                "name": "/dev/sdd2",
                                "type": "part",
                                "pkname": "/dev/sdd",
                                "partuuid": "storage-uuid",
                            }
                        ],
                    },
                    {
                        "name": "/dev/sdg",
                        "type": "disk",
                        "serial": "drive-scsi6",
                        "children": [
                            {
                                "name": "/dev/sdg1",
                                "type": "part",
                                "pkname": "/dev/sdg",
                                "partuuid": "cache-uuid",
                            }
                        ],
                    },
                ]
            }
        )
        zpool = """
  pool: storage
 state: ONLINE
config:
        NAME                                            STATE     READ WRITE CKSUM
        storage                                         ONLINE       0     0     0
          mirror-1                                      ONLINE       0     0     0
            /dev/disk/by-partuuid/storage-uuid          ONLINE       0     0     0
errors: No known data errors

  pool: backups
 state: ONLINE
config:
        NAME                                            STATE     READ WRITE CKSUM
        backups                                         ONLINE       0     0     0
        cache
          /dev/disk/by-partuuid/cache-uuid              ONLINE       0     0     0
errors: No known data errors

  pool: boot-pool
 state: ONLINE
config:
        NAME                                            STATE     READ WRITE CKSUM
        boot-pool                                       ONLINE       0     0     0
          /dev/sda3                                     ONLINE       0     0     0
errors: No known data errors
"""

        def qga(item: int, output: str) -> dict[str, object]:
            return {
                "item": item,
                "rc": 0,
                "stdout": json.dumps({"exitcode": 0, "out-data": output}),
            }

        smart = {
            "details": {
                "devices": [
                    {
                        "device": "/dev/sdp",
                        "serial": "WD-WCC4N1016847",
                        "status": "warning",
                    },
                    {
                        "device": "/dev/sdn",
                        "serial": "2312E6BDFD96",
                        "status": "healthy",
                    },
                ]
            }
        }
        topology = storage_health.proxmox_guest_storage_topology(
            configs,
            [{"item": 1000, "rc": 0}],
            [qga(1000, lsblk)],
            [qga(1000, zpool)],
            smart,
            "nimbus",
            "2026-08-16T20:00:00Z",
        )

        self.assertEqual(storage_health.proxmox_passthrough_vm_ids(configs), [1000])
        guest = topology["guests"][0]
        storage_member = guest["pools"][0]["vdevs"][0]["members"][0]
        self.assertEqual(storage_member["slot"], "scsi3")
        self.assertEqual(storage_member["guest_member"], "/dev/sdd2")
        self.assertEqual(storage_member["host_device"], "/dev/sdp")
        self.assertEqual(storage_member["physical_serial"], "WD-WCC4N1016847")

        cache_member = guest["pools"][1]["vdevs"][0]["members"][0]
        self.assertEqual(cache_member["vdev_class"], "cache")
        self.assertEqual(cache_member["slot"], "scsi6")

        boot_member = guest["pools"][2]["vdevs"][0]["members"][0]
        self.assertEqual(boot_member["trace_status"], "virtual")
        self.assertIsNone(boot_member["physical_serial"])

        enriched = storage_health.attach_storage_topology(smart, topology)
        live = enriched["details"]["devices"][0]["topology"]
        self.assertEqual(live["source"], "proxmox_qemu_guest_agent")
        self.assertEqual(live["consumer"]["device"], "/dev/sdd")
        self.assertEqual(live["zfs"]["pool"], "storage")
        self.assertEqual(live["zfs"]["vdev"], "mirror-1")

    def test_non_zfs_guest_does_not_report_unassigned_pool_disks(self) -> None:
        configs = [
            {
                "item": 999,
                "rc": 0,
                "stdout": "name: pbs\nscsi1: /dev/disk/by-id/ata-Example_SERIAL1\n",
            }
        ]
        lsblk = json.dumps(
            {
                "blockdevices": [
                    {"name": "/dev/sdb", "type": "disk", "serial": "drive-scsi1"}
                ]
            }
        )
        topology = storage_health.proxmox_guest_storage_topology(
            configs,
            [{"item": 999, "rc": 0}],
            [
                {
                    "item": 999,
                    "rc": 0,
                    "stdout": json.dumps({"exitcode": 0, "out-data": lsblk}),
                }
            ],
            [
                {
                    "item": 999,
                    "rc": 0,
                    "stdout": json.dumps(
                        {"exitcode": 127, "err-data": "zpool: not found"}
                    ),
                }
            ],
            {"details": {"devices": []}},
            "nimbus",
        )
        guest = topology["guests"][0]
        self.assertEqual(guest["collection_status"], "consumer_only")
        self.assertEqual(guest["unassigned_passthroughs"], [])
        self.assertFalse(
            any(
                finding["kind"] == "passthrough_not_in_zfs"
                for finding in topology["findings"]
            )
        )

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
        self.assertIn("proxmox_vm_ids", filters)
        self.assertIn("proxmox_passthrough_vm_ids", filters)
        self.assertIn("proxmox_guest_storage_topology", filters)
        self.assertIn("attach_storage_topology", filters)
        self.assertIn("smart_module_result", filters)
        self.assertIn("zfs_module_result", filters)


if __name__ == "__main__":
    unittest.main()
