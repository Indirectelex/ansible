"""Normalize and correlate read-only ZFS, SMART, kernel, and guest evidence.

TEACHER NOTE — CHAPTER 8
Purpose: turn several incompatible storage namespaces into credible device,
pool, and consumer health without relying on unstable ``/dev/sdX`` names.
Inputs include smartctl JSON, kernel logs, Proxmox VM configs, QEMU Guest Agent
``lsblk`` JSON, guest ``zpool status``, and the previous trusted host report.
Outputs are standard module results plus a live physical-to-guest topology.

CHANGE INSTRUCTIONS
Status decisions require evidence. Preserve stable identity joins, keep unknown
or vendor-specific data conservative, and add fixtures for every parser or
threshold change. Validate SMART, ZFS, non-ZFS guests, missing QGA, and partial
join cases before changing the schema.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any


# CHAPTER 8.1 — Defensive primitives and common severity aggregation
STATUS_ORDER = {
    "healthy": 0,
    "watch": 1,
    "unknown": 2,
    "warning": 3,
    "critical": 4,
}


def safe_json_object(value: Any) -> dict[str, Any]:
    """Return a JSON object or an empty object without failing a health run."""

    try:
        payload = json.loads(str(value or "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _integer(value: Any) -> int | None:
    """Return the first integer represented by a SMART value."""

    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "").strip()
    if re.fullmatch(r"[+-]?0x[0-9a-f]+", text, re.IGNORECASE):
        return int(text, 16)
    match = re.search(r"-?\d+", text)
    return int(match.group(0)) if match else None


def _worst_status(statuses: list[str]) -> str:
    """Return the most severe normalized status."""

    return max(statuses, key=lambda item: STATUS_ORDER.get(item, 1))


# CHAPTER 8.2 — SMART discovery, ATA attributes, and evidence confidence
def smart_scan_devices(output: str) -> list[dict[str, str]]:
    """Parse smartctl --scan-open JSON into safe command arguments."""

    try:
        payload = json.loads(output or "{}")
    except (TypeError, json.JSONDecodeError):
        return []

    devices: list[dict[str, str]] = []
    for item in payload.get("devices", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        device = {"name": str(item["name"])}
        for key in ("type", "protocol", "info_name"):
            if item.get(key):
                device[key] = str(item[key])
        devices.append(device)
    return devices


def _ata_attributes(payload: dict[str, Any]) -> dict[str, int]:
    """Extract portable ATA attributes by normalized name."""

    wanted = {
        "reallocated_sector_ct": "reallocated_sectors",
        "reallocated_event_count": "reallocated_events",
        "current_pending_sector": "pending_sectors",
        "offline_uncorrectable": "offline_uncorrectable",
        "reported_uncorrect": "reported_uncorrectable",
        "udma_crc_error_count": "interface_crc_errors",
        "interface_crc_error_count": "interface_crc_errors",
    }
    attributes: dict[str, int] = {}
    table = payload.get("ata_smart_attributes", {}).get("table", [])
    for item in table:
        if not isinstance(item, dict):
            continue
        source_name = str(item.get("name", "")).lower()
        target_name = wanted.get(source_name)
        if not target_name:
            continue
        raw = item.get("raw", {})
        value = _integer(raw.get("value") if isinstance(raw, dict) else raw)
        if value is not None:
            attributes[target_name] = max(
                value,
                attributes.get(target_name, value),
            )
    return attributes


def _ata_attribute_table(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve the useful parts of the vendor attribute table for review."""

    attributes: list[dict[str, Any]] = []
    table = payload.get("ata_smart_attributes", {}).get("table", [])
    for item in table:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw", {})
        attributes.append(
            {
                "id": item.get("id"),
                "name": str(item.get("name", "Unknown")),
                "normalized": item.get("value"),
                "worst": item.get("worst"),
                "threshold": item.get("thresh"),
                "raw": _integer(raw.get("value") if isinstance(raw, dict) else raw),
            }
        )
    return attributes


def _interpretation_confidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Estimate whether ATA attribute names are safe to interpret literally."""

    if payload.get("nvme_smart_health_information_log"):
        return {"level": "high", "reasons": ["NVMe health log is standardized"]}

    table = payload.get("ata_smart_attributes", {}).get("table", [])
    if not isinstance(table, list) or not table:
        return {
            "level": "medium",
            "reasons": ["No ATA vendor attribute table was available"],
        }

    reasons: list[str] = []
    unknown = sum(
        str(item.get("name", "")).lower().startswith("unknown_")
        for item in table
        if isinstance(item, dict)
    )
    if unknown >= 3 or unknown / max(len(table), 1) >= 0.25:
        reasons.append(
            f"{unknown} of {len(table)} ATA attributes are vendor-specific or unknown"
        )

    wwn = payload.get("wwn")
    if isinstance(wwn, dict):
        numeric_parts = [
            _integer(wwn.get(key))
            for key in ("naa", "oui", "id")
            if wwn.get(key) is not None
        ]
        if numeric_parts and all(value == 0 for value in numeric_parts):
            reasons.append("The device reports an all-zero WWN")

    if reasons:
        return {"level": "low", "reasons": reasons}
    return {
        "level": "medium",
        "reasons": ["ATA SMART attributes are vendor-defined"],
    }


def _kernel_storage_evidence(output: str, device_name: str) -> dict[str, Any]:
    """Extract recent kernel messages that explicitly name one block device."""

    kernel_name = str(device_name or "").rsplit("/", 1)[-1]
    if not kernel_name:
        return {"event_count": 0, "severity": "none", "samples": []}

    token = re.compile(rf"(?:\[{re.escape(kernel_name)}\]|\b{re.escape(kernel_name)}\b)")
    critical = re.compile(
        r"(?i)(?:I/O error|unrecovered read|medium error|failed command|critical medium)"
    )
    warning = re.compile(
        r"(?i)(?:timed? out|timeout|reset|abort|offline|link.*down|rejecting I/O)"
    )
    samples: list[str] = []
    severities: list[str] = []
    for line in (output or "").splitlines():
        if not token.search(line):
            continue
        if critical.search(line):
            severities.append("critical")
        elif warning.search(line):
            severities.append("warning")
        else:
            continue
        if len(samples) < 5:
            samples.append(line.strip()[-500:])

    severity = "none"
    if "critical" in severities:
        severity = "critical"
    elif "warning" in severities:
        severity = "warning"
    return {
        "event_count": len(severities),
        "severity": severity,
        "samples": samples,
    }


# CHAPTER 8.3 — Proxmox guest selection and physical passthrough parsing
def proxmox_vm_ids(
    output: str,
    node: str | None = None,
    running_only: bool = False,
) -> list[int]:
    """Extract local QEMU VM identifiers from pvesh JSON."""

    try:
        payload = json.loads(output or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return sorted(
        {
            int(item["vmid"])
            for item in payload
            if isinstance(item, dict)
            and item.get("type") == "qemu"
            and item.get("vmid") is not None
            and (
                not node
                or not item.get("node")
                or str(item.get("node")) == str(node)
            )
            and (not running_only or str(item.get("status")) == "running")
        }
    )


def _proxmox_passthroughs(
    config_results: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Normalize serial-backed disks passed through to QEMU guests."""

    passthroughs: list[dict[str, Any]] = []
    for result in config_results or []:
        if not isinstance(result, dict) or int(result.get("rc", 1) or 0) != 0:
            continue
        vmid = result.get("item")
        name = None
        lines = str(result.get("stdout", "")).splitlines()
        for line in lines:
            if line.startswith("name:"):
                name = line.split(":", 1)[1].strip()
                break
        for line in lines:
            match = re.match(
                r"^(scsi\d+|sata\d+|virtio\d+):\s*"
                r"(/dev/disk/by-id/[^,\s]+)",
                line,
            )
            if not match:
                continue
            passthroughs.append(
                {
                    "vm_id": int(vmid) if str(vmid).isdigit() else vmid,
                    "vm_name": name,
                    "slot": match.group(1),
                    "source_path": match.group(2),
                }
            )
    return passthroughs


def proxmox_passthrough_vm_ids(
    config_results: list[dict[str, Any]] | None,
) -> list[int]:
    """Return only QEMU guests that receive stable by-id host disks."""

    return sorted(
        {
            int(item["vm_id"])
            for item in _proxmox_passthroughs(config_results)
            if str(item.get("vm_id", "")).isdigit()
        }
    )


def _result_item_id(result: dict[str, Any]) -> int | str | None:
    """Return the loop item used for one registered Ansible command."""

    item = result.get("item")
    if isinstance(item, dict):
        item = item.get("vm_id", item.get("vmid"))
    return int(item) if str(item or "").isdigit() else item


def _results_by_item(
    results: list[dict[str, Any]] | None,
) -> dict[int | str, dict[str, Any]]:
    """Index registered Ansible command results by their loop item."""

    indexed: dict[int | str, dict[str, Any]] = {}
    for result in results or []:
        if not isinstance(result, dict):
            continue
        item = _result_item_id(result)
        if item is not None:
            indexed[item] = result
    return indexed


def _qga_output(result: dict[str, Any] | None) -> tuple[bool, str, str]:
    """Unwrap qm guest exec JSON without allowing a failed guest command through."""

    if not isinstance(result, dict) or int(result.get("rc", 1) or 0) != 0:
        error = str((result or {}).get("stderr", "")).strip()
        return False, "", error or "Proxmox guest command failed"
    try:
        wrapper = json.loads(str(result.get("stdout", "") or "{}"))
    except (TypeError, json.JSONDecodeError):
        return False, "", "Proxmox guest command returned invalid JSON"
    if not isinstance(wrapper, dict) or int(wrapper.get("exitcode", 1) or 0) != 0:
        error = str(wrapper.get("err-data", "")).strip() if isinstance(wrapper, dict) else ""
        return False, "", error or "Guest command returned a non-zero exit code"
    return True, str(wrapper.get("out-data", "")), ""


# CHAPTER 8.4 — Guest block identity and ZFS topology parsing
def _guest_block_inventory(output: str) -> dict[str, Any]:
    """Index lsblk JSON by path, PARTUUID, and the QEMU drive slot serial."""

    try:
        payload = json.loads(output or "{}")
    except (TypeError, json.JSONDecodeError):
        return {"devices": [], "by_name": {}, "by_partuuid": {}, "by_slot": {}}

    devices: list[dict[str, Any]] = []

    def visit(node: Any, parent: str | None = None) -> None:
        if not isinstance(node, dict) or not node.get("name"):
            return
        current = {
            key: node.get(key)
            for key in ("name", "type", "pkname", "size", "model", "serial", "wwn", "partuuid")
        }
        if not current.get("pkname") and parent:
            current["pkname"] = parent
        devices.append(current)
        for child in node.get("children", []) or []:
            visit(child, str(node["name"]))

    for device in payload.get("blockdevices", []) if isinstance(payload, dict) else []:
        visit(device)

    by_name = {str(item["name"]): item for item in devices}
    by_partuuid = {
        str(item["partuuid"]).lower(): item
        for item in devices
        if item.get("partuuid")
    }
    by_slot: dict[str, dict[str, Any]] = {}
    for item in devices:
        match = re.fullmatch(
            r"drive-(scsi\d+|sata\d+|virtio\d+)",
            str(item.get("serial", "")),
            re.IGNORECASE,
        )
        if match:
            by_slot[match.group(1).lower()] = item
    return {
        "devices": devices,
        "by_name": by_name,
        "by_partuuid": by_partuuid,
        "by_slot": by_slot,
    }


def _zfs_topology(output: str) -> list[dict[str, Any]]:
    """Preserve healthy ZFS pool, vdev-class, vdev, and leaf relationships."""

    pools: list[dict[str, Any]] = []
    current_pool: dict[str, Any] | None = None
    in_config = False
    pool_indent: int | None = None
    current_class = "data"
    current_vdev: dict[str, Any] | None = None
    current_vdev_indent: int | None = None
    states = {"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "AVAIL"}
    class_names = {
        "logs": "log",
        "log": "log",
        "cache": "cache",
        "special": "special",
        "dedup": "dedup",
        "spares": "spare",
        "spare": "spare",
    }
    vdev_pattern = re.compile(r"^(?:mirror|raidz\d*|draid\d*|replacing|spare)-\d+$")

    def vdev_for(pool: dict[str, Any], name: str, vdev_class: str, state: str) -> dict[str, Any]:
        for candidate in pool["vdevs"]:
            if candidate["name"] == name and candidate["class"] == vdev_class:
                return candidate
        candidate = {
            "name": name,
            "class": vdev_class,
            "state": state,
            "members": [],
        }
        pool["vdevs"].append(candidate)
        return candidate

    for raw_line in (output or "").splitlines():
        pool_match = re.match(r"\s*pool:\s*(\S+)", raw_line)
        if pool_match:
            current_pool = {
                "name": pool_match.group(1),
                "state": "UNKNOWN",
                "vdevs": [],
            }
            pools.append(current_pool)
            in_config = False
            pool_indent = None
            current_class = "data"
            current_vdev = None
            current_vdev_indent = None
            continue
        if current_pool is None:
            continue
        state_match = re.match(r"\s*state:\s*(\S+)", raw_line)
        if state_match:
            current_pool["state"] = state_match.group(1)
            continue
        if raw_line.strip() == "config:":
            in_config = True
            continue
        if raw_line.lstrip().startswith("errors:"):
            in_config = False
            continue
        if not in_config or not raw_line.strip():
            continue

        expanded = raw_line.expandtabs(8).rstrip()
        stripped = expanded.strip()
        if stripped.startswith("NAME ") or stripped == "NAME":
            continue
        class_name = class_names.get(stripped.lower())
        if class_name:
            current_class = class_name
            current_vdev = None
            current_vdev_indent = None
            continue

        fields = stripped.split()
        if len(fields) < 2 or fields[1] not in states:
            continue
        name, state = fields[0], fields[1]
        indent = len(expanded) - len(expanded.lstrip())
        read_errors = _integer(fields[2]) if len(fields) > 2 else None
        write_errors = _integer(fields[3]) if len(fields) > 3 else None
        checksum_errors = _integer(fields[4]) if len(fields) > 4 else None

        if name == current_pool["name"]:
            current_pool["state"] = state
            pool_indent = indent
            current_class = "data"
            current_vdev = None
            current_vdev_indent = None
            continue
        if pool_indent is None:
            pool_indent = max(indent - 2, 0)

        if vdev_pattern.match(name):
            current_vdev = vdev_for(current_pool, name, current_class, state)
            current_vdev_indent = indent
            continue
        if current_vdev_indent is not None and indent <= current_vdev_indent:
            current_vdev = None
            current_vdev_indent = None

        vdev = current_vdev or vdev_for(
            current_pool,
            current_class,
            current_class,
            state,
        )
        partuuid_match = re.search(r"/by-partuuid/([^/\s]+)$", name, re.IGNORECASE)
        vdev["members"].append(
            {
                "member": name,
                "state": state,
                "read_errors": read_errors,
                "write_errors": write_errors,
                "checksum_errors": checksum_errors,
                "partuuid": partuuid_match.group(1).lower() if partuuid_match else None,
            }
        )
    return pools


def _physical_device_for_path(
    source_path: str,
    smart_devices: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Match a stable Proxmox by-id path to one SMART device serial."""

    matches = [
        device
        for device in smart_devices
        if device.get("serial") and str(device["serial"]) in str(source_path or "")
    ]
    return max(matches, key=lambda item: len(str(item.get("serial", "")))) if matches else None


# CHAPTER 8.5 — Stable multi-source physical-to-guest join
# Join order: host slot/by-id -> drive-scsi identity -> guest partition/PARTUUID
# -> ZFS member. Incomplete evidence remains visible instead of being invented.
def proxmox_guest_storage_topology(
    config_results: list[dict[str, Any]] | None,
    agent_results: list[dict[str, Any]] | None = None,
    lsblk_results: list[dict[str, Any]] | None = None,
    zpool_results: list[dict[str, Any]] | None = None,
    smart_result: dict[str, Any] | None = None,
    proxmox_host: str | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Join Proxmox passthroughs, QGA block identities, ZFS, and SMART."""

    passthroughs = _proxmox_passthroughs(config_results)
    configs_by_vm: dict[int | str, dict[str, Any]] = {}
    for item in passthroughs:
        vm_id = item["vm_id"]
        guest = configs_by_vm.setdefault(
            vm_id,
            {
                "vm_id": vm_id,
                "vm_name": item.get("vm_name") or f"VM {vm_id}",
                "passthroughs": [],
            },
        )
        guest["passthroughs"].append(item)

    agent_by_vm = _results_by_item(agent_results)
    lsblk_by_vm = _results_by_item(lsblk_results)
    zpool_by_vm = _results_by_item(zpool_results)
    smart_devices = (
        (smart_result or {}).get("details", {}).get("devices", [])
        if isinstance(smart_result, dict)
        else []
    )
    guests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    def vm_sort_key(value: int | str) -> tuple[int, Any]:
        return (0, int(value)) if str(value).isdigit() else (1, str(value))

    for vm_id in sorted(configs_by_vm, key=vm_sort_key):
        config = configs_by_vm[vm_id]
        agent_result = agent_by_vm.get(vm_id, {})
        agent_available = int(agent_result.get("rc", 1) or 0) == 0
        lsblk_ok, lsblk_output, lsblk_error = _qga_output(lsblk_by_vm.get(vm_id))
        zpool_ok, zpool_output, zpool_error = _qga_output(zpool_by_vm.get(vm_id))
        block = _guest_block_inventory(lsblk_output) if lsblk_ok else _guest_block_inventory("")
        pools = _zfs_topology(zpool_output) if zpool_ok else []
        passthrough_by_slot = {
            str(item["slot"]).lower(): item for item in config["passthroughs"]
        }
        disks: list[dict[str, Any]] = []
        disk_by_slot: dict[str, dict[str, Any]] = {}

        for slot, passthrough in sorted(passthrough_by_slot.items()):
            guest_disk = block["by_slot"].get(slot, {})
            physical = _physical_device_for_path(
                str(passthrough.get("source_path", "")), smart_devices
            )
            disk = {
                "slot": slot,
                "source_path": passthrough.get("source_path"),
                "host_device": physical.get("device") if physical else None,
                "physical_serial": physical.get("serial") if physical else None,
                "smart_status": physical.get("status") if physical else "unknown",
                "guest_disk": guest_disk.get("name"),
                "guest_serial": guest_disk.get("serial"),
                "pool_memberships": [],
            }
            disks.append(disk)
            disk_by_slot[slot] = disk

        for pool in pools:
            for vdev in pool.get("vdevs", []):
                for member in vdev.get("members", []):
                    block_member = None
                    if member.get("partuuid"):
                        block_member = block["by_partuuid"].get(member["partuuid"])
                    if block_member is None:
                        block_member = block["by_name"].get(str(member.get("member", "")))
                    parent_name = None
                    if block_member:
                        parent_name = (
                            block_member.get("pkname")
                            if block_member.get("type") != "disk"
                            else block_member.get("name")
                        )
                    parent = block["by_name"].get(str(parent_name or ""), {})
                    slot_match = re.fullmatch(
                        r"drive-(scsi\d+|sata\d+|virtio\d+)",
                        str(parent.get("serial", "")),
                        re.IGNORECASE,
                    )
                    slot = slot_match.group(1).lower() if slot_match else None
                    disk = disk_by_slot.get(str(slot or ""))
                    membership = {
                        "pool": pool["name"],
                        "pool_state": pool["state"],
                        "vdev": vdev["name"],
                        "vdev_class": vdev["class"],
                        "member": member["member"],
                        "member_state": member["state"],
                        "partuuid": member.get("partuuid"),
                        "guest_disk": parent.get("name"),
                        "guest_member": block_member.get("name") if block_member else None,
                        "slot": slot,
                        "source_path": disk.get("source_path") if disk else None,
                        "host_device": disk.get("host_device") if disk else None,
                        "physical_serial": disk.get("physical_serial") if disk else None,
                        "smart_status": disk.get("smart_status") if disk else "unknown",
                        "trace_status": (
                            "physical"
                            if disk
                            else "virtual"
                            if slot
                            else "unresolved"
                        ),
                    }
                    member.update(membership)
                    if disk:
                        disk["pool_memberships"].append(membership)
                    elif not slot:
                        findings.append(
                            {
                                "kind": "unresolved_zfs_member",
                                "status": "unknown",
                                "vm_id": vm_id,
                                "vm_name": config["vm_name"],
                                "pool": pool["name"],
                                "member": member["member"],
                            }
                        )

        unassigned = [disk for disk in disks if not disk["pool_memberships"]]
        if zpool_ok:
            for disk in unassigned:
                findings.append(
                    {
                        "kind": "passthrough_not_in_zfs",
                        "status": "watch",
                        "vm_id": vm_id,
                        "vm_name": config["vm_name"],
                        "slot": disk["slot"],
                        "physical_serial": disk.get("physical_serial"),
                    }
                )
        if not agent_available:
            findings.append(
                {
                    "kind": "qemu_agent_unavailable",
                    "status": "unknown",
                    "vm_id": vm_id,
                    "vm_name": config["vm_name"],
                }
            )

        guests.append(
            {
                "vm_id": vm_id,
                "vm_name": config["vm_name"],
                "agent_available": agent_available,
                "block_inventory_available": lsblk_ok,
                "zfs_available": zpool_ok and bool(pools),
                "collection_status": (
                    "mapped"
                    if zpool_ok and pools
                    else "consumer_only"
                    if lsblk_ok
                    else "unavailable"
                ),
                "collection_errors": [
                    message
                    for message in (lsblk_error, zpool_error)
                    if message
                ],
                "disks": disks,
                "pools": pools,
                "unassigned_passthroughs": unassigned if zpool_ok else [],
            }
        )

    return {
        "schema_version": 1,
        "source": "proxmox_qemu_guest_agent",
        "observed_at": observed_at,
        "proxmox_host": proxmox_host,
        "status": (
            "available"
            if any(guest["collection_status"] == "mapped" for guest in guests)
            else "partial"
            if guests
            else "not_applicable"
        ),
        "guests": guests,
        "findings": findings,
    }


# CHAPTER 8.6 — Attach consumer/pool context to physical SMART devices
def attach_storage_topology(
    smart_result: dict[str, Any],
    topology: dict[str, Any] | None,
) -> dict[str, Any]:
    """Attach one live consumer and ZFS path to each matching SMART device."""

    result = copy.deepcopy(smart_result or {})
    topology = topology or {}
    by_serial: dict[str, dict[str, Any]] = {}
    for guest in topology.get("guests", []) or []:
        for disk in guest.get("disks", []) or []:
            serial = str(disk.get("physical_serial") or "")
            if not serial:
                continue
            memberships = disk.get("pool_memberships", []) or []
            live = {
                "source": topology.get("source"),
                "observed_at": topology.get("observed_at"),
                "state": "confirmed" if disk.get("guest_disk") else "partial",
                "proxmox": {
                    "host": topology.get("proxmox_host"),
                    "vm_id": guest.get("vm_id"),
                    "vm_name": guest.get("vm_name"),
                    "slot": disk.get("slot"),
                    "source_path": disk.get("source_path"),
                },
                "consumer": {
                    "host": guest.get("vm_name"),
                    "device": disk.get("guest_disk"),
                },
                "memberships": memberships,
            }
            if memberships:
                membership = memberships[0]
                live["consumer"]["member"] = membership.get("guest_member")
                live["zfs"] = {
                    "pool": membership.get("pool"),
                    "pool_state": membership.get("pool_state"),
                    "vdev": membership.get("vdev"),
                    "vdev_class": membership.get("vdev_class"),
                    "member": membership.get("guest_member") or membership.get("member"),
                    "member_state": membership.get("member_state"),
                }
            by_serial[serial] = live

    for device in result.get("details", {}).get("devices", []) or []:
        live = by_serial.get(str(device.get("serial") or ""))
        if live:
            device["topology"] = live
    return result


def _device_topology(
    serial: str | None,
    config_results: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Attach the Proxmox passthrough before live guest correlation runs."""

    topology: dict[str, Any] = {}
    serial_text = str(serial or "")
    for item in _proxmox_passthroughs(config_results):
        if serial_text and serial_text in item["source_path"]:
            topology["proxmox"] = item
            break
    return topology


# CHAPTER 8.7 — Historical SMART trends and device-level interpretation
# Stable counters may be WATCH; increasing or corroborated counters can warn.
def _counter_history(
    current: dict[str, int],
    previous: dict[str, int],
    previous_history: dict[str, Any],
    observed_at: str | None,
    previous_observed_at: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Calculate counter deltas while preserving first nonzero observation."""

    history: dict[str, dict[str, Any]] = {}
    for name in sorted(set(current) | set(previous)):
        current_value = current.get(name)
        previous_value = previous.get(name)
        change = (
            current_value - previous_value
            if current_value is not None and previous_value is not None
            else None
        )
        trend = "baseline"
        if change == 0:
            trend = "stable"
        elif change is not None and change > 0:
            trend = "increasing"
        elif change is not None and change < 0:
            trend = "decreasing"
        prior_metric = previous_history.get(name, {})
        first_nonzero = prior_metric.get("first_nonzero_at")
        if current_value and current_value > 0 and not first_nonzero:
            first_nonzero = (
                previous_observed_at
                if previous_value is not None and previous_value > 0
                else observed_at
            )
        history[name] = {
            "previous": previous_value,
            "current": current_value,
            "change": change,
            "trend": trend,
            "first_nonzero_at": first_nonzero,
        }
    return history


def _self_test(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return the latest ATA self-test entry when available."""

    table = (
        payload.get("ata_smart_self_test_log", {})
        .get("standard", {})
        .get("table", [])
    )
    if not table or not isinstance(table[0], dict):
        return None
    latest = table[0]
    status = latest.get("status", {})
    result: dict[str, Any] = {}
    if isinstance(status, dict) and status.get("string"):
        result["status"] = status["string"]
    if latest.get("lifetime_hours") is not None:
        result["lifetime_hours"] = latest["lifetime_hours"]
    return result or None


def _smart_device_result(
    item: dict[str, Any],
    kernel_output: str = "",
    previous_device: dict[str, Any] | None = None,
    observed_at: str | None = None,
    previous_observed_at: str | None = None,
    proxmox_config_results: list[dict[str, Any]] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Normalize one registered smartctl command result."""

    command_rc = int(item.get("rc", 1) or 0)
    device_spec = item.get("item", {})
    device_name = (
        device_spec.get("name")
        if isinstance(device_spec, dict)
        else str(device_spec)
    )
    try:
        payload = json.loads(item.get("stdout", "") or "{}")
    except (TypeError, json.JSONDecodeError):
        return "unknown", {
            "device": device_name or "unknown",
            "collection_rc": command_rc,
            "collection_error": "smartctl did not return valid JSON",
        }

    detail: dict[str, Any] = {
        "device": device_name or payload.get("device", {}).get("name", "unknown"),
        "collection_rc": command_rc,
    }
    field_map = {
        "model_name": "model",
        "product": "model",
        "serial_number": "serial",
        "firmware_version": "firmware",
        "rotation_rate": "rotation_rate",
    }
    for source, target in field_map.items():
        if payload.get(source) is not None and target not in detail:
            detail[target] = payload[source]

    capacity = payload.get("user_capacity", {})
    if isinstance(capacity, dict) and capacity.get("bytes") is not None:
        detail["capacity_bytes"] = capacity["bytes"]

    smart_status = payload.get("smart_status", {})
    if isinstance(smart_status, dict) and smart_status.get("passed") is not None:
        detail["smart_passed"] = bool(smart_status["passed"])

    temperature = payload.get("temperature", {})
    if isinstance(temperature, dict) and temperature.get("current") is not None:
        detail["temperature_c"] = temperature["current"]

    power_on = payload.get("power_on_time", {})
    if isinstance(power_on, dict) and power_on.get("hours") is not None:
        detail["power_on_hours"] = power_on["hours"]

    attributes = _ata_attributes(payload)
    if attributes:
        detail["attributes"] = attributes
    raw_attributes = _ata_attribute_table(payload)
    if raw_attributes:
        detail["raw_attributes"] = raw_attributes

    confidence = _interpretation_confidence(payload)
    detail["interpretation"] = confidence

    latest_test = _self_test(payload)
    if latest_test:
        detail["latest_self_test"] = latest_test

    nvme = payload.get("nvme_smart_health_information_log", {})
    if isinstance(nvme, dict) and nvme:
        nvme_fields = {
            "critical_warning": "critical_warning",
            "temperature": "temperature_c",
            "percentage_used": "percentage_used",
            "media_errors": "media_errors",
            "num_err_log_entries": "error_log_entries",
            "power_on_hours": "power_on_hours",
        }
        for source, target in nvme_fields.items():
            if nvme.get(source) is not None:
                detail[target] = nvme[source]

    previous_device = previous_device or {}
    previous_attributes = previous_device.get("attributes", {})
    previous_history = previous_device.get("history", {}).get("attributes", {})
    detail["history"] = {
        "first_observed_at": previous_device.get("history", {}).get(
            "first_observed_at",
            previous_observed_at or observed_at,
        ),
        "previous_observed_at": previous_device.get("history", {}).get(
            "last_observed_at"
        ),
        "last_observed_at": observed_at,
        "attributes": _counter_history(
            attributes,
            previous_attributes if isinstance(previous_attributes, dict) else {},
            previous_history if isinstance(previous_history, dict) else {},
            observed_at,
            previous_observed_at,
        ),
    }
    kernel = _kernel_storage_evidence(kernel_output, detail["device"])
    detail["kernel_evidence"] = kernel
    topology = _device_topology(
        detail.get("serial"),
        proxmox_config_results,
    )
    if topology:
        detail["topology"] = topology

    evidence: list[dict[str, Any]] = []
    status = "healthy"
    if command_rc & 0b11:
        status = "unknown"
        detail["collection_error"] = "smartctl could not fully access the device"
        evidence.append(
            {
                "level": "unknown",
                "source": "smartctl",
                "confirmed": True,
                "message": detail["collection_error"],
            }
        )
    elif (
        detail.get("smart_passed") is False
        or _integer(detail.get("critical_warning")) not in (None, 0)
        or command_rc & 0b1000
    ):
        status = "critical"
        evidence.append(
            {
                "level": "critical",
                "source": "smart",
                "confirmed": True,
                "message": "SMART reported a failing health condition",
            }
        )
    else:
        if kernel["severity"] in {"warning", "critical"}:
            status = "warning"
            evidence.append(
                {
                    "level": "warning",
                    "source": "kernel",
                    "confirmed": True,
                    "message": (
                        f"{kernel['event_count']} recent kernel storage event(s) "
                        "explicitly named this device"
                    ),
                }
            )

        counter_labels = {
            "pending_sectors": "pending sectors",
            "reallocated_sectors": "reallocated sectors",
            "reallocated_events": "reallocation events",
            "offline_uncorrectable": "offline uncorrectable sectors",
            "reported_uncorrectable": "reported uncorrectable errors",
            "interface_crc_errors": "interface CRC errors",
        }
        nonzero = {
            name: value
            for name, value in attributes.items()
            if name in counter_labels and value > 0
        }
        if nonzero:
            trusted = confidence["level"] != "low"
            active_failure_counters = {
                "pending_sectors",
                "offline_uncorrectable",
                "reported_uncorrectable",
            }
            counter_statuses: list[str] = []
            for name, value in nonzero.items():
                trend = detail["history"]["attributes"].get(name, {}).get("trend")
                active = name in active_failure_counters or trend == "increasing"
                level = "warning" if trusted and active else "watch"
                counter_statuses.append(level)
                qualifier = f"Reported value {value}:" if not trusted else str(value)
                message = (
                    f"{qualifier} {counter_labels[name]}"
                    if not trusted
                    else f"{value} {counter_labels[name]}"
                )
                if trend == "increasing":
                    message += " and the value is increasing"
                evidence.append(
                    {
                        "level": level,
                        "source": "smart_attribute",
                        "confirmed": trusted,
                        "active": active,
                        "trend": trend or "baseline",
                        "attribute": name,
                        "message": message,
                    }
                )
            status = _worst_status([status, *counter_statuses])

        media_errors = _integer(detail.get("media_errors")) or 0
        if media_errors > 0:
            status = "warning" if status == "healthy" else status
            evidence.append(
                {
                    "level": "warning",
                    "source": "nvme",
                    "confirmed": True,
                    "message": f"{media_errors} NVMe media error(s)",
                }
            )
        smartctl_log_bits = [
            (0b10000000, "watch", "SMART self-test log contains a historical error"),
            (0b01000000, "watch", "SMART error log contains recorded errors"),
            (
                0b00100000,
                "watch",
                "A SMART usage attribute crossed its threshold in the past",
            ),
            (
                0b00010000,
                "warning",
                "A SMART prefailure attribute is currently at or below threshold",
            ),
        ]
        for bit, level, message in smartctl_log_bits:
            if command_rc & bit:
                status = _worst_status([status, level])
                evidence.append(
                    {
                        "level": level,
                        "source": "smartctl",
                        "confirmed": True,
                        "active": level == "warning",
                        "message": message,
                    }
                )

    detail["evidence"] = evidence
    detail["assessment"] = status
    detail["status"] = status
    return status, detail


# CHAPTER 8.8 — SMART module aggregation and collection-failure semantics
def smart_module_result(
    command_results: list[dict[str, Any]] | None,
    scan_rc: int = 0,
    kernel_output: str = "",
    previous_result: dict[str, Any] | None = None,
    observed_at: str | None = None,
    previous_observed_at: str | None = None,
    proxmox_config_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one standardized SMART monitoring result."""

    results = command_results or []
    if not results:
        return {
            "check": "smart",
            "status": "unknown",
            "summary": "No SMART-accessible devices were detected",
            "details": {"scan_rc": int(scan_rc), "devices": []},
        }

    previous_devices = (
        previous_result.get("details", {}).get("devices", [])
        if isinstance(previous_result, dict)
        else []
    )
    previous_by_serial = {
        str(device.get("serial")): device
        for device in previous_devices
        if isinstance(device, dict) and device.get("serial")
    }
    previous_by_path = {
        str(device.get("device")): device
        for device in previous_devices
        if isinstance(device, dict) and device.get("device")
    }

    devices: list[dict[str, Any]] = []
    statuses: list[str] = []
    for item in results:
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(item.get("stdout", "") or "{}")
        except (TypeError, json.JSONDecodeError):
            pass
        serial = payload.get("serial_number")
        item_spec = item.get("item", {})
        path = item_spec.get("name") if isinstance(item_spec, dict) else str(item_spec)
        previous_device = previous_by_serial.get(str(serial)) or previous_by_path.get(
            str(path)
        )
        status, detail = _smart_device_result(
            item,
            kernel_output,
            previous_device,
            observed_at,
            previous_observed_at,
            proxmox_config_results,
        )
        statuses.append(status)
        devices.append(detail)

    overall = _worst_status(statuses)
    critical = statuses.count("critical")
    warnings = statuses.count("warning")
    unknown = statuses.count("unknown")
    watches = statuses.count("watch")
    if overall == "critical":
        summary = (
            f"{critical} device(s) critical; {warnings} warning; "
            f"{watches} under watch; {unknown} unknown"
        )
    elif overall == "warning":
        summary = (
            f"{warnings} device(s) require attention; "
            f"{watches} under watch; {unknown} unknown"
        )
    elif overall == "unknown":
        summary = f"{unknown} SMART device(s) unavailable; {watches} under watch"
    elif overall == "watch":
        summary = (
            f"{watches} device(s) under watch; "
            "no active deterioration detected"
        )
    else:
        summary = f"{len(devices)} SMART device(s) healthy"
    return {
        "check": "smart",
        "status": overall,
        "summary": summary,
        "details": {"scan_rc": int(scan_rc), "devices": devices},
    }


# CHAPTER 8.9 — ZFS pool parsing, scan evidence, and module aggregation
def _zfs_pools(output: str) -> list[dict[str, Any]]:
    """Parse tab-separated zpool list output."""

    pools: list[dict[str, Any]] = []
    for line in (output or "").splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            continue
        name, size, allocated, free, capacity, health = fields
        pools.append(
            {
                "name": name,
                "size_bytes": _integer(size),
                "allocated_bytes": _integer(allocated),
                "free_bytes": _integer(free),
                "capacity_percent": _integer(capacity),
                "health": health,
            }
        )
    return pools


def _zfs_scans(output: str) -> list[dict[str, str]]:
    """Associate zpool scan lines with pool names."""

    scans: list[dict[str, str]] = []
    current_pool = "unknown"
    for line in (output or "").splitlines():
        pool_match = re.match(r"\s*pool:\s*(\S+)", line)
        if pool_match:
            current_pool = pool_match.group(1)
        scan_match = re.match(r"\s*scan:\s*(.+)", line)
        if scan_match:
            scans.append({"pool": current_pool, "status": scan_match.group(1)})
    return scans


def _zfs_attention(output: str) -> list[dict[str, Any]]:
    """Extract non-online or error-bearing rows from zpool status."""

    rows: list[dict[str, Any]] = []
    states = {"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED"}
    for line in (output or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[1] not in states:
            continue
        read_errors = _integer(fields[2])
        write_errors = _integer(fields[3])
        checksum_errors = _integer(fields[4])
        if (
            fields[1] != "ONLINE"
            or any(value not in (None, 0) for value in (read_errors, write_errors, checksum_errors))
        ):
            rows.append(
                {
                    "name": fields[0],
                    "state": fields[1],
                    "read_errors": read_errors,
                    "write_errors": write_errors,
                    "checksum_errors": checksum_errors,
                }
            )
    return rows


def zfs_module_result(
    status_output: str,
    list_output: str,
    status_rc: int = 0,
    list_rc: int = 0,
) -> dict[str, Any]:
    """Build one standardized ZFS monitoring result."""

    pools = _zfs_pools(list_output)
    topology_by_pool = {
        pool["name"]: pool for pool in _zfs_topology(status_output)
    }
    for pool in pools:
        pool["vdevs"] = topology_by_pool.get(pool["name"], {}).get("vdevs", [])
    scans = _zfs_scans(status_output)
    attention = _zfs_attention(status_output)
    details = {
        "status_rc": int(status_rc),
        "list_rc": int(list_rc),
        "pools": pools,
        "scans": scans,
        "devices_requiring_attention": attention,
    }
    if int(status_rc) != 0 or int(list_rc) != 0:
        status = "unknown"
        summary = "ZFS collection unavailable"
    elif not pools:
        status = "unknown"
        summary = "No ZFS pools were detected"
    elif any(pool["health"] != "ONLINE" for pool in pools):
        status = "critical"
        summary = "One or more ZFS pools are not online"
    elif attention:
        status = "warning"
        summary = f"{len(attention)} ZFS row(s) require attention"
    else:
        status = "healthy"
        summary = f"{len(pools)} ZFS pool(s) online"
    return {
        "check": "zfs",
        "status": status,
        "summary": summary,
        "details": details,
    }


# CHAPTER 8.10 — Ansible filter registration boundary
class FilterModule:
    """Expose storage normalization filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "smart_scan_devices": smart_scan_devices,
            "proxmox_vm_ids": proxmox_vm_ids,
            "proxmox_passthrough_vm_ids": proxmox_passthrough_vm_ids,
            "proxmox_guest_storage_topology": proxmox_guest_storage_topology,
            "attach_storage_topology": attach_storage_topology,
            "smart_module_result": smart_module_result,
            "zfs_module_result": zfs_module_result,
            "safe_json_object": safe_json_object,
        }
