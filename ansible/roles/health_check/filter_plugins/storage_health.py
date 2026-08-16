"""Read-only ZFS and SMART result normalization for health reports."""

from __future__ import annotations

import json
import re
from typing import Any


STATUS_ORDER = {
    "healthy": 0,
    "unknown": 1,
    "warning": 2,
    "critical": 3,
}


def _integer(value: Any) -> int | None:
    """Return the first integer represented by a SMART value."""

    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    match = re.search(r"-?\d+", str(value or ""))
    return int(match.group(0)) if match else None


def _worst_status(statuses: list[str]) -> str:
    """Return the most severe normalized status."""

    return max(statuses, key=lambda item: STATUS_ORDER.get(item, 1))


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


def _smart_device_result(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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

    status = "healthy"
    if command_rc & 0b11:
        status = "unknown"
        detail["collection_error"] = "smartctl could not fully access the device"
    elif (
        detail.get("smart_passed") is False
        or _integer(detail.get("critical_warning")) not in (None, 0)
        or command_rc & 0b1000
    ):
        status = "critical"
    else:
        warning_values = [
            attributes.get("reallocated_sectors", 0),
            attributes.get("reallocated_events", 0),
            attributes.get("pending_sectors", 0),
            attributes.get("offline_uncorrectable", 0),
            attributes.get("reported_uncorrectable", 0),
            attributes.get("interface_crc_errors", 0),
            _integer(detail.get("media_errors")) or 0,
        ]
        if any(value > 0 for value in warning_values) or command_rc & 0b11110000:
            status = "warning"
    detail["status"] = status
    return status, detail


def smart_module_result(
    command_results: list[dict[str, Any]] | None,
    scan_rc: int = 0,
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

    devices: list[dict[str, Any]] = []
    statuses: list[str] = []
    for item in results:
        status, detail = _smart_device_result(item)
        statuses.append(status)
        devices.append(detail)

    overall = _worst_status(statuses)
    attention = sum(status in {"warning", "critical", "unknown"} for status in statuses)
    summary = (
        f"{len(devices)} SMART device(s) healthy"
        if attention == 0
        else f"{attention} of {len(devices)} SMART device(s) require attention"
    )
    return {
        "check": "smart",
        "status": overall,
        "summary": summary,
        "details": {"scan_rc": int(scan_rc), "devices": devices},
    }


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


class FilterModule:
    """Expose storage normalization filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "smart_scan_devices": smart_scan_devices,
            "smart_module_result": smart_module_result,
            "zfs_module_result": zfs_module_result,
        }
