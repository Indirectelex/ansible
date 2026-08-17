"""Read-only Proxmox Backup Server result normalization.

TEACHER NOTE — CHAPTER 5.5
Purpose: parse PBS JSON and POSIX ``df`` observations into one standardized
module result with per-datastore capacity evidence.
CHANGE INSTRUCTIONS: accept only absolute datastore paths, keep collection
failure distinct from high usage, and add fixtures at warning/critical bounds.
"""

from __future__ import annotations

import json
import re
from typing import Any


# CHAPTER 5.5A — Shared severity ordering and defensive JSON normalization
STATUS_ORDER = {
    "healthy": 0,
    "watch": 1,
    "unknown": 2,
    "warning": 3,
    "critical": 4,
}


def _json_list(value: Any) -> list[dict[str, Any]]:
    """Return only object rows from one JSON array."""

    try:
        payload = json.loads(str(value or "[]"))
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


# CHAPTER 5.5B — Configured datastore identity and path validation
def pbs_datastore_paths(output: str) -> list[dict[str, str]]:
    """Extract configured PBS datastore names and filesystem paths."""

    datastores: list[dict[str, str]] = []
    for item in _json_list(output):
        name = item.get("name") or item.get("store")
        path = item.get("path")
        if not name or not path or not str(path).startswith("/"):
            continue
        datastores.append({"name": str(name), "path": str(path)})
    return sorted(datastores, key=lambda item: item["name"])


def _df_usage(result: dict[str, Any]) -> dict[str, Any]:
    """Normalize one POSIX df result collected for a datastore path."""

    item = result.get("item", {}) if isinstance(result, dict) else {}
    detail: dict[str, Any] = {
        "name": item.get("name", "Unknown") if isinstance(item, dict) else "Unknown",
        "path": item.get("path") if isinstance(item, dict) else None,
        "status": "unknown",
    }
    if not isinstance(result, dict) or int(result.get("rc", 1) or 0) != 0:
        detail["collection_error"] = str(result.get("stderr", "")).strip() or "Filesystem usage unavailable"
        return detail
    lines = [line for line in str(result.get("stdout", "")).splitlines() if line.strip()]
    if len(lines) < 2:
        detail["collection_error"] = "df returned no datastore usage row"
        return detail
    fields = lines[-1].split()
    if len(fields) < 6:
        detail["collection_error"] = "df returned an unexpected datastore usage row"
        return detail
    percent_match = re.fullmatch(r"(\d+)%", fields[4])
    if not percent_match:
        detail["collection_error"] = "df returned an invalid capacity percentage"
        return detail
    detail.update(
        {
            "filesystem": fields[0],
            "size_kib": int(fields[1]),
            "used_kib": int(fields[2]),
            "available_kib": int(fields[3]),
            "capacity_percent": int(percent_match.group(1)),
            "mountpoint": " ".join(fields[5:]),
            "status": "healthy",
        }
    )
    return detail


# CHAPTER 5.5C — Per-datastore usage plus module-level aggregation
def pbs_module_result(
    versions_output: str,
    versions_rc: int,
    datastore_output: str,
    datastore_rc: int,
    df_results: list[dict[str, Any]] | None,
    warning_percent: int = 80,
    critical_percent: int = 90,
) -> dict[str, Any]:
    """Build one standardized PBS monitoring result."""

    configured = pbs_datastore_paths(datastore_output)
    usages = [_df_usage(item) for item in (df_results or [])]
    usage_by_name = {str(item.get("name")): item for item in usages}
    datastores: list[dict[str, Any]] = []
    statuses: list[str] = []

    for item in configured:
        detail = usage_by_name.get(item["name"], {**item, "status": "unknown"})
        percent = detail.get("capacity_percent")
        status = str(detail.get("status", "unknown"))
        if percent is not None:
            status = (
                "critical"
                if int(percent) >= int(critical_percent)
                else "warning"
                if int(percent) >= int(warning_percent)
                else "healthy"
            )
        detail["status"] = status
        datastores.append(detail)
        statuses.append(status)

    versions = _json_list(versions_output)
    details = {
        "versions_rc": int(versions_rc),
        "datastore_rc": int(datastore_rc),
        "versions": versions or str(versions_output or "").splitlines()[:20],
        "datastores": datastores,
    }
    if int(datastore_rc) != 0:
        status = "unknown"
        summary = "PBS datastore collection unavailable"
    elif not configured:
        status = "warning"
        summary = "No PBS datastores are configured"
    else:
        overall = max(statuses or ["unknown"], key=lambda value: STATUS_ORDER.get(value, 2))
        status = overall
        critical = sum(item == "critical" for item in statuses)
        warnings = sum(item == "warning" for item in statuses)
        unknown = sum(item == "unknown" for item in statuses)
        if critical:
            summary = f"{critical} PBS datastore(s) critically full"
        elif warnings:
            summary = f"{warnings} PBS datastore(s) need capacity review"
        elif unknown:
            summary = f"{unknown} PBS datastore(s) could not be measured"
        else:
            summary = f"{len(datastores)} PBS datastore(s) healthy"
    return {
        "check": "pbs",
        "status": status,
        "summary": summary,
        "details": details,
    }


# CHAPTER 5.5D — Ansible filter registration boundary
class FilterModule:
    """Expose PBS normalization filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "pbs_datastore_paths": pbs_datastore_paths,
            "pbs_module_result": pbs_module_result,
        }
