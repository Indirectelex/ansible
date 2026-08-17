"""Filters for read-only APT patch intelligence.

TEACHER NOTE — CHAPTER 7
Purpose: convert cached ``apt-get --simulate`` and automation observations into
trusted package groups, durable pending history, and one patch-posture state.
Inputs are strings/mappings collected by Ansible; outputs are JSON-safe values.
CHANGE INSTRUCTIONS: keep parsing pure and first-match classification explicit;
add transition fixtures whenever a rule, field, or posture boundary changes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


# CHAPTER 7.1 — Package-line parsing and first-match impact classification
def _matching_rule(
    package_name: str,
    rules: Iterable[Mapping[str, str]],
) -> Mapping[str, str] | None:
    """Return the first operational-impact rule matching a package."""

    for rule in rules:
        pattern = str(rule.get("pattern", ""))
        if pattern and re.search(pattern, package_name):
            return rule

    return None


def _parse_inst_line(line: str) -> dict[str, Any] | None:
    """Parse one apt-get --simulate upgrade Inst line."""

    package_match = re.match(r"^Inst\s+(\S+)", line)
    if not package_match:
        return None

    package_name = package_match.group(1)
    installed_match = re.search(r"\[([^\]]+)\]", line)
    candidate_match = re.search(
        r"\((\S+)(?:\s+(.*?))?\)\s*$",
        line,
    )

    source = ""
    candidate_version = ""
    if candidate_match:
        candidate_version = candidate_match.group(1)
        source = candidate_match.group(2) or ""
        source = re.sub(r"\s+\[[^\]]+\]\s*$", "", source)

    return {
        "name": package_name,
        "base_name": package_name.split(":", 1)[0],
        "installed_version": (
            installed_match.group(1) if installed_match else ""
        ),
        "candidate_version": candidate_version,
        "source": source,
        "_raw_line": line,
    }


def health_check_classify_apt_updates(
    lines: Iterable[str] | str | None,
    security_origin_patterns: Iterable[str],
    review_rules: Iterable[Mapping[str, str]],
    restart_rules: Iterable[Mapping[str, str]],
) -> dict[str, Any]:
    """Classify simulated APT upgrades without changing the target."""

    if lines is None:
        input_lines: list[str] = []
    elif isinstance(lines, str):
        input_lines = lines.splitlines()
    else:
        input_lines = [str(line) for line in lines]

    groups: dict[str, list[dict[str, Any]]] = {
        "review_required": [],
        "restart_sensitive": [],
        "standard_security": [],
    }
    total_count = 0
    regular_count = 0

    for line in input_lines:
        package = _parse_inst_line(line)
        if package is None:
            continue

        total_count += 1
        is_security = any(
            re.search(pattern, package["_raw_line"])
            for pattern in security_origin_patterns
        )
        if not is_security:
            regular_count += 1
            continue

        review_rule = _matching_rule(package["base_name"], review_rules)
        restart_rule = _matching_rule(package["base_name"], restart_rules)
        if review_rule:
            classification = "review_required"
            reason = str(review_rule.get("reason", "Review required"))
        elif restart_rule:
            classification = "restart_sensitive"
            reason = str(
                restart_rule.get("reason", "Restart-sensitive package")
            )
        else:
            classification = "standard_security"
            reason = "Standard security update"

        package.pop("base_name", None)
        package.pop("_raw_line", None)
        package["classification"] = classification
        package["classification_reason"] = reason
        groups[classification].append(package)

    for packages in groups.values():
        packages.sort(key=lambda item: item["name"])

    security_count = sum(len(packages) for packages in groups.values())
    return {
        "updates_available": total_count,
        "security_updates_available": security_count,
        "regular_updates_available": regular_count,
        "review_required": len(groups["review_required"]),
        "restart_sensitive": len(groups["restart_sensitive"]),
        "standard_security": len(groups["standard_security"]),
        "security_packages": groups,
    }


def health_check_parse_key_values(
    lines: Iterable[str] | str | None,
) -> dict[str, str]:
    """Parse newline-delimited key=value observations."""

    if lines is None:
        input_lines: list[str] = []
    elif isinstance(lines, str):
        input_lines = lines.splitlines()
    else:
        input_lines = [str(line) for line in lines]

    result: dict[str, str] = {}
    for line in input_lines:
        key, separator, value = line.partition("=")
        if separator and key:
            result[key.strip()] = value.strip()

    return result


def _security_package_identity(package: Mapping[str, Any]) -> str:
    """Build a stable identity for one installed security candidate."""

    return "|".join(
        (
            str(package.get("name", "")),
            str(package.get("installed_version", "")),
        )
    )


# CHAPTER 7.2 — Trusted first-seen history across observations
# An untrusted scan cannot prove a package disappeared, so it must not clear the
# prior trusted state.
def health_check_merge_pending_security_state(
    security_packages: Mapping[str, Iterable[Mapping[str, Any]]] | None,
    previous_state: Mapping[str, Any] | None,
    observed_at: str,
    observed_epoch: int | str,
    trusted: bool,
) -> dict[str, Any]:
    """Preserve first-seen times for active, trusted security candidates."""

    previous = dict(previous_state or {})
    previous_packages = previous.get("packages", [])
    if not isinstance(previous_packages, list):
        previous_packages = []

    previous_by_identity = {
        _security_package_identity(package): package
        for package in previous_packages
        if isinstance(package, Mapping)
    }

    if not trusted:
        packages = [dict(package) for package in previous_packages]
        first_epochs = [
            int(package.get("first_detected_epoch", 0) or 0)
            for package in packages
        ]
        first_epochs = [epoch for epoch in first_epochs if epoch > 0]
        return {
            "schema_version": 1,
            "observation_trusted": False,
            "last_trusted_observation_at": previous.get(
                "last_trusted_observation_at"
            ),
            "last_trusted_observation_epoch": previous.get(
                "last_trusted_observation_epoch", 0
            ),
            "pending_since_at": (
                min(
                    (
                        package
                        for package in packages
                        if int(
                            package.get("first_detected_epoch", 0) or 0
                        )
                        == min(first_epochs)
                    ),
                    key=lambda package: str(
                        package.get("first_detected_at", "")
                    ),
                ).get("first_detected_at")
                if first_epochs
                else None
            ),
            "pending_since_epoch": min(first_epochs) if first_epochs else 0,
            "packages": packages,
        }

    epoch = int(observed_epoch)
    current_packages: list[dict[str, Any]] = []
    for classification in (
        "review_required",
        "restart_sensitive",
        "standard_security",
    ):
        for package_value in (security_packages or {}).get(
            classification, []
        ):
            package = dict(package_value)
            identity = _security_package_identity(package)
            prior = previous_by_identity.get(identity, {})
            package["first_detected_at"] = prior.get(
                "first_detected_at", observed_at
            )
            package["first_detected_epoch"] = int(
                prior.get("first_detected_epoch", epoch) or epoch
            )
            package["last_detected_at"] = observed_at
            package["last_detected_epoch"] = epoch
            current_packages.append(package)

    current_packages.sort(key=lambda package: str(package.get("name", "")))
    first_epochs = [
        int(package["first_detected_epoch"])
        for package in current_packages
    ]
    pending_since_epoch = min(first_epochs) if first_epochs else 0
    pending_since_at = None
    if pending_since_epoch:
        pending_since_at = next(
            package["first_detected_at"]
            for package in current_packages
            if int(package["first_detected_epoch"]) == pending_since_epoch
        )

    return {
        "schema_version": 1,
        "observation_trusted": True,
        "last_trusted_observation_at": observed_at,
        "last_trusted_observation_epoch": epoch,
        "pending_since_at": pending_since_at,
        "pending_since_epoch": pending_since_epoch,
        "packages": current_packages,
    }


# CHAPTER 7.3 — Final posture decision from package and automation evidence
def health_check_determine_patch_posture(
    apt_return_code: int | str,
    counts_trusted: bool,
    security_count: int | str,
    review_count: int | str,
    reboot_required: bool,
    regular_count: int | str,
    automation_enabled: bool,
    automation_active: bool,
    automation_attempt_after_detection: bool,
    automation_failed_after_detection: bool,
) -> str:
    """Choose patch posture while distinguishing OS-managed updates."""

    if int(apt_return_code) != 0:
        return "ERROR"
    if not counts_trusted:
        return "DATA_STALE"

    security_updates = int(security_count)
    if security_updates > 0 and automation_enabled:
        if automation_active:
            return "INSTALLING"
        if automation_failed_after_detection:
            return "AUTOMATION_ERROR"
        if automation_attempt_after_detection:
            return "AUTOMATION_OVERDUE"
        return "SCHEDULED"

    if int(review_count) > 0:
        return "REVIEW_REQUIRED"
    if security_updates > 0:
        return "ACTION_NEEDED"
    if reboot_required:
        return "REBOOT_PENDING"
    if int(regular_count) > 0:
        return "ROUTINE_MAINTENANCE"
    return "CURRENT"


# CHAPTER 7.4 — Ansible filter registration boundary
class FilterModule:
    """Expose patch-intelligence filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "health_check_classify_apt_updates": (
                health_check_classify_apt_updates
            ),
            "health_check_parse_key_values": health_check_parse_key_values,
            "health_check_merge_pending_security_state": (
                health_check_merge_pending_security_state
            ),
            "health_check_determine_patch_posture": (
                health_check_determine_patch_posture
            ),
        }
