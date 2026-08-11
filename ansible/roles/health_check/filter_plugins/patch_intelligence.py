"""Filters for read-only APT patch intelligence."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


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


class FilterModule:
    """Expose patch-intelligence filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "health_check_classify_apt_updates": (
                health_check_classify_apt_updates
            ),
        }
