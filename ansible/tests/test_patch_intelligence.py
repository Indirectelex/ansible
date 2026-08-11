"""Tests for the APT patch-intelligence filter."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PLUGIN_PATH = (
    Path(__file__).resolve().parents[1]
    / "roles"
    / "health_check"
    / "filter_plugins"
    / "patch_intelligence.py"
)
SPEC = importlib.util.spec_from_file_location(
    "patch_intelligence",
    PLUGIN_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load patch-intelligence filter")

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SECURITY_PATTERNS = [
    r"(?i)\b(?:Debian-Security|Ubuntu):"
    r"[^ )]+/[^ )]*-security\b",
]
REVIEW_RULES = [
    {
        "pattern": r"^linux-image",
        "reason": "Kernel package",
    },
    {
        "pattern": r"^openssh-server$",
        "reason": "Remote access service",
    },
]
RESTART_RULES = [
    {
        "pattern": r"^(?:libc6|libc-bin)$",
        "reason": "Core C runtime",
    },
]


class PatchIntelligenceTests(unittest.TestCase):
    """Verify parsing, security detection and classification."""

    def test_mixed_debian_and_ubuntu_updates(self) -> None:
        lines = [
            "Inst openssh-server [1:9.2] "
            "(1:9.3 Debian-Security:12/oldstable-security [amd64])",
            "Inst libc6 [2.39-0ubuntu8] "
            "(2.39-0ubuntu9 Ubuntu:24.04/noble-security [amd64])",
            "Inst linux-image-amd64 [6.1.1] "
            "(6.1.2 Debian-Security:12/oldstable-security [amd64])",
            "Inst tzdata [2026a] "
            "(2026b Debian-Security:13/stable-security [all])",
            "Inst curl [8.0] (8.1 Debian:12.12/oldstable [amd64])",
        ]
        result = MODULE.health_check_classify_apt_updates(
            lines,
            SECURITY_PATTERNS,
            REVIEW_RULES,
            RESTART_RULES,
        )
        self.assertEqual(result["updates_available"], 5)
        self.assertEqual(result["security_updates_available"], 4)
        self.assertEqual(result["regular_updates_available"], 1)
        self.assertEqual(result["review_required"], 2)
        self.assertEqual(result["restart_sensitive"], 1)
        self.assertEqual(result["standard_security"], 1)
        self.assertEqual(
            result["updates_available"],
            result["security_updates_available"]
            + result["regular_updates_available"],
        )
        self.assertEqual(
            result["security_updates_available"],
            result["review_required"]
            + result["restart_sensitive"]
            + result["standard_security"],
        )

    def test_non_inst_lines_are_ignored(self) -> None:
        result = MODULE.health_check_classify_apt_updates(
            [
                "Reading package lists...",
                "Conf package-name (1.0 Debian:12/oldstable [amd64])",
            ],
            SECURITY_PATTERNS,
            REVIEW_RULES,
            RESTART_RULES,
        )
        self.assertEqual(result["updates_available"], 0)
        self.assertEqual(result["security_updates_available"], 0)
        self.assertEqual(result["regular_updates_available"], 0)

    def test_architecture_suffix_does_not_break_rules(self) -> None:
        result = MODULE.health_check_classify_apt_updates(
            [
                "Inst openssh-server:amd64 [1:9.2] "
                "(1:9.3 Debian-Security:12/oldstable-security [amd64])",
            ],
            SECURITY_PATTERNS,
            REVIEW_RULES,
            RESTART_RULES,
        )
        self.assertEqual(result["review_required"], 1)

    def test_filter_is_registered_for_ansible(self) -> None:
        filters = MODULE.FilterModule().filters()

        self.assertIs(
            filters["health_check_classify_apt_updates"],
            MODULE.health_check_classify_apt_updates,
        )


if __name__ == "__main__":
    unittest.main()
