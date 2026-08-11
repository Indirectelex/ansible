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
        self.assertIs(
            filters["health_check_merge_pending_security_state"],
            MODULE.health_check_merge_pending_security_state,
        )
        self.assertIs(
            filters["health_check_determine_patch_posture"],
            MODULE.health_check_determine_patch_posture,
        )

    def test_key_value_observations_are_parsed(self) -> None:
        self.assertEqual(
            MODULE.health_check_parse_key_values(
                ["timer_enabled=enabled", "next_attempt_at=2026-08-12"]
            ),
            {
                "timer_enabled": "enabled",
                "next_attempt_at": "2026-08-12",
            },
        )

    def test_first_detection_is_preserved_until_package_clears(self) -> None:
        packages = {
            "review_required": [
                {
                    "name": "systemd",
                    "installed_version": "255.4-1",
                    "candidate_version": "255.4-2",
                    "classification": "review_required",
                }
            ],
            "restart_sensitive": [],
            "standard_security": [],
        }
        first = MODULE.health_check_merge_pending_security_state(
            packages,
            {},
            "2026-08-11T16:00:00-04:00",
            100,
            True,
        )
        second = MODULE.health_check_merge_pending_security_state(
            packages,
            first,
            "2026-08-11T17:00:00-04:00",
            200,
            True,
        )

        self.assertEqual(second["pending_since_epoch"], 100)
        self.assertEqual(
            second["packages"][0]["first_detected_epoch"], 100
        )
        self.assertEqual(second["packages"][0]["last_detected_epoch"], 200)

        cleared = MODULE.health_check_merge_pending_security_state(
            {
                "review_required": [],
                "restart_sensitive": [],
                "standard_security": [],
            },
            second,
            "2026-08-11T18:00:00-04:00",
            300,
            True,
        )
        self.assertEqual(cleared["packages"], [])
        self.assertIsNone(cleared["pending_since_at"])

    def test_untrusted_observation_does_not_clear_history(self) -> None:
        previous = {
            "last_trusted_observation_at": "2026-08-11T16:00:00-04:00",
            "last_trusted_observation_epoch": 100,
            "packages": [
                {
                    "name": "systemd",
                    "installed_version": "255.4-1",
                    "first_detected_at": "2026-08-11T16:00:00-04:00",
                    "first_detected_epoch": 100,
                }
            ],
        }
        result = MODULE.health_check_merge_pending_security_state(
            {},
            previous,
            "2026-08-11T17:00:00-04:00",
            200,
            False,
        )

        self.assertFalse(result["observation_trusted"])
        self.assertEqual(result["pending_since_epoch"], 100)
        self.assertEqual(len(result["packages"]), 1)

    def test_os_managed_posture_transitions(self) -> None:
        arguments = {
            "apt_return_code": 0,
            "counts_trusted": True,
            "security_count": 11,
            "review_count": 5,
            "reboot_required": False,
            "regular_count": 5,
            "automation_enabled": True,
            "automation_active": False,
            "automation_attempt_after_detection": False,
            "automation_failed_after_detection": False,
        }
        self.assertEqual(
            MODULE.health_check_determine_patch_posture(**arguments),
            "SCHEDULED",
        )

        arguments["automation_attempt_after_detection"] = True
        self.assertEqual(
            MODULE.health_check_determine_patch_posture(**arguments),
            "AUTOMATION_OVERDUE",
        )

        arguments["automation_failed_after_detection"] = True
        self.assertEqual(
            MODULE.health_check_determine_patch_posture(**arguments),
            "AUTOMATION_ERROR",
        )

        arguments["automation_active"] = True
        self.assertEqual(
            MODULE.health_check_determine_patch_posture(**arguments),
            "INSTALLING",
        )

    def test_manual_review_status_is_unchanged(self) -> None:
        status = MODULE.health_check_determine_patch_posture(
            0,
            True,
            5,
            2,
            False,
            10,
            False,
            False,
            False,
            False,
        )
        self.assertEqual(status, "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
