"""Safety-contract tests for the manual security update playbook.

TEACHER NOTE — CHAPTER 14
These static contracts prevent fleet-wide execution, package removal, hidden
scheduling, and automatic reboot from entering the maintenance workflow.
CHANGE INSTRUCTIONS: mutation-policy changes require explicit approval, updated
operator instructions, and stronger tests before weakening an assertion.
"""

from __future__ import annotations

import unittest
from pathlib import Path

PLAYBOOK_PATH = (
    Path(__file__).resolve().parents[1]
    / "playbooks"
    / "security-update.yml"
)


class SecurityUpdatePlaybookTests(unittest.TestCase):
    """Keep the maintenance action explicit, bounded, and reboot-free."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK_PATH.read_text(encoding="utf-8")

    def test_one_host_confirmation_is_required(self) -> None:
        self.assertIn("  serial: 1", self.source)
        self.assertIn("security_update_dashboard_confirmed", self.source)
        self.assertIn("security_update_target_host", self.source)
        self.assertIn("ansible_play_hosts_all | length == 1", self.source)

    def test_install_is_exact_and_refuses_removals(self) -> None:
        self.assertIn("--only-upgrade", self.source)
        self.assertIn("--no-remove", self.source)
        self.assertIn("fail_on_autoremove: true", self.source)
        self.assertIn("security_update_packages", self.source)

    def test_playbook_has_no_schedule_or_reboot_action(self) -> None:
        lower_source = self.source.lower()
        self.assertNotIn("ansible.builtin.reboot", lower_source)
        self.assertNotIn("ansible.builtin.cron", lower_source)
        self.assertNotIn("ansible.builtin.systemd_service", lower_source)
        self.assertNotIn("oncalendar", lower_source)


if __name__ == "__main__":
    unittest.main()
