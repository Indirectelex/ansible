"""Focused tests for the local dashboard health-check controller."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


SERVER_PATH = (
    Path(__file__).resolve().parents[1]
    / "dashboard"
    / "server.py"
)
SPEC = importlib.util.spec_from_file_location("dashboard_server", SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
dashboard_server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_server)


class DashboardServerTests(unittest.TestCase):
    """Verify command construction, allowlisting, and loopback protections."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.ansible_dir = Path(self.temporary_directory.name)
        self.reports_dir = self.ansible_dir / "reports"
        self.playbooks_dir = self.ansible_dir / "playbooks"
        self.reports_dir.mkdir()
        self.playbooks_dir.mkdir()
        (self.playbooks_dir / "health-check.yml").write_text(
            "---\n",
            encoding="utf-8",
        )
        (self.playbooks_dir / "security-update.yml").write_text(
            "---\n",
            encoding="utf-8",
        )
        (self.reports_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "hosts": [
                        {"id": "nimbus"},
                        {"id": "docker-ct"},
                        {"id": "bad/host"},
                    ],
                },
            ),
            encoding="utf-8",
        )
        (self.reports_dir / "nimbus.json").write_text(
            json.dumps(
                {
                    "host": "nimbus",
                    "generated_at": "2026-08-11T20:00:00-04:00",
                    "health_status": "OK",
                    "patch_posture_status": "ACTION_NEEDED",
                    "security_updates_available": 2,
                    "regular_updates_available": 5,
                    "reboot_required": False,
                    "failed_service_count": 0,
                    "security_packages": {
                        "review_required": [],
                        "restart_sensitive": [
                            {"name": "openssl"},
                        ],
                        "standard_security": [
                            {"name": "libstdc++6"},
                        ],
                    },
                },
            ),
            encoding="utf-8",
        )

    def wait_for_completion(self, controller: object) -> dict[str, object]:
        """Wait briefly for the controller's daemon worker."""

        for _ in range(100):
            snapshot = controller.snapshot()
            if snapshot["state"] != "running":
                return snapshot
            time.sleep(0.01)
        self.fail("Health-check worker did not complete")

    def test_only_manifest_hosts_are_allowed(self) -> None:
        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=lambda *args, **kwargs: SimpleNamespace(
                returncode=0,
                stdout="ok",
                stderr="",
            ),
        )

        self.assertEqual(controller.allowed_hosts(), {"nimbus", "docker-ct"})
        started, message, _job = controller.start("zebulon")
        self.assertFalse(started)
        self.assertIn("not present", message)

    def test_fixed_command_runs_one_validated_host_without_shell(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="PLAY RECAP", stderr="")

        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=runner,
        )
        started, _message, _job = controller.start("nimbus")
        self.assertTrue(started)
        completed = self.wait_for_completion(controller)

        self.assertEqual(completed["state"], "success")
        self.assertEqual(
            calls[0][0],
            [
                "ansible-playbook",
                "playbooks/health-check.yml",
                "--limit",
                "nimbus",
            ],
        )
        self.assertNotIn("shell", calls[0][1])
        self.assertEqual(calls[0][1]["cwd"], self.ansible_dir.resolve())

    def test_invalid_hostname_never_reaches_runner(self) -> None:
        calls: list[object] = []
        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=lambda *args, **kwargs: calls.append(args),
        )

        started, message, _job = controller.start("nimbus;reboot")
        self.assertFalse(started)
        self.assertEqual(message, "Invalid hostname.")
        self.assertEqual(calls, [])

    def test_security_update_runs_fixed_install_then_health_check(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="PLAY RECAP", stderr="")

        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=runner,
        )
        started, _message, _job = controller.start_security_update("nimbus")
        self.assertTrue(started)
        completed = self.wait_for_completion(controller)

        self.assertEqual(completed["state"], "success")
        self.assertEqual(completed["action"], "security_update")
        self.assertEqual(calls[0][:5], [
            "ansible-playbook",
            "playbooks/security-update.yml",
            "--limit",
            "nimbus",
            "--extra-vars",
        ])
        self.assertEqual(
            json.loads(calls[0][5]),
            {
                "security_update_dashboard_confirmed": True,
                "security_update_target_host": "nimbus",
            },
        )
        self.assertEqual(
            calls[1],
            [
                "ansible-playbook",
                "playbooks/health-check.yml",
                "--limit",
                "nimbus",
            ],
        )

        history = json.loads(
            (self.reports_dir / "maintenance" / "nimbus.json").read_text(
                encoding="utf-8",
            ),
        )
        latest = history["latest"]
        self.assertEqual(latest["state"], "success")
        self.assertEqual(latest["approved_package_count"], 2)
        self.assertEqual(
            latest["approved_packages"],
            ["libstdc++6", "openssl"],
        )
        self.assertEqual(
            [phase["name"] for phase in latest["phases"]],
            ["installation", "report_refresh"],
        )
        self.assertTrue(completed["maintenance_history_saved"])

    def test_failed_install_is_persisted_without_running_health_check(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> SimpleNamespace:
            calls.append(command)
            return SimpleNamespace(
                returncode=2,
                stdout="APT install failed safely",
                stderr="No packages were installed",
            )

        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=runner,
        )
        started, _message, _job = controller.start_security_update("nimbus")
        self.assertTrue(started)
        completed = self.wait_for_completion(controller)

        self.assertEqual(completed["state"], "failed")
        self.assertIn("installation failed", completed["message"])
        self.assertEqual(len(calls), 1)

        history = json.loads(
            (self.reports_dir / "maintenance" / "nimbus.json").read_text(
                encoding="utf-8",
            ),
        )
        latest = history["latest"]
        self.assertEqual(latest["state"], "failed")
        self.assertIsNone(latest["final_report"])
        self.assertEqual(latest["phases"][0]["state"], "failed")
        self.assertIn(
            "No packages were installed",
            latest["phases"][0]["output_tail"],
        )

    def test_successful_install_with_failed_refresh_is_distinguished(self) -> None:
        return_codes = iter([0, 2])

        def runner(_command: list[str], **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                returncode=next(return_codes),
                stdout="PLAY RECAP",
                stderr="",
            )

        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
            runner=runner,
        )
        started, _message, _job = controller.start_security_update("nimbus")
        self.assertTrue(started)
        completed = self.wait_for_completion(controller)

        self.assertEqual(completed["state"], "failed")
        self.assertIn("report refresh failed", completed["message"])

        history = json.loads(
            (self.reports_dir / "maintenance" / "nimbus.json").read_text(
                encoding="utf-8",
            ),
        )
        phases = history["latest"]["phases"]
        self.assertEqual(phases[0]["state"], "success")
        self.assertEqual(phases[1]["state"], "failed")

    def test_maintenance_history_is_bounded_and_newest_first(self) -> None:
        controller = dashboard_server.HealthCheckController(
            self.ansible_dir,
            self.reports_dir,
        )

        for index in range(12):
            controller._save_maintenance_record(  # noqa: SLF001
                "nimbus",
                {
                    "started_at": f"2026-08-11T20:{index:02d}:00+00:00",
                    "finished_at": f"2026-08-11T20:{index:02d}:30+00:00",
                    "state": "success",
                },
            )

        history = json.loads(
            (self.reports_dir / "maintenance" / "nimbus.json").read_text(
                encoding="utf-8",
            ),
        )
        self.assertEqual(len(history["runs"]), 10)
        self.assertEqual(
            history["runs"][0]["started_at"],
            "2026-08-11T20:11:00+00:00",
        )
        self.assertEqual(history["latest"], history["runs"][0])

    def test_security_update_confirmation_is_host_specific(self) -> None:
        valid = dashboard_server.valid_security_confirmation

        self.assertTrue(
            valid(
                {
                    "confirm_host": "nimbus",
                    "install_security_updates": True,
                    "automatic_reboot": False,
                },
                "nimbus",
            ),
        )
        self.assertFalse(
            valid(
                {
                    "confirm_host": "zebulon",
                    "install_security_updates": True,
                    "automatic_reboot": False,
                },
                "nimbus",
            ),
        )
        self.assertFalse(valid({}, "nimbus"))

    def test_browser_action_requires_exact_loopback_origin(self) -> None:
        trusted = dashboard_server.trusted_browser_request

        self.assertTrue(
            trusted("127.0.0.1:8088", "http://127.0.0.1:8088"),
        )
        self.assertTrue(trusted("localhost:8088", "http://localhost:8088"))
        self.assertFalse(
            trusted("127.0.0.1:8088", "https://malicious.example"),
        )
        self.assertFalse(
            trusted("malicious.example", "http://malicious.example"),
        )
        self.assertFalse(
            trusted("127.0.0.1:8088", "http://localhost:8088"),
        )


if __name__ == "__main__":
    unittest.main()
