"""Focused tests for the local dashboard health-check controller.

TEACHER NOTE — CHAPTERS 11, 12, AND 14
These tests lock down loopback trust, manifest allowlisting, fixed commands,
maintenance history, and bounded UniFi/controller behaviour.
CHANGE INSTRUCTIONS: every route, trust check, query family, or job-state change
needs a positive case, a rejection/failure case, and matching server notes.
"""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit


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

    def test_unifi_summary_imports_fixed_prometheus_metrics(self) -> None:
        def sample(
            metric_name: str,
            value: float,
            **labels: str,
        ) -> dict[str, object]:
            return {
                "metric": {"__name__": metric_name, "job": "unpoller", **labels},
                "value": [1786900000, str(value)],
            }

        payload = {
            "status": "success",
            "data": {
                "result": [
                    sample("unpoller_controller_up", 1),
                    sample("unpoller_site_aps", 1, subsystem="wlan", status="error"),
                    sample("unpoller_site_switches", 5, subsystem="lan", status="error"),
                    sample("unpoller_site_gateways", 1, subsystem="wan", status="ok"),
                    sample("unpoller_site_users", 18, subsystem="lan", status="error"),
                    sample("unpoller_site_users", 2, subsystem="wlan", status="error"),
                    sample("unpoller_site_disconnected", 1, subsystem="lan", status="error"),
                    sample("unpoller_site_disconnected", 2, subsystem="wlan", status="error"),
                    sample("unpoller_site_latency_seconds", 0.002, subsystem="www", status="ok"),
                    sample("unpoller_site_intenet_drops_total", 2, subsystem="www", status="ok"),
                    sample(
                        "unpoller_device_info",
                        1,
                        mac="68:d7:9a:68:24:49",
                        name="Main switch",
                        model="US624P",
                        type="usw",
                        ip="192.168.12.243",
                    ),
                    sample(
                        "unpoller_device_temperature_celsius",
                        42,
                        name="Main switch",
                    ),
                    sample(
                        "unpoller_device_uptime_seconds",
                        0,
                        name="Main switch",
                    ),
                ],
            },
        }
        requested_urls: list[str] = []

        def opener(request: object, **_kwargs: object) -> io.BytesIO:
            requested_urls.append(request.full_url)
            parsed = urlsplit(request.full_url)
            query = parse_qs(parsed.query).get("query", [""])[0]
            response_payload = payload
            if parsed.path.endswith("/query_range"):
                results = []
                if "unpoller_site_users" in query:
                    results = [
                        {
                            "metric": {},
                            "values": [
                                [1786813600, "19"],
                                [1786900000, "20"],
                            ],
                        },
                    ]
                response_payload = {
                    "status": "success",
                    "data": {"resultType": "matrix", "result": results},
                }
            elif "__name__=~" not in query:
                results = []
                if "topk(5" in query and "errors_total" in query:
                    results = [
                        {
                            "metric": {"name": "Main switch", "port": "8"},
                            "value": [1786900000, "4325"],
                        },
                    ]
                elif "packets_total" in query and "errors_total" in query:
                    results = [
                        {"metric": {}, "value": [1786900000, "0.0004"]},
                    ]
                elif "packets_total" in query and "dropped_total" in query:
                    results = [
                        {"metric": {}, "value": [1786900000, "0.0008"]},
                    ]
                elif "port_receive_errors_total" in query:
                    results = [
                        {"metric": {}, "value": [1786900000, "4325"]},
                    ]
                elif "port_receive_dropped_total" in query:
                    results = [
                        {"metric": {}, "value": [1786900000, "6235"]},
                    ]
                response_payload = {
                    "status": "success",
                    "data": {"resultType": "vector", "result": results},
                }
            return io.BytesIO(json.dumps(response_payload).encode("utf-8"))

        client = dashboard_server.UnifiPrometheusClient(
            "http://192.168.40.214:9090",
            opener=opener,
            controller_client=SimpleNamespace(
                devices=lambda: [
                    {
                        "mac": "68:d7:9a:68:24:49",
                        "name": "Main switch",
                        "model": "US624P",
                        "controller_state": "OFFLINE",
                        "reported_online": False,
                        "inventory_source": "unifi_controller",
                    },
                ],
            ),
        )
        summary = client.summary()

        self.assertEqual(summary["status"], "WARNING")
        self.assertEqual(summary["summary"]["clients"], 20)
        self.assertEqual(summary["summary"]["disconnected"], 3)
        self.assertEqual(summary["summary"]["latency_ms"], 2.0)
        self.assertEqual(summary["health"]["devices"]["status"], "WARNING")
        self.assertEqual(summary["health"]["devices"]["unexpected_offline"], 1)
        self.assertEqual(summary["health"]["switching"]["status"], "WATCH")
        self.assertEqual(
            summary["health"]["switching"]["port_error_ratio_pct"],
            0.04,
        )
        self.assertEqual(
            summary["health"]["switching"]["error_hotspots"][0]["port"],
            "8",
        )
        switch_finding = next(
            finding
            for finding in summary["findings"]
            if finding["title"] == "Switch-port errors"
        )
        self.assertIn("Main switch port 8", switch_finding["detail"])
        self.assertEqual(len(summary["trends"]["clients"]), 2)
        self.assertEqual(summary["trends"]["clients"][-1][1], 20)
        self.assertEqual(len(summary["devices"]), 1)
        self.assertEqual(summary["devices"][0]["name"], "Main switch")
        self.assertEqual(summary["devices"][0]["temperature_c"], 42)
        self.assertFalse(summary["devices"][0]["reported_online"])
        self.assertIn("Main switch", summary["findings"][0]["detail"])
        query = parse_qs(urlsplit(requested_urls[0]).query)["query"][0]
        self.assertIn('job="unpoller"', query)
        self.assertIn("unpoller_device_info", query)
        self.assertNotIn("unpoller_client_mac", query)

        expected_client = dashboard_server.UnifiPrometheusClient(
            "http://192.168.40.214:9090",
            opener=opener,
            expected_offline_devices=["Main switch"],
            controller_client=SimpleNamespace(
                devices=lambda: [
                    {
                        "mac": "68:d7:9a:68:24:49",
                        "name": "Main switch",
                        "model": "US624P",
                        "controller_state": "OFFLINE",
                        "reported_online": False,
                        "inventory_source": "unifi_controller",
                    },
                ],
            ),
        )
        expected_summary = expected_client.summary()
        self.assertEqual(expected_summary["status"], "WATCH")
        self.assertEqual(expected_summary["health"]["devices"]["status"], "OK")
        self.assertEqual(expected_summary["summary"]["expected_offline"], 1)
        self.assertEqual(expected_summary["summary"]["unexpected_offline"], 0)

    def test_unifi_integration_url_is_optional_topology_configuration(self) -> None:
        topology_dir = self.ansible_dir / "dashboard" / "assets"
        topology_dir.mkdir(parents=True)
        (topology_dir / "dashboard-topology.json").write_text(
            json.dumps(
                {
                    "integrations": {
                        "unifi": {
                            "enabled": True,
                            "prometheus_url": "http://192.168.40.214:9090",
                            "controller_url": "https://192.168.2.12",
                            "controller_verify_tls": False,
                            "expected_offline_devices": ["ModemPlug"],
                        },
                    },
                },
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            dashboard_server.configured_prometheus_url(self.ansible_dir),
            "http://192.168.40.214:9090",
        )
        self.assertEqual(
            dashboard_server.configured_unifi_settings(self.ansible_dir)[
                "expected_offline_devices"
            ],
            ["ModemPlug"],
        )
        settings = dashboard_server.configured_unifi_settings(self.ansible_dir)
        self.assertEqual(settings["controller_url"], "https://192.168.2.12")
        self.assertFalse(settings["controller_verify_tls"])

    def test_unifi_controller_reads_adopted_devices_from_local_api(self) -> None:
        requested: list[object] = []

        def opener(request: object, **kwargs: object) -> io.BytesIO:
            requested.append((request, kwargs))
            path = urlsplit(request.full_url).path
            if path.endswith("/v1/sites"):
                payload = {
                    "offset": 0,
                    "limit": 200,
                    "totalCount": 1,
                    "data": [{"id": "site-id", "name": "Default"}],
                }
            else:
                payload = {
                    "offset": 0,
                    "limit": 200,
                    "totalCount": 1,
                    "data": [
                        {
                            "id": "device-id",
                            "ipAddress": "192.168.12.243",
                            "macAddress": "68:d7:9a:68:24:49",
                            "model": "US624P",
                            "name": "Main switch",
                            "firmwareVersion": "7.4.1",
                            "state": "OFFLINE",
                        },
                    ],
                }
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        devices = dashboard_server.UnifiControllerClient(
            "https://192.168.2.12",
            "secret-key",
            verify_tls=False,
            opener=opener,
        ).devices()

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["name"], "Main switch")
        self.assertEqual(devices[0]["ip"], "192.168.12.243")
        self.assertEqual(devices[0]["controller_state"], "OFFLINE")
        self.assertFalse(devices[0]["reported_online"])
        self.assertTrue(
            requested[1][0].full_url.endswith(
                "/proxy/network/integration/v1/sites/site-id/devices?offset=0&limit=200",
            ),
        )
        self.assertEqual(requested[0][0].get_header("X-api-key"), "secret-key")
        self.assertIn("context", requested[0][1])

    def test_unifi_controller_roster_excludes_forgotten_history(self) -> None:
        sample_timestamp = 1786900000
        current_payload = {
            "status": "success",
            "data": {
                "result": [
                    {
                        "metric": {
                            "__name__": "unpoller_controller_up",
                            "job": "unpoller",
                        },
                        "value": [sample_timestamp, "1"],
                    },
                    {
                        "metric": {
                            "__name__": "unpoller_device_info",
                            "job": "unpoller",
                            "mac": "00:00:00:00:00:01",
                            "name": "Online switch",
                            "model": "USMINI",
                            "type": "usw",
                        },
                        "value": [sample_timestamp, "1"],
                    },
                    {
                        "metric": {
                            "__name__": "unpoller_device_uptime_seconds",
                            "job": "unpoller",
                            "name": "Online switch",
                        },
                        "value": [sample_timestamp, "3600"],
                    },
                ],
            },
        }
        history_payload = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {
                            "job": "unpoller",
                            "mac": "00:00:00:00:00:01",
                            "name": "Online switch",
                            "model": "USMINI",
                            "type": "usw",
                        },
                        "values": [[sample_timestamp, "1"]],
                    },
                    {
                        "metric": {
                            "job": "unpoller",
                            "mac": "00:00:00:00:00:02",
                            "name": "Missing switch",
                            "model": "USMINI",
                            "type": "usw",
                        },
                        "values": [[sample_timestamp - 3600, "1"]],
                    },
                ],
            },
        }
        empty_payload = {
            "status": "success",
            "data": {"result": []},
        }

        def opener(request: object, **_kwargs: object) -> io.BytesIO:
            parsed = urlsplit(request.full_url)
            query = parse_qs(parsed.query).get("query", [""])[0]
            response_payload = empty_payload
            if "__name__=~" in query:
                response_payload = current_payload
            elif parsed.path.endswith("/query_range"):
                response_payload = (
                    history_payload
                    if "unpoller_device_info" in query
                    else {
                        "status": "success",
                        "data": {"resultType": "matrix", "result": []},
                    }
                )
            return io.BytesIO(json.dumps(response_payload).encode("utf-8"))

        summary = dashboard_server.UnifiPrometheusClient(
            "http://192.168.40.214:9090",
            opener=opener,
            controller_client=SimpleNamespace(
                devices=lambda: [
                    {
                        "mac": "00:00:00:00:00:01",
                        "name": "Online switch",
                        "model": "USMINI",
                        "controller_state": "ONLINE",
                        "reported_online": True,
                        "inventory_source": "unifi_controller",
                    },
                ],
            ),
        ).summary()

        self.assertEqual(summary["summary"]["total_devices"], 1)
        self.assertEqual(summary["summary"]["online_devices"], 1)
        self.assertEqual(summary["summary"]["unexpected_offline"], 0)
        self.assertEqual(summary["health"]["devices"]["status"], "OK")
        self.assertTrue(summary["summary"]["inventory_authoritative"])
        self.assertNotIn(
            "Missing switch",
            [device["name"] for device in summary["devices"]],
        )


    def test_event_history_uses_current_reports_as_a_quiet_baseline(self) -> None:
        store = dashboard_server.EventStore(
            self.ansible_dir / ".state" / "dashboard" / "events.db",
            self.reports_dir,
        )

        store.sync_reports()

        self.assertEqual(store.list_events(), [])
        self.assertTrue(store.database_path.is_file())
        self.assertFalse(store.database_path.is_relative_to(self.reports_dir))

    def test_event_history_records_state_and_smart_counter_changes_once(self) -> None:
        store = dashboard_server.EventStore(
            self.ansible_dir / ".state" / "dashboard" / "events.db",
            self.reports_dir,
        )
        store.sync_reports()

        report = json.loads(
            (self.reports_dir / "nimbus.json").read_text(encoding="utf-8"),
        )
        report.update(
            {
                "generated_at": "2026-08-11T21:00:00-04:00",
                "health_status": "WARNING",
                "health_status_reasons": ["Storage needs attention"],
                "module_results": [
                    {
                        "check": "smart",
                        "status": "watch",
                        "summary": "1 device under watch",
                        "details": {
                            "devices": [
                                {
                                    "device": "/dev/sda",
                                    "model": "Example SSD",
                                    "serial": "SERIAL-1",
                                    "assessment": "watch",
                                    "history": {
                                        "attributes": {
                                            "pending_sectors": {
                                                "previous": 13,
                                                "current": 15,
                                                "change": 2,
                                            },
                                        },
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        )
        (self.reports_dir / "nimbus.json").write_text(
            json.dumps(report),
            encoding="utf-8",
        )

        store.sync_reports()
        first_events = store.list_events()
        store.sync_reports()
        second_events = store.list_events()

        self.assertEqual(first_events, second_events)
        self.assertTrue(
            any(
                event["event_type"] == "state_change"
                and event["source"] == "health"
                and event["previous_state"] == "OK"
                and event["current_state"] == "WARNING"
                for event in first_events
            ),
        )
        self.assertTrue(
            any(
                event["event_type"] == "monitoring_change"
                and event["source"] == "smart"
                and event["current_state"] == "WATCH"
                for event in first_events
            ),
        )
        smart_event = next(
            event
            for event in first_events
            if event["event_type"] == "metric_change"
        )
        self.assertEqual(smart_event["source"], "smart")
        self.assertEqual(smart_event["previous_state"], "13")
        self.assertEqual(smart_event["current_state"], "15")
        self.assertIn("Pending sectors changed from 13 to 15", smart_event["message"])

    def test_event_history_filters_are_bounded_and_validated(self) -> None:
        store = dashboard_server.EventStore(
            self.ansible_dir / ".state" / "dashboard" / "events.db",
            self.reports_dir,
        )
        store.sync_reports()

        self.assertEqual(store.list_events(host="bad/host"), [])
        self.assertEqual(store.list_events(source="bad source"), [])
        self.assertEqual(
            dashboard_server.event_status("healthy"),
            "OK",
        )

    def test_event_history_period_summary_facets_and_paging(self) -> None:
        store = dashboard_server.EventStore(
            self.ansible_dir / ".state" / "dashboard" / "events.db",
            self.reports_dir,
        )
        store.sync_reports()

        now = datetime.now(timezone.utc)
        seeded = [
            {
                "occurred_at": (now - timedelta(hours=2)).isoformat(),
                "host": "nimbus",
                "source": "health",
                "severity": "WARNING",
                "event_type": "state_change",
                "message": "Warning started",
                "previous_state": "OK",
                "current_state": "WARNING",
                "fingerprint": "period-warning",
            },
            {
                "occurred_at": (now - timedelta(hours=1)).isoformat(),
                "host": "nimbus",
                "source": "health",
                "severity": "OK",
                "event_type": "state_change",
                "message": "Recovered",
                "previous_state": "WARNING",
                "current_state": "OK",
                "fingerprint": "period-recovered",
            },
            {
                "occurred_at": (now - timedelta(days=3)).isoformat(),
                "host": "nimbus",
                "source": "smart",
                "severity": "WATCH",
                "event_type": "metric_change",
                "message": "Older SMART change",
                "previous_state": "1",
                "current_state": "2",
                "fingerprint": "period-old-smart",
            },
        ]
        with dashboard_server.closing(store._connect()) as connection, connection:
            for event in seeded:
                store._insert_event(connection, event)

        recent = store.list_events(period="24h", limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["message"], "Recovered")
        next_page = store.list_events(period="24h", limit=1, offset=1)
        self.assertEqual(next_page[0]["message"], "Warning started")

        summary = store.event_summary(period="24h")
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_severity"]["WARNING"], 1)
        self.assertEqual(summary["by_severity"]["OK"], 1)
        self.assertEqual(summary["recovered"], 1)

        filtered = store.event_summary(host="nimbus", severity="WARNING", period="7d")
        self.assertEqual(filtered["total"], 1)
        facets = store.event_facets()
        self.assertEqual(facets["hosts"], ["docker-ct", "nimbus"])
        self.assertIn("health", facets["sources"])
        self.assertIn("smart", facets["sources"])
        self.assertEqual(store.list_events(period="invalid"), [])

    def test_event_history_prunes_events_older_than_retention(self) -> None:
        store = dashboard_server.EventStore(
            self.ansible_dir / ".state" / "dashboard" / "events.db",
            self.reports_dir,
        )
        store.sync_reports()

        old_event = {
            "occurred_at": (
                datetime.now(timezone.utc)
                - timedelta(days=dashboard_server.EVENT_HISTORY_RETENTION_DAYS + 1)
            ).isoformat(),
            "host": "nimbus",
            "source": "health",
            "severity": "WARNING",
            "event_type": "state_change",
            "message": "Expired event",
            "previous_state": "OK",
            "current_state": "WARNING",
            "fingerprint": "expired-event",
        }
        with dashboard_server.closing(store._connect()) as connection, connection:
            store._insert_event(connection, old_event)

        self.assertEqual(store.event_summary(period="all")["total"], 1)
        store.sync_reports()
        self.assertEqual(store.event_summary(period="all")["total"], 0)

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
