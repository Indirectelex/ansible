"""Protect the EchoDATA Loki + Alloy deployment contract.

TEACHER NOTE — OBSERVABILITY TEST CONTRACT
CHANGE INSTRUCTIONS: extend these checks with each logging schema/deployment change;
never weaken them to accept public Loki exposure or unvalidated Alloy config.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ObservabilityLoggingTests(unittest.TestCase):
    def test_registry_drives_private_loki_and_alloy_collection(self) -> None:
        registry = yaml.safe_load(
            (ROOT / "inventory/infrastructure-registry.yml").read_text(encoding="utf-8"),
        )["infrastructure_registry"]
        logging = registry["observability"]["logging"]

        self.assertEqual(logging["backend"]["kind"], "loki")
        self.assertEqual(logging["backend"]["runtime_host"], "docker-ct")
        self.assertEqual(logging["backend"]["port"], 3100)
        self.assertEqual(logging["backend"]["retention_days"], 15)
        self.assertEqual(logging["collectors"]["docker"]["hosts"], ["docker-ct"])
        self.assertNotIn("scale", logging["collectors"]["journal"]["hosts"])

    def test_logging_playbook_is_separate_and_registry_driven(self) -> None:
        playbook = (ROOT / "playbooks/logging-stack.yml").read_text(encoding="utf-8")

        self.assertIn("Deploy EchoDATA Loki backend", playbook)
        self.assertIn("Deploy EchoDATA Alloy log collectors", playbook)
        self.assertIn("infrastructure-registry.yml", playbook)
        self.assertIn("loki_target_host", playbook)
        self.assertIn("Verify Loki is reachable before configuring Alloy", playbook)
        self.assertIn("routine monitoring never installs packages", playbook)

    def test_loki_is_pinned_private_and_retained(self) -> None:
        defaults = (ROOT / "roles/loki/defaults/main.yml").read_text(encoding="utf-8")
        config = (ROOT / "roles/loki/templates/loki-config.yml.j2").read_text(encoding="utf-8")
        compose = (ROOT / "roles/loki/templates/compose.yml.j2").read_text(encoding="utf-8")

        self.assertIn('loki_version: "3.7.0"', defaults)
        self.assertIn("auth_enabled: false", config)
        self.assertIn("store: tsdb", config)
        self.assertIn("schema: v13", config)
        self.assertIn("retention_enabled: true", config)
        self.assertIn("retention_period", config)
        self.assertIn("reporting_enabled: false", config)
        self.assertIn("{{ loki_bind_address }}:{{ loki_port }}:3100", compose)
        self.assertNotIn("0.0.0.0:3100", compose)

    def test_alloy_collects_journal_and_docker_with_stable_labels(self) -> None:
        config = (ROOT / "roles/alloy/templates/config.alloy.j2").read_text(encoding="utf-8")
        tasks = (ROOT / "roles/alloy/tasks/main.yml").read_text(encoding="utf-8")

        self.assertIn('loki.source.journal "system"', config)
        self.assertIn('discovery.docker "local"', config)
        self.assertIn('loki.source.docker "local"', config)
        self.assertIn('host   = "{{ inventory_hostname }}"', config)
        self.assertIn('source = "journal"', config)
        self.assertIn('source = "docker"', config)
        self.assertIn("- alloy", tasks)
        self.assertIn("- validate", tasks)
        self.assertIn("systemd-journal", tasks)
        self.assertIn("docker", tasks)
        self.assertIn("--disable-reporting", tasks)

    def test_existing_grafana_is_provisioned_not_reinstalled(self) -> None:
        playbook = (ROOT / "playbooks/logging-stack.yml").read_text(encoding="utf-8")
        tasks = (ROOT / "roles/grafana_loki/tasks/main.yml").read_text(encoding="utf-8")
        defaults = (ROOT / "roles/grafana_loki/defaults/main.yml").read_text(encoding="utf-8")

        self.assertIn("Provision EchoDATA Loki datasource in existing Grafana", playbook)
        self.assertIn("- grafana", playbook)
        self.assertIn("docker-ct", playbook)
        self.assertIn("/opt/stacks/unpoller-unifi/grafana/provisioning/datasources", defaults)
        self.assertIn("Verify existing Grafana container is present", tasks)
        self.assertIn("Provision EchoDATA Loki datasource", tasks)
        self.assertNotIn("apt:", tasks)
        self.assertNotIn("docker compose", tasks)

    def test_grafana_loki_datasource_is_stable_and_private(self) -> None:
        template = (ROOT / "roles/grafana_loki/templates/loki.yml.j2").read_text(encoding="utf-8")

        self.assertIn("name: \"{{ grafana_loki_datasource_name }}\"", template)
        self.assertIn("type: loki", template)
        self.assertIn("url: \"{{ grafana_loki_url }}\"", template)
        self.assertIn("isDefault: false", template)
        self.assertIn("editable: false", template)


    def test_grafana_logs_dashboard_is_provisioned_without_replacing_provider(self) -> None:
        defaults = (ROOT / "roles/grafana_loki/defaults/main.yml").read_text(encoding="utf-8")
        tasks = (ROOT / "roles/grafana_loki/tasks/main.yml").read_text(encoding="utf-8")
        dashboard = (ROOT / "roles/grafana_loki/templates/echodata-logs.json.j2").read_text(encoding="utf-8")

        self.assertIn("/opt/stacks/unpoller-unifi/grafana/provisioning/dashboards", defaults)
        self.assertIn("Verify existing Grafana dashboard provider is present", tasks)
        self.assertIn("Provision EchoDATA Logs dashboard", tasks)
        self.assertIn("python3 -m json.tool %s", tasks)
        self.assertNotIn("provider.yml.j2", tasks)
        self.assertIn('"uid": "echodata-logs"', dashboard)
        self.assertIn('"title": "EchoDATA Logs"', dashboard)

    def test_grafana_logs_dashboard_has_low_cardinality_filters_and_core_panels(self) -> None:
        dashboard = (ROOT / "roles/grafana_loki/templates/echodata-logs.json.j2").read_text(encoding="utf-8")

        self.assertIn('"name": "host"', dashboard)
        self.assertIn('"name": "source"', dashboard)
        self.assertIn('"name": "container"', dashboard)
        self.assertIn('"name": "search"', dashboard)
        self.assertIn('"title": "Log volume by host"', dashboard)
        self.assertIn('"title": "Error-like"', dashboard)
        self.assertIn('"title": "Warning-like"', dashboard)
        self.assertIn('"title": "Logs"', dashboard)
        self.assertNotIn('request_id', dashboard)
        self.assertNotIn('client_ip', dashboard)


    def test_grafana_logs_dashboard_renders_to_valid_json(self) -> None:
        template = (
            ROOT / "roles/grafana_loki/templates/echodata-logs.json.j2"
        ).read_text(encoding="utf-8")

        rendered = Environment(
            undefined=StrictUndefined,
            autoescape=False,
        ).from_string(template).render()

        dashboard = json.loads(rendered)

        self.assertEqual(dashboard["uid"], "echodata-logs")
        self.assertEqual(dashboard["title"], "EchoDATA Logs")

        volume_panel = next(
            panel
            for panel in dashboard["panels"]
            if panel["title"] == "Log volume by host"
        )

        self.assertEqual(
            volume_panel["targets"][0]["legendFormat"],
            "{{host}}",
        )


if __name__ == "__main__":
    unittest.main()
