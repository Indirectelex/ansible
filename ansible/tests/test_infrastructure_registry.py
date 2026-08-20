"""Protect the EchoDATA infrastructure registry contract.

TEACHER NOTE — CHAPTER 3A
Purpose: prove that the maintained registry contains the monitored fleet,
runtime workloads and public-service identity; that server validation rejects
broken relationships; and that publication/browser code consumes the registry
rather than a second hand-maintained topology map.
CHANGE INSTRUCTIONS: add fixtures whenever registry schema or relationship
rules change; never weaken validation merely to accept an inconsistent source.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "dashboard" / "server.py"
SPEC = importlib.util.spec_from_file_location("dashboard_server_registry", SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
dashboard_server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_server)


class InfrastructureRegistryTests(unittest.TestCase):
    """Verify registry identity, references, publication and browser use."""

    def registry(self) -> dict[str, object]:
        source = yaml.safe_load(
            (ROOT / "inventory/infrastructure-registry.yml").read_text(
                encoding="utf-8",
            ),
        )
        return source["infrastructure_registry"]

    def test_registry_contains_current_hosts_workloads_and_public_services(self) -> None:
        registry = self.registry()

        self.assertEqual(registry["schema_version"], 3)
        self.assertEqual(
            set(registry["hosts"]),
            {"docker-ct", "nimbus", "pbs", "scale", "ubuntu-server", "zebulon"},
        )
        self.assertEqual(registry["hosts"]["docker-ct"]["parent"], "zebulon")
        self.assertEqual(registry["hosts"]["scale"]["parent"], "nimbus")
        self.assertEqual(registry["hosts"]["pbs"]["guest_id"], 999)

        self.assertEqual(
            registry["workloads"]["website-app"]["runtime_host"],
            "ubuntu-server",
        )
        self.assertEqual(
            registry["workloads"]["portal-app"]["runtime_host"],
            "ubuntu-server",
        )
        self.assertEqual(
            registry["workloads"]["erpnext-stack"]["runtime_host"],
            "docker-ct",
        )
        self.assertEqual(registry["workloads"]["erpnext-stack"]["engine"], "docker")

        self.assertEqual(registry["services"]["website"]["hostname"], "echodata.ca")
        self.assertEqual(
            registry["services"]["portal"]["hostname"],
            "signal.echodata.ca",
        )
        self.assertEqual(
            registry["services"]["erpnext"]["hostname"],
            "vault.echodata.ca",
        )
        for service in registry["services"].values():
            self.assertEqual(service["edge"], "cloudflare")
            self.assertEqual(service["exposure"], "public")
            self.assertNotIn("runtime_host", service)
        self.assertEqual(registry["services"]["website"]["workload"], "website-app")
        self.assertEqual(registry["services"]["portal"]["workload"], "portal-app")
        self.assertEqual(registry["services"]["erpnext"]["workload"], "erpnext-stack")

        logging = registry["observability"]["logging"]
        self.assertEqual(logging["backend"]["kind"], "loki")
        self.assertEqual(logging["backend"]["runtime_host"], "docker-ct")
        self.assertEqual(logging["backend"]["port"], 3100)
        self.assertEqual(logging["backend"]["retention_days"], 15)
        self.assertEqual(
            set(logging["collectors"]["journal"]["hosts"]),
            {"docker-ct", "nimbus", "pbs", "ubuntu-server", "zebulon"},
        )
        self.assertEqual(logging["collectors"]["docker"]["hosts"], ["docker-ct"])

    def test_server_validates_registry_and_derives_runtime_hosts(self) -> None:
        registry = self.registry()
        normalized = dashboard_server.validate_infrastructure_registry(registry)

        self.assertTrue(normalized["available"])
        self.assertEqual(normalized["summary"]["hosts"], 6)
        self.assertEqual(normalized["summary"]["workloads"], 3)
        self.assertEqual(normalized["summary"]["services"], 3)
        self.assertEqual(normalized["summary"]["mapped_services"], 3)
        self.assertEqual(normalized["summary"]["unmapped_services"], 0)
        self.assertEqual(normalized["summary"]["edges"], 1)
        self.assertEqual(normalized["summary"]["logging_collectors"], 5)
        self.assertEqual(
            normalized["observability"]["logging"]["backend"]["endpoint"],
            "http://192.168.40.214:3100",
        )
        self.assertEqual(
            normalized["services"]["website"]["runtime_host"],
            "ubuntu-server",
        )
        self.assertEqual(
            normalized["services"]["erpnext"]["runtime_host"],
            "docker-ct",
        )

    def test_server_rejects_broken_registry_relationships(self) -> None:
        registry = self.registry()

        bad_parent = deepcopy(registry)
        bad_parent["hosts"]["docker-ct"]["parent"] = "missing-host"
        with self.assertRaisesRegex(ValueError, "invalid parent"):
            dashboard_server.validate_infrastructure_registry(bad_parent)

        bad_workload_host = deepcopy(registry)
        bad_workload_host["workloads"]["erpnext-stack"]["runtime_host"] = "missing-host"
        with self.assertRaisesRegex(ValueError, "unknown host"):
            dashboard_server.validate_infrastructure_registry(bad_workload_host)

        bad_service_workload = deepcopy(registry)
        bad_service_workload["services"]["erpnext"]["workload"] = "missing-workload"
        with self.assertRaisesRegex(ValueError, "unknown workload"):
            dashboard_server.validate_infrastructure_registry(bad_service_workload)

        bad_edge = deepcopy(registry)
        bad_edge["services"]["portal"]["edge"] = "missing-edge"
        with self.assertRaisesRegex(ValueError, "unknown edge"):
            dashboard_server.validate_infrastructure_registry(bad_edge)

        bad_logging_host = deepcopy(registry)
        bad_logging_host["observability"]["logging"]["backend"]["runtime_host"] = "missing-host"
        with self.assertRaisesRegex(ValueError, "logging backend references unknown host"):
            dashboard_server.validate_infrastructure_registry(bad_logging_host)

        bad_collector_host = deepcopy(registry)
        bad_collector_host["observability"]["logging"]["collectors"]["journal"]["hosts"].append("missing-host")
        with self.assertRaisesRegex(ValueError, "collector journal references unknown host"):
            dashboard_server.validate_infrastructure_registry(bad_collector_host)

    def test_server_rejects_invalid_workload_engine(self) -> None:
        registry = self.registry()
        bad_engine = deepcopy(registry)
        bad_engine["workloads"]["erpnext-stack"]["engine"] = []

        with self.assertRaisesRegex(ValueError, "engine must be a string"):
            dashboard_server.validate_infrastructure_registry(bad_engine)

    def test_publication_validates_inventory_workloads_and_registry_json(self) -> None:
        playbook = (ROOT / "playbooks/health-check.yml").read_text(encoding="utf-8")

        self.assertIn("Load infrastructure registry source", playbook)
        self.assertIn("Require every monitored host in infrastructure registry", playbook)
        self.assertIn("Validate registered host identity and topology", playbook)
        self.assertIn("Validate registered workload relationships", playbook)
        self.assertIn("Validate registry observability logging contract", playbook)
        self.assertIn("Validate registry logging collector hosts", playbook)
        self.assertIn("Validate registered service relationships", playbook)
        self.assertIn("infrastructure-registry.json", playbook)
        self.assertIn("hostvars[item.key].ansible_host", playbook)
        self.assertIn("item.value.workload in health_dashboard_registry.workloads", playbook)

    def test_dashboard_consumes_registry_for_topology_workloads_and_services(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text(
            encoding="utf-8",
        )
        server = (ROOT / "dashboard/server.py").read_text(encoding="utf-8")
        topology = json.loads(
            (ROOT / "dashboard/assets/dashboard-topology.json").read_text(
                encoding="utf-8",
            ),
        )

        self.assertIn('API_REGISTRY_PATH = "/api/registry"', server)
        self.assertIn('fetch("api/registry"', javascript)
        self.assertIn("function registryWorkloads()", javascript)
        self.assertIn("function workloadForService(service)", javascript)
        self.assertIn("function registryServices()", javascript)
        self.assertIn("function renderServiceInspector(service)", javascript)
        self.assertIn("Dependency chain", javascript)
        self.assertIn("function renderRegistryHostContext(report)", javascript)
        self.assertNotIn("nodes", topology)
        self.assertIn("infrastructure-registry.yml", topology["_teacher_notes"]["purpose"])


if __name__ == "__main__":
    unittest.main()
