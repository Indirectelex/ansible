"""Contract checks for the Proxmox-style dashboard workspace.

TEACHER NOTE — CHAPTER 13
These tests are executable documentation for navigation, inspector, drawer,
UniFi, storage, and status-presentation invariants.
CHANGE INSTRUCTIONS: an intentional layout contract change must update the
source teacher note and the focused assertion together; never delete a test
merely to make a redesign pass.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DashboardLayoutTests(unittest.TestCase):
    """Keep the host navigator narrow and the selected-node view primary."""

    def test_navigation_and_node_workspace_are_separate(self) -> None:
        html = (ROOT / "dashboard/index.html").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()

        self.assertIn('class="fleet-navigation"', html)
        self.assertIn('class="host-inspector"', html)
        self.assertNotIn("fleet-table-header", html)
        self.assertNotIn("host-search", html)
        self.assertNotIn("health-filter", html)
        self.assertNotIn("patch-filter", html)
        self.assertIn("grid-template-columns: 300px minmax(0, 1fr)", stylesheet)
        self.assertNotIn("max-width: 1600px", stylesheet)

    def test_tree_rows_only_render_identity_and_health_dot(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        start = javascript.index("function renderHostRow")
        end = javascript.index("function renderFleetTree")
        renderer = javascript[start:end]

        self.assertIn('class="host-name-line"', renderer)
        self.assertIn("status-dot", renderer)
        self.assertLess(renderer.index("<strong>"), renderer.index("status-dot"))
        for removed_column in (
            "tree-col-health",
            "tree-col-maintenance",
            "tree-col-cpu",
            "tree-col-memory",
            "tree-col-disk",
            "tree-col-checked",
        ):
            self.assertNotIn(removed_column, renderer)

    def test_selected_node_keeps_removed_list_information(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()

        for label in (
            "CPU / core",
            "Memory",
            "Root disk",
            "Maintenance",
            "Last checked",
        ):
            self.assertIn(label, javascript)

    def test_fleet_status_and_logs_live_in_bottom_drawer(self) -> None:
        html = (ROOT / "dashboard/index.html").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()

        main_end = html.index("</main>")
        drawer_start = html.index('id="activity-drawer"')
        fleet_start = html.index('id="fleet-summary"')
        log_start = html.index('id="activity-log-output"')

        self.assertGreater(drawer_start, main_end)
        self.assertGreater(fleet_start, drawer_start)
        self.assertGreater(log_start, fleet_start)
        self.assertIn('id="activity-drawer-toggle"', html)
        self.assertIn('aria-controls="activity-drawer-body"', html)
        self.assertIn(".activity-drawer", stylesheet)
        self.assertIn("position: fixed", stylesheet)

    def test_activity_drawer_renders_existing_job_output_tail(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()

        self.assertIn("function setActivityDrawerOpen", javascript)
        self.assertIn("job.output_tail", javascript)
        self.assertIn('outputLines.join("\\n")', javascript)
        self.assertIn('["running", "failed"].includes(job.state)', javascript)


    def test_event_history_lives_beside_the_existing_activity_log(self) -> None:
        html = (ROOT / "dashboard/index.html").read_text()
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()
        server = (ROOT / "dashboard/server.py").read_text()

        self.assertIn('id="event-history-list"', html)
        self.assertIn('id="event-history-context"', html)
        self.assertIn("function renderEventHistory", javascript)
        self.assertIn('loadEventHistory({limit: 50})', javascript)
        self.assertIn("startEventHistoryPolling", javascript)
        self.assertIn(".event-history-row", stylesheet)
        self.assertIn('API_EVENTS_PATH = "/api/events"', server)
        self.assertIn('".state" / "dashboard" / "events.db"', server)

    def test_event_history_full_view_has_filters_counts_and_details(self) -> None:
        html = (ROOT / "dashboard/index.html").read_text()
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()
        server = (ROOT / "dashboard/server.py").read_text()

        for selector in [
            'id="event-history-dialog"',
            'id="event-filter-host"',
            'id="event-filter-severity"',
            'id="event-filter-source"',
            'id="event-filter-period"',
            'id="event-history-summary"',
            'id="event-history-load-more"',
        ]:
            self.assertIn(selector, html)
        self.assertIn("function refreshFullEventHistory", javascript)
        self.assertIn("function renderEventHistorySummary", javascript)
        self.assertIn("new URLSearchParams()", javascript)
        self.assertIn("event-history-detail", stylesheet)
        self.assertIn("EVENT_HISTORY_RETENTION_DAYS = 90", server)
        self.assertIn("def event_summary(", server)
        self.assertIn("def event_facets(", server)

    def test_smart_status_badges_explain_why_states_differ(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()

        self.assertIn("function smartStatusContext", javascript)
        self.assertIn('confidence === "low"', javascript)
        self.assertIn('{label: "Uncertain data", kind: "uncertain"}', javascript)
        self.assertIn('{label: "Stable", kind: "stable"}', javascript)
        self.assertIn(
            '{label: "Confirmed issue", kind: "confirmed"}',
            javascript,
        )
        self.assertIn(
            ".smart-drive-grid {\n  display: grid;\n"
            "  grid-template-columns: repeat(2, minmax(0, 1fr));",
            stylesheet,
        )

    def test_unifi_is_a_live_selectable_infrastructure_node(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        server = (ROOT / "dashboard/server.py").read_text()
        topology = (ROOT / "dashboard/assets/dashboard-topology.json").read_text()

        self.assertIn('const UNIFI_NODE_ID = "@unifi-network"', javascript)
        self.assertIn("function renderUnifiTreeRow", javascript)
        self.assertIn("function renderUnifiInspector", javascript)
        self.assertIn('fetch("api/unifi/summary"', javascript)
        self.assertIn('API_UNIFI_SUMMARY_PATH = "/api/unifi/summary"', server)
        self.assertIn('"prometheus_url": "http://192.168.40.214:9090"', topology)

    def test_unifi_prioritizes_findings_and_health_over_inventory(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()

        for operational_section in (
            "Active findings",
            "Operational health",
            "Last 24 hours",
            'renderUnifiHealthCard("WAN"',
            'renderUnifiHealthCard("Wi-Fi"',
            'renderUnifiHealthCard("Switching"',
            'renderUnifiHealthCard("Devices"',
        ):
            self.assertIn(operational_section, javascript)
        self.assertIn('class="unifi-details unifi-inventory-details"', javascript)
        self.assertNotIn('<details class="unifi-details unifi-inventory-details" open', javascript)
        self.assertIn("formatUnifiCountWithRatio", javascript)
        self.assertIn("device.last_seen_at", javascript)
        self.assertIn("adopted devices", javascript)
        self.assertIn("Roster from UniFi", javascript)
        self.assertIn(".unifi-health-grid", stylesheet)
        self.assertIn(".unifi-trend-grid", stylesheet)

    def test_datacenter_and_network_sections_are_independently_collapsible(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()

        self.assertIn("collapsedSections: new Set()", javascript)
        self.assertIn("function renderInfrastructureSection", javascript)
        self.assertIn('"datacenter",', javascript)
        self.assertIn('"network",', javascript)
        self.assertIn('data-action="toggle-section"', javascript)
        self.assertIn("state.collapsedSections.has(section)", javascript)

    def test_live_storage_topology_is_rendered_from_both_hosts(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()
        playbook = (ROOT / "playbooks/health-check.yml").read_text()
        nimbus = (ROOT / "inventory/host_vars/nimbus.yml").read_text()

        self.assertIn('fetch("storage-topology.json"', javascript)
        self.assertIn("function renderZfsPhysicalTopology", javascript)
        self.assertIn("function storageTopologyGuests", javascript)
        self.assertIn("Live via Proxmox QEMU Guest Agent", javascript)
        self.assertIn('class="zfs-physical-topology"', javascript)
        self.assertIn(".zfs-member-row", stylesheet)
        self.assertIn("Write live storage topology", playbook)
        self.assertIn("health_check_storage_topology_result", playbook)
        self.assertNotIn("WD-WCC4N", nimbus)
        self.assertNotIn("apps_configs", nimbus)

    def test_pbs_is_a_monitored_vm_under_nimbus(self) -> None:
        inventory = (ROOT / "inventory/hosts.yml").read_text()
        topology = (ROOT / "dashboard/assets/dashboard-topology.json").read_text()
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        pbs_tasks = (ROOT / "roles/health_check/tasks/modules/pbs.yml").read_text()

        self.assertIn("pbs_servers:", inventory)
        self.assertIn("ansible_host: 192.168.12.157", inventory)
        self.assertIn("pbs: true", inventory)
        self.assertIn('"parent": "nimbus"', topology)
        self.assertIn('"guest_id": 999', topology)
        self.assertIn('"kind": "pbs"', topology)
        self.assertIn('pbs: "Proxmox Backup Server VM"', javascript)
        self.assertIn("function renderPbsModuleDetails", javascript)
        self.assertIn("proxmox-backup-manager", pbs_tasks)
        self.assertIn("Collect PBS datastore filesystem capacity", pbs_tasks)


if __name__ == "__main__":
    unittest.main()
