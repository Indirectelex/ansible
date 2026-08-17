"""Static contract checks for the first-class WATCH health state.

TEACHER NOTE — CHAPTER 6
WATCH must survive normalization, overall aggregation, schema publication, and
browser presentation without becoming an urgent warning.
CHANGE INSTRUCTIONS: status-vocabulary edits must update every layer and extend
this cross-pipeline test before any label, precedence, or styling change.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WatchPipelineTests(unittest.TestCase):
    """Ensure WATCH remains wired through every reporting layer."""

    def test_ansible_pipeline_propagates_watch(self) -> None:
        main_tasks = (ROOT / "roles/health_check/tasks/main.yml").read_text()
        truenas_tasks = (ROOT / "roles/health_check/tasks/truenas.yml").read_text()
        schema_tasks = (
            ROOT / "roles/health_check/tasks/dashboard_schema.yml"
        ).read_text()
        markdown_template = (
            ROOT / "roles/health_check/templates/health-report.md.j2"
        ).read_text()

        self.assertIn("else 'WATCH'", main_tasks)
        self.assertIn("selectattr('status', 'equalto', 'watch')", main_tasks)
        self.assertIn("else 'WATCH'", truenas_tasks)
        self.assertIn("'schema_version': 5", schema_tasks)
        self.assertIn("status == 'WATCH'", markdown_template)

    def test_dashboard_presents_watch_without_immediate_action(self) -> None:
        javascript = (ROOT / "dashboard/assets/dashboard.js").read_text()
        stylesheet = (ROOT / "dashboard/assets/dashboard.css").read_text()

        self.assertIn("WATCH: 4", javascript)
        self.assertIn('healthStatus === "WATCH"', javascript)
        self.assertIn('tone: "watch"', javascript)
        self.assertIn("requiresAction: false", javascript)
        self.assertIn("under watch · No immediate action required", javascript)
        self.assertIn(".status-watch", stylesheet)
        self.assertIn(".fleet-state-watch", stylesheet)


if __name__ == "__main__":
    unittest.main()
