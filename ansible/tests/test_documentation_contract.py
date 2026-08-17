"""Enforce the repository's continuous teaching-note contract.

TEACHER NOTE — DOCUMENTATION CHAPTER
This test turns maintainability from a suggestion into an executable rule. It
scans maintained source/configuration roots but deliberately excludes generated
reports, runtime state, caches, and audit evidence.
CHANGE INSTRUCTIONS: when adding a maintained file type or source root, extend
the scanner. Do not add exclusions merely to bypass missing documentation.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAINTAINED_ROOTS = (
    ROOT / "dashboard",
    ROOT / "inventory",
    ROOT / "playbooks",
    ROOT / "roles",
    ROOT / "tests",
)
MAINTAINED_SUFFIXES = {".py", ".js", ".css", ".html", ".yml", ".j2"}


def maintained_sources() -> list[Path]:
    """Return every maintained text source covered by the note contract."""

    files = [ROOT / "ansible.cfg"]
    for source_root in MAINTAINED_ROOTS:
        files.extend(
            path
            for path in source_root.rglob("*")
            if path.is_file()
            and path.suffix in MAINTAINED_SUFFIXES
            and "__pycache__" not in path.parts
        )
    return sorted(set(files))


class DocumentationContractTests(unittest.TestCase):
    """Require orientation and safe-change guidance beside maintained code."""

    def test_every_maintained_source_has_teacher_and_change_notes(self) -> None:
        missing: list[str] = []

        for path in maintained_sources():
            content = path.read_text(encoding="utf-8")
            relative_path = path.relative_to(ROOT)
            if "TEACHER NOTE" not in content:
                missing.append(f"{relative_path}: missing TEACHER NOTE")
            if "CHANGE INSTRUCTIONS" not in content:
                missing.append(f"{relative_path}: missing CHANGE INSTRUCTIONS")

        self.assertEqual([], missing, "\n".join(missing))

    def test_topology_json_contains_safe_embedded_guidance(self) -> None:
        topology = json.loads(
            (ROOT / "dashboard/assets/dashboard-topology.json").read_text(
                encoding="utf-8",
            ),
        )
        notes = topology.get("_teacher_notes", {})

        self.assertIn("purpose", notes)
        self.assertIn("outputs", notes)
        self.assertGreaterEqual(len(notes.get("change_instructions", [])), 4)
        self.assertNotIn("api_key", json.dumps(topology).lower())

    def test_start_here_guides_and_generated_output_warning_exist(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        teacher_guide = (
            ROOT / "docs/INFRASTRUCTURE-TEACHER-GUIDE.md"
        ).read_text(encoding="utf-8")
        change_protocol = (ROOT / "docs/CHANGE-PROTOCOL.md").read_text(
            encoding="utf-8",
        )
        report_readme = (ROOT / "reports/README.md").read_text(encoding="utf-8")

        self.assertIn("dashboard/server.py", readme)
        self.assertIn("Chapter 18", teacher_guide)
        self.assertIn("Generated files", change_protocol)
        self.assertIn("Do not repair behaviour by editing", report_readme)

    def test_service_example_runs_the_custom_loopback_server(self) -> None:
        service = (
            ROOT / "systemd/hackwell-dashboard.service.example"
        ).read_text(encoding="utf-8")

        self.assertIn("dashboard/server.py", service)
        self.assertIn("--bind 127.0.0.1", service)
        self.assertIn("--reports-dir", service)
        self.assertNotIn("python3 -m http.server", service)


if __name__ == "__main__":
    unittest.main()
