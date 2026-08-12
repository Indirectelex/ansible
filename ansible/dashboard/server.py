#!/usr/bin/env python3
"""Serve the dashboard and run one validated Ansible action at a time."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit


HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PACKAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$")
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1"}
API_STATUS_PATH = "/api/health-check/status"
API_RUN_PREFIX = "/api/health-check/"
API_SECURITY_UPDATE_PREFIX = "/api/security-update/"
REQUEST_HEADER = "X-Health-Dashboard"
MAX_REQUEST_BODY_BYTES = 512
MAINTENANCE_HISTORY_LIMIT = 10
MAINTENANCE_OUTPUT_LINES = 160


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def hostname_from_authority(authority: str) -> str | None:
    """Extract a normalized hostname from an HTTP authority value."""

    try:
        return urlsplit(f"//{authority}").hostname
    except ValueError:
        return None


def trusted_browser_request(host_header: str, origin: str) -> bool:
    """Accept same-origin browser requests addressed only to loopback."""

    request_host = hostname_from_authority(host_header)

    try:
        origin_parts = urlsplit(origin)
    except ValueError:
        return False

    return (
        request_host in LOOPBACK_NAMES
        and origin_parts.scheme == "http"
        and origin_parts.hostname == request_host
        and origin_parts.netloc == host_header
    )


def tail_output(stdout: str, stderr: str, line_count: int = 40) -> list[str]:
    """Return a bounded diagnostic tail for the local status endpoint."""

    combined = [
        line
        for line in f"{stdout}\n{stderr}".splitlines()
        if line.strip()
    ]
    return combined[-line_count:]


def valid_security_confirmation(payload: Any, host: str) -> bool:
    """Require an explicit acknowledgement for the exact target host."""

    return (
        isinstance(payload, dict)
        and payload.get("confirm_host") == host
        and payload.get("install_security_updates") is True
        and payload.get("automatic_reboot") is False
    )


def elapsed_seconds(started_at: str, finished_at: str) -> float | None:
    """Return a non-negative elapsed duration for two ISO timestamps."""

    try:
        started = datetime.fromisoformat(started_at)
        finished = datetime.fromisoformat(finished_at)
    except (TypeError, ValueError):
        return None

    return round(max(0.0, (finished - started).total_seconds()), 1)


class HealthCheckController:
    """Validate hosts and coordinate one background Ansible action."""

    def __init__(
        self,
        ansible_dir: Path,
        reports_dir: Path,
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self.ansible_dir = ansible_dir.resolve()
        self.reports_dir = reports_dir.resolve()
        self.manifest_path = self.reports_dir / "manifest.json"
        self.playbook_path = self.ansible_dir / "playbooks" / "health-check.yml"
        self.security_update_playbook_path = (
            self.ansible_dir / "playbooks" / "security-update.yml"
        )
        self.runner = runner
        self.lock = threading.Lock()
        self.job: dict[str, Any] = {
            "state": "idle",
            "action": None,
            "phase": None,
            "host": None,
            "started_at": None,
            "finished_at": None,
            "return_code": None,
            "message": "No dashboard action has been requested.",
            "output_tail": [],
        }

    def allowed_hosts(self) -> set[str]:
        """Read the monitored host allowlist from the published manifest."""

        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Cannot read dashboard manifest: {error}") from error

        hosts = {
            str(item.get("id", ""))
            for item in manifest.get("hosts", [])
            if isinstance(item, dict)
        }
        return {host for host in hosts if HOST_PATTERN.fullmatch(host)}

    def snapshot(self) -> dict[str, Any]:
        """Return a copy of the current job state."""

        with self.lock:
            return dict(self.job)

    def start(self, host: str) -> tuple[bool, str, dict[str, Any]]:
        """Start one host health check after strict allowlist validation."""

        return self._start(host, "health_check")

    def start_security_update(
        self,
        host: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Start one explicitly requested security update installation."""

        return self._start(host, "security_update")

    def _start(
        self,
        host: str,
        action: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Start one validated action for one manifest host."""

        if not HOST_PATTERN.fullmatch(host):
            return False, "Invalid hostname.", self.snapshot()

        try:
            allowed_hosts = self.allowed_hosts()
        except RuntimeError as error:
            return False, str(error), self.snapshot()

        if host not in allowed_hosts:
            return False, "Host is not present in the dashboard manifest.", self.snapshot()

        approved_packages = (
            self._approved_security_packages(host)
            if action == "security_update"
            else []
        )

        with self.lock:
            if self.job["state"] == "running":
                return False, "Another dashboard action is already running.", dict(self.job)

            action_label = (
                "Security update"
                if action == "security_update"
                else "Health check"
            )

            self.job = {
                "state": "running",
                "action": action,
                "phase": "installing" if action == "security_update" else "checking",
                "host": host,
                "started_at": utc_now(),
                "finished_at": None,
                "return_code": None,
                "message": f"{action_label} running for {host}.",
                "output_tail": [],
                "approved_packages": approved_packages,
            }
            snapshot = dict(self.job)

        thread = threading.Thread(
            target=self._run,
            args=(host, action),
            name=f"{action.replace('_', '-')}-{host}",
            daemon=True,
        )
        thread.start()
        return True, snapshot["message"], snapshot

    def _run(self, host: str, action: str) -> None:
        """Run fixed playbook commands without invoking a shell."""

        health_check_command = [
            "ansible-playbook",
            "playbooks/health-check.yml",
            "--limit",
            host,
        ]
        security_update_command = [
            "ansible-playbook",
            "playbooks/security-update.yml",
            "--limit",
            host,
            "--extra-vars",
            json.dumps(
                {
                    "security_update_dashboard_confirmed": True,
                    "security_update_target_host": host,
                },
            ),
        ]
        commands = (
            [security_update_command, health_check_command]
            if action == "security_update"
            else [health_check_command]
        )
        environment = os.environ.copy()
        environment["ANSIBLE_FORCE_COLOR"] = "0"
        environment["LC_ALL"] = "C.UTF-8"

        initial_job = self.snapshot()
        started_at = str(initial_job["started_at"])
        approved_packages = list(initial_job.get("approved_packages", []))
        outputs: list[str] = []
        phase_records: list[dict[str, Any]] = []
        active_phase: str | None = None
        active_phase_started: str | None = None

        try:
            return_code = 0

            for index, command in enumerate(commands):
                active_phase = (
                    "installation"
                    if action == "security_update" and index == 0
                    else "report_refresh"
                    if action == "security_update"
                    else "health_check"
                )
                active_phase_started = utc_now()

                if action == "security_update" and index == 1:
                    with self.lock:
                        self.job["phase"] = "refreshing_report"
                        self.job["message"] = (
                            f"Security update completed for {host}; "
                            "refreshing its report."
                        )

                result = self.runner(
                    command,
                    cwd=self.ansible_dir,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )
                stdout = str(result.stdout or "")
                stderr = str(result.stderr or "")
                outputs.extend([stdout, stderr])
                return_code = int(result.returncode)
                phase_finished_at = utc_now()
                phase_records.append(
                    {
                        "name": active_phase,
                        "state": "success" if return_code == 0 else "failed",
                        "started_at": active_phase_started,
                        "finished_at": phase_finished_at,
                        "duration_seconds": elapsed_seconds(
                            active_phase_started,
                            phase_finished_at,
                        ),
                        "return_code": return_code,
                        "output_tail": tail_output(
                            stdout,
                            stderr,
                            MAINTENANCE_OUTPUT_LINES,
                        ),
                    },
                )
                active_phase = None
                active_phase_started = None
                if return_code != 0:
                    break

            output_tail = tail_output("\n".join(outputs), "")
            state = "success" if return_code == 0 else "failed"
            if action == "security_update":
                installation_succeeded = (
                    phase_records
                    and phase_records[0]["name"] == "installation"
                    and phase_records[0]["state"] == "success"
                )
                if return_code == 0:
                    message = (
                        f"Security update and report refresh completed for {host}."
                    )
                elif installation_succeeded:
                    message = (
                        f"Security update completed for {host}, but its report "
                        "refresh failed."
                    )
                else:
                    message = f"Security update installation failed for {host}."
            else:
                message = (
                    f"Health check completed for {host}."
                    if return_code == 0
                    else f"Health check failed for {host}."
                )
        except subprocess.TimeoutExpired as error:
            phase_finished_at = utc_now()
            return_code = None
            phase_output = tail_output(
                str(error.stdout or ""),
                str(error.stderr or ""),
                MAINTENANCE_OUTPUT_LINES,
            )
            output_tail = phase_output[-40:]
            if active_phase and active_phase_started:
                phase_records.append(
                    {
                        "name": active_phase,
                        "state": "timed_out",
                        "started_at": active_phase_started,
                        "finished_at": phase_finished_at,
                        "duration_seconds": elapsed_seconds(
                            active_phase_started,
                            phase_finished_at,
                        ),
                        "return_code": None,
                        "output_tail": phase_output,
                    },
                )
            state = "failed"
            message = f"Dashboard action timed out for {host}."
        except OSError as error:
            phase_finished_at = utc_now()
            return_code = None
            output_tail = [str(error)]
            if active_phase and active_phase_started:
                phase_records.append(
                    {
                        "name": active_phase,
                        "state": "could_not_start",
                        "started_at": active_phase_started,
                        "finished_at": phase_finished_at,
                        "duration_seconds": elapsed_seconds(
                            active_phase_started,
                            phase_finished_at,
                        ),
                        "return_code": None,
                        "output_tail": output_tail,
                    },
                )
            state = "failed"
            message = f"Could not start the dashboard action for {host}."

        finished_at = utc_now()
        final_job = {
            "state": state,
            "action": action,
            "phase": None,
            "host": host,
            "started_at": started_at,
            "finished_at": finished_at,
            "return_code": return_code,
            "message": message,
            "output_tail": output_tail,
        }

        if action == "security_update":
            record = {
                "schema_version": 1,
                "action": action,
                "host": host,
                "state": state,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_seconds": elapsed_seconds(started_at, finished_at),
                "return_code": return_code,
                "message": message,
                "approved_packages": approved_packages,
                "approved_package_count": len(approved_packages),
                "automatic_reboot": False,
                "phases": phase_records,
                "final_report": (
                    self._final_report_summary(host)
                    if any(
                        phase["name"] == "report_refresh"
                        and phase["state"] == "success"
                        for phase in phase_records
                    )
                    else None
                ),
            }
            try:
                self._save_maintenance_record(host, record)
                final_job["maintenance_history_saved"] = True
            except OSError as error:
                final_job["maintenance_history_saved"] = False
                final_job["output_tail"] = [
                    *output_tail[-39:],
                    f"Could not save maintenance history: {error}",
                ]

        print(f"[{utc_now()}] {message}", flush=True)
        for line in output_tail:
            print(line, flush=True)

        with self.lock:
            self.job = final_job

    def _approved_security_packages(self, host: str) -> list[str]:
        """Read the package set shown to the operator at confirmation time."""

        try:
            report = json.loads(
                (self.reports_dir / f"{host}.json").read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError):
            return []

        groups = report.get("security_packages", {})
        if not isinstance(groups, dict):
            return []

        packages: set[str] = set()
        for items in groups.values():
            if not isinstance(items, list):
                continue
            for item in items:
                name = item.get("name") if isinstance(item, dict) else None
                if isinstance(name, str) and PACKAGE_PATTERN.fullmatch(name):
                    packages.add(name)
        return sorted(packages)

    def _final_report_summary(self, host: str) -> dict[str, Any] | None:
        """Read the small post-maintenance result needed by the dashboard."""

        try:
            report = json.loads(
                (self.reports_dir / f"{host}.json").read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError):
            return None

        return {
            "generated_at": report.get("generated_at"),
            "health_status": report.get("health_status", report.get("status")),
            "patch_posture_status": report.get("patch_posture_status"),
            "security_updates_available": report.get(
                "security_updates_available",
            ),
            "regular_updates_available": report.get("regular_updates_available"),
            "reboot_required": report.get("reboot_required"),
            "failed_service_count": report.get("failed_service_count"),
        }

    def _save_maintenance_record(
        self,
        host: str,
        record: dict[str, Any],
    ) -> None:
        """Atomically retain the latest bounded maintenance history per host."""

        maintenance_dir = self.reports_dir / "maintenance"
        maintenance_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        history_path = maintenance_dir / f"{host}.json"

        try:
            existing = json.loads(history_path.read_text(encoding="utf-8"))
            existing_runs = existing.get("runs", [])
            if not isinstance(existing_runs, list):
                existing_runs = []
        except (OSError, json.JSONDecodeError):
            existing_runs = []

        runs = [
            record,
            *[
                item
                for item in existing_runs
                if isinstance(item, dict)
                and item.get("started_at") != record["started_at"]
            ],
        ][:MAINTENANCE_HISTORY_LIMIT]
        history = {
            "schema_version": 1,
            "host": host,
            "updated_at": record["finished_at"],
            "latest": record,
            "runs": runs,
        }
        temporary_path = maintenance_dir / f".{host}.json.tmp"
        temporary_path.write_text(
            f"{json.dumps(history, indent=2, sort_keys=True)}\n",
            encoding="utf-8",
        )
        temporary_path.chmod(0o640)
        os.replace(temporary_path, history_path)


class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Serve reports and expose narrowly scoped local action APIs."""

    controller: HealthCheckController

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """Send one no-cache JSON response."""

        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if urlsplit(self.path).path == API_STATUS_PATH:
            self.send_json(HTTPStatus.OK, {"job": self.controller.snapshot()})
            return

        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path

        is_health_check = (
            path.startswith(API_RUN_PREFIX) and path != API_STATUS_PATH
        )
        is_security_update = path.startswith(API_SECURITY_UPDATE_PREFIX)

        if not is_health_check and not is_security_update:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown API endpoint."})
            return

        if not trusted_browser_request(
            self.headers.get("Host", ""),
            self.headers.get("Origin", ""),
        ) or self.headers.get(REQUEST_HEADER) != "1":
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Request rejected."})
            return

        prefix = (
            API_SECURITY_UPDATE_PREFIX
            if is_security_update
            else API_RUN_PREFIX
        )
        host = unquote(path.removeprefix(prefix))

        if is_security_update:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = -1

            if not 0 < content_length <= MAX_REQUEST_BODY_BYTES:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "A bounded confirmation body is required."},
                )
                return

            try:
                payload = json.loads(self.rfile.read(content_length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Invalid confirmation body."},
                )
                return

            if not valid_security_confirmation(payload, host):
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Explicit security-update confirmation is required."},
                )
                return

            started, message, job = self.controller.start_security_update(host)
        else:
            started, message, job = self.controller.start(host)

        if started:
            self.send_json(HTTPStatus.ACCEPTED, {"message": message, "job": job})
            return

        status = (
            HTTPStatus.CONFLICT
            if job.get("state") == "running"
            else HTTPStatus.BAD_REQUEST
        )
        self.send_json(status, {"error": message, "job": job})

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Not allowed."})


def parse_args() -> argparse.Namespace:
    """Parse local dashboard server arguments."""

    ansible_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Serve reports with local-only validated Ansible actions.",
    )
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--ansible-dir", type=Path, default=ansible_dir)
    parser.add_argument("--reports-dir", type=Path)
    args = parser.parse_args()

    if args.bind not in {"127.0.0.1", "localhost"}:
        parser.error("--bind must be 127.0.0.1 or localhost")

    args.ansible_dir = args.ansible_dir.resolve()
    args.reports_dir = (
        args.reports_dir.resolve()
        if args.reports_dir
        else args.ansible_dir / "reports"
    )
    return args


def main() -> None:
    """Start the loopback-only dashboard controller."""

    args = parse_args()

    if not args.reports_dir.is_dir():
        raise SystemExit(f"Reports directory does not exist: {args.reports_dir}")

    playbook = args.ansible_dir / "playbooks" / "health-check.yml"
    if not playbook.is_file():
        raise SystemExit(f"Health-check playbook does not exist: {playbook}")

    security_update_playbook = (
        args.ansible_dir / "playbooks" / "security-update.yml"
    )
    if not security_update_playbook.is_file():
        raise SystemExit(
            "Security-update playbook does not exist: "
            f"{security_update_playbook}",
        )

    if shutil.which("ansible-playbook") is None:
        raise SystemExit("ansible-playbook is not available in PATH")

    controller = HealthCheckController(args.ansible_dir, args.reports_dir)
    DashboardRequestHandler.controller = controller
    handler = partial(DashboardRequestHandler, directory=str(args.reports_dir))

    server = ThreadingHTTPServer((args.bind, args.port), handler)
    server.daemon_threads = True
    print(
        f"Dashboard: http://{args.bind}:{args.port}\n"
        "Dashboard actions are restricted to manifest hosts on loopback.",
        flush=True,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
