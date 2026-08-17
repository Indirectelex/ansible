#!/usr/bin/env python3
"""Serve the complete local dashboard and its bounded control plane.

TEACHER NOTE — CHAPTERS 11, 12, AND 14
=======================================
Purpose
    This process is both the static server for ``reports/`` and the local API
    controller for health checks, security maintenance, and UniFi summaries.
    It is not interchangeable with ``python3 -m http.server``.

Inputs
    Published reports/manifest, fixed Ansible playbooks, optional Prometheus
    metrics, optional authoritative UniFi inventory, and loopback HTTP requests.

Outputs
    Static report files, bounded JSON API responses, one serialized background
    Ansible job, and bounded per-host maintenance history.

Security boundary
    The server binds only to loopback, validates same-origin action requests,
    permits only manifest hosts, runs fixed argv arrays without a shell, and
    requires an exact confirmation body for package installation.

CHANGE INSTRUCTIONS
    When changing a route, query, command, environment variable, response
    field, or trust check, update dashboard.js, the relevant guide chapter,
    and focused server tests in the same change. Re-run the full unit suite and
    verify the manifest, action-status, and UniFi HTTP boundaries.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, unquote, urlsplit
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# CHAPTER 11.1 — Fixed trust and API contracts
# ---------------------------------------------------------------------------
# These constants are deliberately closed allowlists. Browser input may select
# an approved host or action, but it may not select a command, PromQL query,
# upstream URL, or arbitrary package. Expand these contracts only with tests.

HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PACKAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$")
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1"}
API_STATUS_PATH = "/api/health-check/status"
API_UNIFI_SUMMARY_PATH = "/api/unifi/summary"
API_RUN_PREFIX = "/api/health-check/"
API_SECURITY_UPDATE_PREFIX = "/api/security-update/"
REQUEST_HEADER = "X-Health-Dashboard"
MAX_REQUEST_BODY_BYTES = 512
MAINTENANCE_HISTORY_LIMIT = 10
MAINTENANCE_OUTPUT_LINES = 160
PROMETHEUS_TIMEOUT_SECONDS = 4
UNIFI_CONTROLLER_TIMEOUT_SECONDS = 5
UNIFI_METRICS = (
    "unpoller_controller_up",
    "unpoller_controller_update_available",
    "unpoller_controller_unsupported_device_count",
    "unpoller_site_aps",
    "unpoller_site_switches",
    "unpoller_site_gateways",
    "unpoller_site_users",
    "unpoller_site_guests",
    "unpoller_site_iots",
    "unpoller_site_disconnected",
    "unpoller_site_pending",
    "unpoller_site_latency_seconds",
    "unpoller_site_intenet_drops_total",
    "unpoller_site_receive_rate_bytes",
    "unpoller_site_transmit_rate_bytes",
    "unpoller_device_info",
    "unpoller_device_temperature_celsius",
    "unpoller_device_cpu_utilization_ratio",
    "unpoller_device_memory_utilization_ratio",
    "unpoller_device_uptime_seconds",
    "unpoller_device_upgradable",
    "unpoller_device_stations",
    "unpoller_device_radio_channel_utilization_total_ratio",
    "unpoller_client_satisfaction_ratio",
    "unpoller_client_radio_signal_db",
    "unpoller_device_port_poe_watts",
    "unpoller_device_max_power_total",
    "unpoller_wan_uptime_percentage",
    "unpoller_wan_peak_download_percent",
    "unpoller_wan_peak_upload_percent",
)

UNIFI_DERIVED_QUERIES = {
    "wan_errors_24h": (
        'sum(increase(unpoller_device_wan_receive_errors_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_wan_transmit_errors_total{job="unpoller"}[24h]))'
    ),
    "wan_drops_24h": (
        'sum(increase(unpoller_device_wan_receive_dropped_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_wan_transmit_dropped_total{job="unpoller"}[24h]))'
    ),
    "switch_port_errors_24h": (
        'sum(increase(unpoller_device_port_receive_errors_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_errors_total{job="unpoller"}[24h]))'
    ),
    "switch_port_drops_24h": (
        'sum(increase(unpoller_device_port_receive_dropped_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_dropped_total{job="unpoller"}[24h]))'
    ),
    "switch_port_error_ratio": (
        '('
        'sum(increase(unpoller_device_port_receive_errors_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_errors_total{job="unpoller"}[24h]))'
        ') / clamp_min(('
        'sum(increase(unpoller_device_port_receive_packets_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_packets_total{job="unpoller"}[24h]))'
        '), 1)'
    ),
    "switch_port_drop_ratio": (
        '('
        'sum(increase(unpoller_device_port_receive_dropped_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_dropped_total{job="unpoller"}[24h]))'
        ') / clamp_min(('
        'sum(increase(unpoller_device_port_receive_packets_total{job="unpoller"}[24h])) + '
        'sum(increase(unpoller_device_port_transmit_packets_total{job="unpoller"}[24h]))'
        '), 1)'
    ),
    "wifi_retry_ratio": (
        'sum(increase(unpoller_client_transmit_retries_total{job="unpoller"}[24h])) / '
        'clamp_min(sum(increase(unpoller_client_wifi_attempts_transmit_total'
        '{job="unpoller"}[24h])), 1)'
    ),
}

UNIFI_PORT_QUERIES = {
    "errors": (
        'topk(5, '
        'sum by (name, mac, port, port_name) '
        '(increase(unpoller_device_port_receive_errors_total{job="unpoller"}[24h])) + '
        'sum by (name, mac, port, port_name) '
        '(increase(unpoller_device_port_transmit_errors_total{job="unpoller"}[24h]))'
        ')'
    ),
    "drops": (
        'topk(5, '
        'sum by (name, mac, port, port_name) '
        '(increase(unpoller_device_port_receive_dropped_total{job="unpoller"}[24h])) + '
        'sum by (name, mac, port, port_name) '
        '(increase(unpoller_device_port_transmit_dropped_total{job="unpoller"}[24h]))'
        ')'
    ),
}

UNIFI_TREND_QUERIES = {
    "latency_ms": 'avg(unpoller_site_latency_seconds{job="unpoller"}) * 1000',
    "clients": 'sum(unpoller_site_users{job="unpoller"})',
    "receive_rate_bytes": 'sum(unpoller_site_receive_rate_bytes{job="unpoller"})',
    "transmit_rate_bytes": 'sum(unpoller_site_transmit_rate_bytes{job="unpoller"})',
}


# ---------------------------------------------------------------------------
# CHAPTER 11.2 — Small normalization and request-safety helpers
# ---------------------------------------------------------------------------
# Keep validation helpers pure so their edge cases can be tested independently
# of sockets, Ansible, or upstream services.

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


def numeric_value(value: Any) -> float:
    """Return a finite Prometheus sample value or zero."""

    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if number == number and abs(number) != float("inf") else 0.0


# ---------------------------------------------------------------------------
# CHAPTER 12.1 — Authoritative UniFi adopted-device inventory
# ---------------------------------------------------------------------------
# The controller answers "which devices still belong to this site?". Prometheus
# history must never resurrect a forgotten device into the active inventory.

class UnifiControllerClient:
    """Read the authoritative adopted-device roster from UniFi Network."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        site_id: str | None = None,
        verify_tls: bool = True,
        opener: Callable[..., Any] = urlopen,
        timeout: int = UNIFI_CONTROLLER_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.site_id = str(site_id or "").strip() or None
        self.verify_tls = verify_tls
        self.opener = opener
        self.timeout = timeout

    def _request(
        self,
        path: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = f"?{urlencode(parameters)}" if parameters else ""
        request = Request(
            f"{self.base_url}/proxy/network/integration{path}{query}",
            headers={
                "Accept": "application/json",
                "X-API-KEY": self.api_key,
            },
        )
        context = (
            ssl.create_default_context()
            if self.verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001 - explicit local option
        )

        try:
            with self.opener(
                request,
                timeout=self.timeout,
                context=context,
            ) as response:
                payload = json.load(response)
        except (HTTPError, URLError, OSError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(f"UniFi controller query failed: {error}") from error

        if not isinstance(payload, dict):
            raise RuntimeError("UniFi controller returned an invalid response")
        return payload

    @staticmethod
    def _page_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Accept the documented page and compatible nested page shapes."""

        candidates: list[Any] = [
            payload.get("data"),
            payload.get("items"),
            payload.get("results"),
        ]
        if isinstance(payload.get("data"), dict):
            data = payload["data"]
            candidates.extend(
                [data.get("data"), data.get("items"), data.get("results")],
            )
        for candidate in candidates:
            if isinstance(candidate, list):
                return [item for item in candidate if isinstance(item, dict)]
        raise RuntimeError("UniFi controller returned an invalid paginated response")

    @staticmethod
    def _page_total(payload: dict[str, Any]) -> int | None:
        containers = [payload]
        if isinstance(payload.get("data"), dict):
            containers.append(payload["data"])
        for container in containers:
            for key in ("totalCount", "total_count", "total"):
                value = container.get(key)
                if isinstance(value, int) and value >= 0:
                    return value
        return None

    def _all_pages(self, path: str, limit: int = 200) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._request(
                path,
                {"offset": offset, "limit": limit},
            )
            page = self._page_items(payload)
            items.extend(page)
            total = self._page_total(payload)
            if not page or len(page) < limit or (
                total is not None and len(items) >= total
            ):
                return items
            offset += len(page)

    def _resolved_site_id(self) -> str:
        if self.site_id:
            return self.site_id

        sites = self._all_pages("/v1/sites")
        if len(sites) != 1:
            raise RuntimeError(
                "UniFi site selection is ambiguous; set DASHBOARD_UNIFI_SITE_ID",
            )
        site_id = str(sites[0].get("id") or sites[0].get("siteId") or "").strip()
        if not site_id:
            raise RuntimeError("UniFi controller did not return a site ID")
        return site_id

    @staticmethod
    def _normalized_device(device: dict[str, Any]) -> dict[str, Any]:
        field_map = {
            "id": ("id", "deviceId"),
            "ip": ("ipAddress", "ip"),
            "mac": ("macAddress", "mac"),
            "model": ("model",),
            "name": ("name",),
            "serial": ("serial", "serialNumber"),
            "type": ("type", "deviceType", "productLine"),
            "version": ("firmwareVersion", "version"),
        }
        normalized: dict[str, Any] = {}
        for destination, sources in field_map.items():
            for source in sources:
                value = device.get(source)
                if value not in (None, ""):
                    normalized[destination] = value
                    break
        state = str(device.get("state") or "UNKNOWN").upper()
        normalized["controller_state"] = state
        normalized["reported_online"] = (
            True if state == "ONLINE" else False if state == "OFFLINE" else None
        )
        normalized["inventory_source"] = "unifi_controller"
        return normalized

    def devices(self) -> list[dict[str, Any]]:
        """Return every device that is currently adopted on the selected site."""

        site_id = self._resolved_site_id()
        path = f"/v1/sites/{site_id}/devices"
        return [self._normalized_device(item) for item in self._all_pages(path)]


# ---------------------------------------------------------------------------
# CHAPTER 12.2 — Bounded metrics, trends, and derived network health
# ---------------------------------------------------------------------------
# Only fixed expressions defined above reach Prometheus. This class normalizes
# exporter labels, merges optional controller identity, derives health/finding
# states, and returns a browser-safe summary rather than raw time-series data.

class UnifiPrometheusClient:
    """Read a fixed, bounded UniFi snapshot from Prometheus."""

    def __init__(
        self,
        base_url: str,
        opener: Callable[..., Any] = urlopen,
        timeout: int = PROMETHEUS_TIMEOUT_SECONDS,
        expected_offline_devices: list[str] | tuple[str, ...] | None = None,
        controller_client: UnifiControllerClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.opener = opener
        self.timeout = timeout
        self.expected_offline_devices = {
            str(name).strip()
            for name in (expected_offline_devices or [])
            if str(name).strip()
        }
        self.controller_client = controller_client

    def _request(self, path: str, parameters: dict[str, Any]) -> dict[str, Any]:
        request_url = f"{self.base_url}{path}?{urlencode(parameters)}"
        request = Request(
            request_url,
            headers={"Accept": "application/json"},
        )

        try:
            with self.opener(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except (HTTPError, URLError, OSError, TimeoutError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Prometheus query failed: {error}") from error

        if payload.get("status") != "success":
            raise RuntimeError("Prometheus returned an unsuccessful query response")
        return payload

    def _samples(self) -> list[dict[str, Any]]:
        metric_pattern = "|".join(re.escape(name) for name in UNIFI_METRICS)
        expression = (
            '{job="unpoller",__name__=~"'
            f"({metric_pattern})"
            '"}'
        )
        payload = self._request("/api/v1/query", {"query": expression})
        results = payload.get("data", {}).get("result", [])
        if not isinstance(results, list):
            raise RuntimeError("Prometheus returned an invalid result set")
        return [item for item in results if isinstance(item, dict)]

    def _instant_value(self, expression: str) -> float | None:
        payload = self._request("/api/v1/query", {"query": expression})
        results = payload.get("data", {}).get("result", [])
        if not isinstance(results, list) or not results:
            return None
        values = [
            numeric_value(item.get("value", [None, 0])[1])
            for item in results
            if isinstance(item, dict)
        ]
        return sum(values) if values else None

    def _instant_samples(self, expression: str) -> list[dict[str, Any]]:
        payload = self._request("/api/v1/query", {"query": expression})
        results = payload.get("data", {}).get("result", [])
        if not isinstance(results, list):
            raise RuntimeError("Prometheus returned an invalid instant result set")
        return [item for item in results if isinstance(item, dict)]

    def _trend_values(
        self,
        expression: str,
        end_timestamp: float,
        hours: int = 24,
        step_seconds: int = 900,
    ) -> list[list[float]]:
        payload = self._request(
            "/api/v1/query_range",
            {
                "query": expression,
                "start": int(end_timestamp - (hours * 3600)),
                "end": int(end_timestamp),
                "step": step_seconds,
            },
        )
        results = payload.get("data", {}).get("result", [])
        if not isinstance(results, list) or not results:
            return []
        points = results[0].get("values", [])
        return [
            [numeric_value(point[0]), numeric_value(point[1])]
            for point in points
            if isinstance(point, list) and len(point) >= 2
        ]

    def _optional_instant_value(self, expression: str) -> float | None:
        try:
            return self._instant_value(expression)
        except RuntimeError:
            return None

    def _optional_instant_samples(
        self,
        expression: str,
    ) -> list[dict[str, Any]]:
        try:
            return self._instant_samples(expression)
        except RuntimeError:
            return []

    def _optional_trend_values(
        self,
        expression: str,
        end_timestamp: float,
    ) -> list[list[float]]:
        try:
            return self._trend_values(expression, end_timestamp)
        except RuntimeError:
            return []

    def _recent_device_samples(
        self,
        end_timestamp: float,
        days: int = 7,
        step_seconds: int = 900,
    ) -> list[dict[str, Any]]:
        """Return device metadata and its most recent sample in a bounded window."""

        payload = self._request(
            "/api/v1/query_range",
            {
                "query": 'unpoller_device_info{job="unpoller"}',
                "start": int(end_timestamp - (days * 86400)),
                "end": int(end_timestamp),
                "step": step_seconds,
            },
        )
        results = payload.get("data", {}).get("result", [])
        if not isinstance(results, list):
            raise RuntimeError("Prometheus returned an invalid device history")

        recent_devices: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            labels = item.get("metric", {})
            points = item.get("values", [])
            if not isinstance(labels, dict) or not isinstance(points, list) or not points:
                continue
            last_point = points[-1]
            if not isinstance(last_point, list) or len(last_point) < 2:
                continue
            recent_devices.append(
                {
                    "metric": labels,
                    "last_seen_timestamp": numeric_value(last_point[0]),
                },
            )
        return recent_devices

    def _optional_recent_device_samples(
        self,
        end_timestamp: float,
    ) -> list[dict[str, Any]]:
        try:
            return self._recent_device_samples(end_timestamp)
        except RuntimeError:
            return []

    def _controller_inventory(
        self,
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        if self.controller_client is None:
            return None, "Direct UniFi device inventory is not configured."
        try:
            return self.controller_client.devices(), None
        except RuntimeError as error:
            return None, str(error)

    def summary(self) -> dict[str, Any]:
        """Build the small live model consumed by the dashboard."""

        samples = self._samples()
        grouped: dict[str, list[dict[str, Any]]] = {}
        latest_timestamp = 0.0

        for sample in samples:
            metric = sample.get("metric", {})
            name = str(metric.get("__name__", ""))
            if name not in UNIFI_METRICS:
                continue
            grouped.setdefault(name, []).append(sample)
            value = sample.get("value", [])
            if isinstance(value, list) and value:
                latest_timestamp = max(latest_timestamp, numeric_value(value[0]))

        def values(name: str) -> list[float]:
            return [
                numeric_value(item.get("value", [None, 0])[1])
                for item in grouped.get(name, [])
            ]

        def total(name: str) -> float:
            return sum(values(name))

        def average(name: str) -> float | None:
            metric_values = values(name)
            return sum(metric_values) / len(metric_values) if metric_values else None

        def maximum(name: str) -> float | None:
            metric_values = values(name)
            return max(metric_values) if metric_values else None

        def percentage(value: float | None) -> float | None:
            if value is None:
                return None
            return round(value * 100 if abs(value) <= 1 else value, 1)

        def ratio_percentage(value: float | None) -> float | None:
            if value is None:
                return None
            return round(value * 100, 3)

        trend_end = latest_timestamp or datetime.now(timezone.utc).timestamp()
        with ThreadPoolExecutor(max_workers=7) as executor:
            derived_futures = {
                key: executor.submit(self._optional_instant_value, expression)
                for key, expression in UNIFI_DERIVED_QUERIES.items()
            }
            trend_futures = {
                key: executor.submit(
                    self._optional_trend_values,
                    expression,
                    trend_end,
                )
                for key, expression in UNIFI_TREND_QUERIES.items()
            }
            port_futures = {
                key: executor.submit(
                    self._optional_instant_samples,
                    expression,
                )
                for key, expression in UNIFI_PORT_QUERIES.items()
            }
            recent_devices_future = executor.submit(
                self._optional_recent_device_samples,
                trend_end,
            )
            controller_inventory_future = executor.submit(
                self._controller_inventory,
            )

            derived = {
                key: future.result() for key, future in derived_futures.items()
            }
            trends = {
                key: future.result() for key, future in trend_futures.items()
            }
            port_samples = {
                key: future.result() for key, future in port_futures.items()
            }
            recent_device_samples = recent_devices_future.result()
            controller_devices, controller_inventory_error = (
                controller_inventory_future.result()
            )

        controller_values = values("unpoller_controller_up")
        controller_up = bool(controller_values and max(controller_values) >= 1)

        subsystem_metrics = {
            "unpoller_site_aps": "access_points",
            "unpoller_site_switches": "switches",
            "unpoller_site_gateways": "gateways",
            "unpoller_site_users": "clients",
            "unpoller_site_guests": "guests",
            "unpoller_site_iots": "iot_clients",
            "unpoller_site_disconnected": "disconnected",
            "unpoller_site_pending": "pending",
        }
        subsystem_status_rank = {"error": 0, "unknown": 1, "warning": 2, "ok": 3}
        subsystems: dict[str, dict[str, Any]] = {}

        for metric_name, field_name in subsystem_metrics.items():
            for sample in grouped.get(metric_name, []):
                labels = sample.get("metric", {})
                subsystem = str(labels.get("subsystem", "other"))
                reported_status = str(labels.get("status", "unknown")).lower()
                current = subsystems.setdefault(
                    subsystem,
                    {"name": subsystem, "status": reported_status},
                )
                if subsystem_status_rank.get(reported_status, 1) < subsystem_status_rank.get(
                    str(current.get("status", "unknown")),
                    1,
                ):
                    current["status"] = reported_status
                current[field_name] = numeric_value(sample.get("value", [None, 0])[1])

        device_metric_fields = {
            "unpoller_device_temperature_celsius": "temperature_c",
            "unpoller_device_cpu_utilization_ratio": "cpu_ratio",
            "unpoller_device_memory_utilization_ratio": "memory_ratio",
            "unpoller_device_uptime_seconds": "uptime_seconds",
            "unpoller_device_upgradable": "upgradable",
            "unpoller_device_stations": "stations",
        }
        devices: dict[str, dict[str, Any]] = {}
        device_aliases: dict[str, str] = {}
        currently_reported_devices: set[str] = set()

        def normalized_alias(value: Any) -> str:
            return str(value or "").strip().casefold()

        def device_key(labels: dict[str, Any]) -> str:
            return str(labels.get("mac") or labels.get("id") or labels.get("name") or "")

        def remember_device_aliases(key: str, labels: dict[str, Any]) -> None:
            for field in ("mac", "id", "name", "serial"):
                value = str(labels.get(field, "")).strip()
                if value:
                    device_aliases[normalized_alias(value)] = key

        for sample in grouped.get("unpoller_device_info", []):
            labels = sample.get("metric", {})
            key = device_key(labels)
            if not key:
                continue
            devices[key] = {
                field: labels.get(field)
                for field in ("id", "ip", "mac", "model", "name", "serial", "type", "version")
                if labels.get(field) is not None
            }
            devices[key]["_last_seen_timestamp"] = trend_end
            remember_device_aliases(key, labels)
            currently_reported_devices.add(key)

        for sample in recent_device_samples:
            labels = sample.get("metric", {})
            raw_key = device_key(labels)
            key = device_aliases.get(normalized_alias(raw_key), raw_key)
            if not key:
                continue
            device = devices.setdefault(
                key,
                {
                    field: labels.get(field)
                    for field in (
                        "id",
                        "ip",
                        "mac",
                        "model",
                        "name",
                        "serial",
                        "type",
                        "version",
                    )
                    if labels.get(field) is not None
                },
            )
            last_seen_timestamp = numeric_value(sample.get("last_seen_timestamp"))
            if last_seen_timestamp > numeric_value(
                device.get("_last_seen_timestamp"),
            ):
                device["_last_seen_timestamp"] = last_seen_timestamp
                if key not in currently_reported_devices:
                    for field in (
                        "id",
                        "ip",
                        "mac",
                        "model",
                        "name",
                        "serial",
                        "type",
                        "version",
                    ):
                        if labels.get(field) is not None:
                            device[field] = labels[field]
            remember_device_aliases(key, labels)

        for metric_name, field_name in device_metric_fields.items():
            for sample in grouped.get(metric_name, []):
                labels = sample.get("metric", {})
                raw_key = device_key(labels)
                key = device_aliases.get(normalized_alias(raw_key), raw_key)
                if not key:
                    continue
                device = devices.setdefault(
                    key,
                    {
                        field: labels.get(field)
                        for field in ("id", "ip", "mac", "model", "name", "type", "version")
                        if labels.get(field) is not None
                    },
                )
                device[field_name] = numeric_value(sample.get("value", [None, 0])[1])
                remember_device_aliases(key, labels)
                currently_reported_devices.add(key)
                device["_last_seen_timestamp"] = max(
                    trend_end,
                    numeric_value(device.get("_last_seen_timestamp")),
                )

        for key, device in devices.items():
            last_seen_timestamp = numeric_value(
                device.pop("_last_seen_timestamp", None),
            )
            if last_seen_timestamp:
                device["last_seen_at"] = datetime.fromtimestamp(
                    last_seen_timestamp,
                    timezone.utc,
                ).isoformat()
            if "uptime_seconds" in device:
                device["reported_online"] = device["uptime_seconds"] > 0
            elif key not in currently_reported_devices:
                device["reported_online"] = False
            device["currently_reported"] = key in currently_reported_devices

        disconnected = int(total("unpoller_site_disconnected"))
        pending = int(total("unpoller_site_pending"))
        unsupported = int(total("unpoller_controller_unsupported_device_count"))
        latency_values = values("unpoller_site_latency_seconds")
        latency_ms = round(max(latency_values) * 1000, 1) if latency_values else None

        channel_utilization_pct = percentage(
            maximum("unpoller_device_radio_channel_utilization_total_ratio"),
        )
        wifi_satisfaction_pct = percentage(
            average("unpoller_client_satisfaction_ratio"),
        )
        weak_signal_clients = sum(
            value < -75 for value in values("unpoller_client_radio_signal_db")
        )
        wifi_retry_ratio_pct = percentage(derived["wifi_retry_ratio"])
        wan_uptime_pct = percentage(maximum("unpoller_wan_uptime_percentage"))
        wan_download_utilization_pct = percentage(
            maximum("unpoller_wan_peak_download_percent"),
        )
        wan_upload_utilization_pct = percentage(
            maximum("unpoller_wan_peak_upload_percent"),
        )
        poe_watts = total("unpoller_device_port_poe_watts")
        poe_capacity_watts = total("unpoller_device_max_power_total")
        port_error_ratio_pct = ratio_percentage(
            derived["switch_port_error_ratio"],
        )
        port_drop_ratio_pct = ratio_percentage(
            derived["switch_port_drop_ratio"],
        )

        def port_hotspots(metric_samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
            hotspots: list[dict[str, Any]] = []
            for sample in metric_samples:
                count = numeric_value(sample.get("value", [None, 0])[1])
                if count <= 0:
                    continue
                labels = sample.get("metric", {})
                device_name = str(
                    labels.get("name")
                    or labels.get("device_name")
                    or labels.get("mac")
                    or "Unknown switch"
                )
                port_name = str(
                    labels.get("port_name")
                    or labels.get("port")
                    or labels.get("port_idx")
                    or labels.get("port_number")
                    or "Unknown port"
                )
                hotspots.append(
                    {
                        "device": device_name,
                        "port": port_name,
                        "count": round(count),
                    },
                )
            return sorted(
                hotspots,
                key=lambda item: item["count"],
                reverse=True,
            )[:5]

        port_error_hotspots = port_hotspots(port_samples["errors"])
        port_drop_hotspots = port_hotspots(port_samples["drops"])

        inventory_authoritative = controller_devices is not None
        active_devices: list[dict[str, Any]] = []

        if controller_devices is not None:
            for controller_device in controller_devices:
                metric_key = ""
                for field in ("mac", "id", "serial", "name"):
                    alias = normalized_alias(controller_device.get(field))
                    if alias and alias in device_aliases:
                        metric_key = device_aliases[alias]
                        break
                metric_device = devices.get(metric_key, {})
                merged_device = {
                    **metric_device,
                    **{
                        key: value
                        for key, value in controller_device.items()
                        if value not in (None, "")
                    },
                }
                merged_device["reported_online"] = controller_device.get(
                    "reported_online",
                )
                merged_device["expected_offline"] = (
                    str(merged_device.get("name", ""))
                    in self.expected_offline_devices
                )
                active_devices.append(merged_device)
        else:
            for key in currently_reported_devices:
                device = devices.get(key)
                if not device:
                    continue
                fallback_device = dict(device)
                fallback_device["inventory_source"] = "unpoller_current"
                fallback_device["expected_offline"] = (
                    str(fallback_device.get("name", ""))
                    in self.expected_offline_devices
                )
                active_devices.append(fallback_device)

        offline_devices = [
            device
            for device in active_devices
            if device.get("reported_online") is False
        ]
        expected_offline = [
            device for device in offline_devices if device.get("expected_offline")
        ]
        unexpected_offline = [
            device for device in offline_devices if not device.get("expected_offline")
        ]
        core_offline = [
            device
            for device in unexpected_offline
            if str(device.get("model", "")).upper() != "UP1"
        ]
        auxiliary_offline = [
            device
            for device in unexpected_offline
            if str(device.get("model", "")).upper() == "UP1"
        ]
        online_devices = sum(
            device.get("reported_online") is True for device in active_devices
        )
        update_devices = [
            device for device in active_devices if numeric_value(device.get("upgradable")) > 0
        ]

        severity_rank = {"CRITICAL": 0, "WARNING": 1, "WATCH": 2, "OK": 3}

        def worse(left: str, right: str) -> str:
            return left if severity_rank[left] <= severity_rank[right] else right

        findings: list[dict[str, str]] = []
        health = {
            "wan": "OK",
            "wifi": "OK",
            "switching": "OK",
            "devices": "OK",
        }

        def finding(
            area: str,
            severity: str,
            title: str,
            detail: str,
        ) -> None:
            health[area] = worse(health[area], severity)
            findings.append(
                {
                    "area": area,
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                },
            )

        if not controller_up:
            finding(
                "devices",
                "CRITICAL",
                "UniFi controller unavailable",
                "Unpoller is not reporting the controller as online.",
            )
        if controller_inventory_error:
            finding(
                "devices",
                "WATCH",
                "Direct UniFi inventory unavailable",
                controller_inventory_error,
            )
        if core_offline:
            names = ", ".join(str(device.get("name")) for device in core_offline)
            finding(
                "devices",
                "WARNING",
                f"{len(core_offline)} network device(s) offline",
                names,
            )
        if auxiliary_offline:
            names = ", ".join(str(device.get("name")) for device in auxiliary_offline)
            finding(
                "devices",
                "WATCH",
                f"{len(auxiliary_offline)} auxiliary device(s) offline",
                names,
            )
        if pending:
            finding(
                "devices",
                "WATCH",
                "Device adoption pending",
                f"{pending} device(s) are waiting for adoption.",
            )
        if unsupported:
            finding(
                "devices",
                "WATCH",
                "Unsupported UniFi devices",
                f"The controller reports {unsupported} unsupported device(s).",
            )
        if bool(total("unpoller_controller_update_available")) or update_devices:
            finding(
                "devices",
                "WATCH",
                "UniFi update available",
                "Review controller and device firmware updates.",
            )

        hottest = max(
            (numeric_value(device.get("temperature_c")) for device in active_devices),
            default=0,
        )
        busiest_cpu = max(
            (numeric_value(device.get("cpu_ratio")) for device in active_devices),
            default=0,
        )
        busiest_memory = max(
            (numeric_value(device.get("memory_ratio")) for device in active_devices),
            default=0,
        )
        if hottest >= 70 or busiest_cpu >= 0.9 or busiest_memory >= 0.9:
            finding(
                "devices",
                "WARNING",
                "High UniFi device resource usage",
                "At least one device crossed a temperature, CPU, or memory threshold.",
            )
        elif hottest >= 60 or busiest_cpu >= 0.8 or busiest_memory >= 0.8:
            finding(
                "devices",
                "WATCH",
                "Elevated UniFi device resource usage",
                "At least one device is approaching a resource threshold.",
            )

        wan_errors = derived["wan_errors_24h"]
        wan_drops = derived["wan_drops_24h"]
        if latency_ms is not None and latency_ms >= 100:
            finding("wan", "WARNING", "High WAN latency", f"Current latency is {latency_ms} ms.")
        elif latency_ms is not None and latency_ms >= 50:
            finding("wan", "WATCH", "Elevated WAN latency", f"Current latency is {latency_ms} ms.")
        if wan_errors is not None and wan_errors > 0:
            severity = "WARNING" if wan_errors >= 10 else "WATCH"
            finding("wan", severity, "WAN interface errors", f"{wan_errors:.0f} in the last 24 hours.")
        if wan_drops is not None and wan_drops > 0:
            severity = "WARNING" if wan_drops >= 10 else "WATCH"
            finding("wan", severity, "WAN packet drops", f"{wan_drops:.0f} in the last 24 hours.")
        if wan_uptime_pct is not None and wan_uptime_pct < 99.0:
            finding("wan", "WARNING", "Reduced WAN uptime", f"Reported uptime is {wan_uptime_pct}%.")

        if channel_utilization_pct is not None and channel_utilization_pct >= 80:
            finding("wifi", "WARNING", "High Wi-Fi channel utilization", f"Peak radio utilization is {channel_utilization_pct}%.")
        elif channel_utilization_pct is not None and channel_utilization_pct >= 60:
            finding("wifi", "WATCH", "Elevated Wi-Fi channel utilization", f"Peak radio utilization is {channel_utilization_pct}%.")
        if wifi_satisfaction_pct is not None and wifi_satisfaction_pct < 70:
            finding("wifi", "WARNING", "Low Wi-Fi satisfaction", f"Average client satisfaction is {wifi_satisfaction_pct}%.")
        elif wifi_satisfaction_pct is not None and wifi_satisfaction_pct < 85:
            finding("wifi", "WATCH", "Reduced Wi-Fi satisfaction", f"Average client satisfaction is {wifi_satisfaction_pct}%.")
        if wifi_retry_ratio_pct is not None and wifi_retry_ratio_pct >= 20:
            finding("wifi", "WARNING", "High Wi-Fi retry rate", f"24-hour retry ratio is {wifi_retry_ratio_pct}%.")
        elif wifi_retry_ratio_pct is not None and wifi_retry_ratio_pct >= 10:
            finding("wifi", "WATCH", "Elevated Wi-Fi retry rate", f"24-hour retry ratio is {wifi_retry_ratio_pct}%.")
        if weak_signal_clients:
            finding(
                "wifi",
                "WATCH",
                "Weak-signal Wi-Fi clients",
                f"{weak_signal_clients} client(s) are below -75 dBm.",
            )

        port_errors = derived["switch_port_errors_24h"]
        port_drops = derived["switch_port_drops_24h"]

        def port_detail(
            total_count: float,
            ratio_pct: float | None,
            hotspots: list[dict[str, Any]],
        ) -> str:
            detail_parts = [f"{total_count:.0f} in the last 24 hours"]
            if ratio_pct is not None:
                detail_parts[0] += f" ({ratio_pct}% of port traffic)"
            if hotspots:
                sources = ", ".join(
                    f'{item["device"]} port {item["port"]} ({item["count"]})'
                    for item in hotspots[:3]
                )
                detail_parts.append(f"Top source: {sources}")
            return ". ".join(detail_parts) + "."

        def port_severity(
            total_count: float | None,
            ratio_pct: float | None,
            warning_ratio: float,
            watch_ratio: float,
            watch_count: int,
        ) -> str | None:
            if total_count is None or total_count <= 0:
                return None
            if ratio_pct is not None and ratio_pct >= warning_ratio:
                return "WARNING"
            if ratio_pct is not None and ratio_pct >= watch_ratio:
                return "WATCH"
            if total_count >= watch_count:
                return "WATCH"
            return None

        error_severity = port_severity(
            port_errors,
            port_error_ratio_pct,
            warning_ratio=1.0,
            watch_ratio=0.1,
            watch_count=100,
        )
        if error_severity:
            finding(
                "switching",
                error_severity,
                "Switch-port errors",
                port_detail(
                    port_errors or 0,
                    port_error_ratio_pct,
                    port_error_hotspots,
                ),
            )

        drop_severity = port_severity(
            port_drops,
            port_drop_ratio_pct,
            warning_ratio=2.0,
            watch_ratio=0.5,
            watch_count=1000,
        )
        if drop_severity:
            finding(
                "switching",
                drop_severity,
                "Switch-port drops",
                port_detail(
                    port_drops or 0,
                    port_drop_ratio_pct,
                    port_drop_hotspots,
                ),
            )

        findings.sort(key=lambda item: severity_rank[item["severity"]])
        status = "OK"
        for area_status in health.values():
            status = worse(status, area_status)
        message = (
            findings[0]["title"]
            if findings
            else "Controller, WAN, Wi-Fi, switching, and devices are within policy."
        )

        return {
            "integration": "unifi",
            "available": bool(samples),
            "name": "UniFi Network",
            "status": status if samples else "UNKNOWN",
            "message": message if samples else "No current UniFi samples were returned.",
            "collected_at": (
                datetime.fromtimestamp(latest_timestamp, timezone.utc).isoformat()
                if latest_timestamp
                else utc_now()
            ),
            "summary": {
                "controller_up": controller_up,
                "access_points": int(total("unpoller_site_aps")),
                "switches": int(total("unpoller_site_switches")),
                "gateways": int(total("unpoller_site_gateways")),
                "clients": int(total("unpoller_site_users")),
                "guests": int(total("unpoller_site_guests")),
                "iot_clients": int(total("unpoller_site_iots")),
                "disconnected": disconnected,
                "online_devices": online_devices,
                "total_devices": len(active_devices),
                "inventory_source": (
                    "unifi_controller"
                    if inventory_authoritative
                    else "unpoller_current"
                ),
                "inventory_authoritative": inventory_authoritative,
                "inventory_error": controller_inventory_error,
                "unexpected_offline": len(unexpected_offline),
                "expected_offline": len(expected_offline),
                "pending": pending,
                "latency_ms": latency_ms,
                "internet_drops_total": int(total("unpoller_site_intenet_drops_total")),
                "receive_rate_bytes": total("unpoller_site_receive_rate_bytes"),
                "transmit_rate_bytes": total("unpoller_site_transmit_rate_bytes"),
                "update_available": bool(total("unpoller_controller_update_available")),
            },
            "health": {
                "wan": {
                    "status": health["wan"],
                    "latency_ms": latency_ms,
                    "errors_24h": wan_errors,
                    "drops_24h": wan_drops,
                    "uptime_pct": wan_uptime_pct,
                    "download_utilization_pct": wan_download_utilization_pct,
                    "upload_utilization_pct": wan_upload_utilization_pct,
                },
                "wifi": {
                    "status": health["wifi"],
                    "channel_utilization_pct": channel_utilization_pct,
                    "satisfaction_pct": wifi_satisfaction_pct,
                    "retry_ratio_pct": wifi_retry_ratio_pct,
                    "weak_signal_clients": weak_signal_clients,
                },
                "switching": {
                    "status": health["switching"],
                    "port_errors_24h": port_errors,
                    "port_drops_24h": port_drops,
                    "port_error_ratio_pct": port_error_ratio_pct,
                    "port_drop_ratio_pct": port_drop_ratio_pct,
                    "error_hotspots": port_error_hotspots,
                    "drop_hotspots": port_drop_hotspots,
                    "poe_watts": round(poe_watts, 1),
                    "poe_capacity_watts": round(poe_capacity_watts, 1),
                },
                "devices": {
                    "status": health["devices"],
                    "online": online_devices,
                    "total": len(active_devices),
                    "unexpected_offline": len(unexpected_offline),
                    "expected_offline": len(expected_offline),
                    "updates": len(update_devices),
                    "hottest_c": hottest or None,
                    "max_cpu_pct": round(busiest_cpu * 100, 1),
                    "max_memory_pct": round(busiest_memory * 100, 1),
                },
            },
            "findings": findings,
            "trends": trends,
            "subsystems": sorted(subsystems.values(), key=lambda item: item["name"]),
            "devices": sorted(
                active_devices,
                key=lambda item: (str(item.get("type", "")), str(item.get("name", ""))),
            ),
        }


# ---------------------------------------------------------------------------
# CHAPTER 12.3 — Non-secret integration configuration
# ---------------------------------------------------------------------------
# dashboard-topology.json may be served to the browser, so it may contain URLs
# and display policy but never the UniFi API key. The key comes from process
# environment during main().

def configured_unifi_settings(ansible_dir: Path) -> dict[str, Any]:
    """Read the optional, validated UniFi settings from dashboard topology."""

    topology_path = ansible_dir / "dashboard" / "assets" / "dashboard-topology.json"
    try:
        topology = json.loads(topology_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    unifi = topology.get("integrations", {}).get("unifi", {})
    if not isinstance(unifi, dict) or unifi.get("enabled") is not True:
        return {}

    url = str(unifi.get("prometheus_url", "")).rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {}

    controller_url = str(unifi.get("controller_url", "")).rstrip("/")
    controller_parsed = urlsplit(controller_url)
    if (
        controller_parsed.scheme != "https"
        or not controller_parsed.hostname
    ):
        controller_url = ""

    controller_verify_tls = unifi.get("controller_verify_tls", True)
    if not isinstance(controller_verify_tls, bool):
        controller_verify_tls = True

    controller_site_id = str(unifi.get("controller_site_id", "")).strip()

    def configured_name_list(key: str) -> list[str]:
        raw_names = unifi.get(key, [])
        return (
            [
                str(name).strip()
                for name in raw_names
                if isinstance(name, str) and name.strip()
            ]
            if isinstance(raw_names, list)
            else []
        )

    expected_offline_devices = configured_name_list(
        "expected_offline_devices",
    )
    return {
        "prometheus_url": url,
        "controller_url": controller_url,
        "controller_verify_tls": controller_verify_tls,
        "controller_site_id": controller_site_id,
        "expected_offline_devices": expected_offline_devices,
    }


def configured_prometheus_url(ansible_dir: Path) -> str | None:
    """Return the configured UniFi Prometheus URL, when enabled."""

    return configured_unifi_settings(ansible_dir).get("prometheus_url")


# ---------------------------------------------------------------------------
# CHAPTER 14 — Serialized and validated Ansible actions
# ---------------------------------------------------------------------------
# The manifest is both display inventory and the action allowlist. One lock
# protects the single in-memory job. Commands are fixed argv arrays and every
# security update is followed by a report refresh when installation succeeds.

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


# ---------------------------------------------------------------------------
# CHAPTER 11.3 — HTTP boundary: static files plus narrow JSON routes
# ---------------------------------------------------------------------------
# GET routes may expose published data/status. POST routes cross a mutation
# boundary and therefore require loopback same-origin validation plus a custom
# header; security updates add a bounded exact-host confirmation body.

class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Serve reports and expose narrowly scoped local action APIs."""

    controller: HealthCheckController
    unifi_client: UnifiPrometheusClient | None = None

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
        path = urlsplit(self.path).path
        if path == API_STATUS_PATH:
            self.send_json(HTTPStatus.OK, {"job": self.controller.snapshot()})
            return

        if path == API_UNIFI_SUMMARY_PATH:
            if self.unifi_client is None:
                self.send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "UniFi integration is not configured."},
                )
                return
            try:
                summary = self.unifi_client.summary()
            except RuntimeError as error:
                self.send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        "integration": "unifi",
                        "available": False,
                        "name": "UniFi Network",
                        "status": "UNKNOWN",
                        "message": str(error),
                    },
                )
                return
            self.send_json(HTTPStatus.OK, summary)
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


# ---------------------------------------------------------------------------
# CHAPTER 15 — Startup, dependency validation, and server wiring
# ---------------------------------------------------------------------------
# Startup fails loudly when the report root, required playbooks, or Ansible
# executable is missing. The static handler is rooted at reports/, while source
# and playbook paths remain rooted at the Ansible repository.

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
    parser.add_argument(
        "--prometheus-url",
        default=os.environ.get("DASHBOARD_PROMETHEUS_URL"),
        help=(
            "Prometheus base URL for the optional UniFi integration. "
            "Defaults to dashboard-topology.json when enabled."
        ),
    )
    parser.add_argument(
        "--unifi-controller-url",
        default=os.environ.get("DASHBOARD_UNIFI_CONTROLLER_URL"),
        help=(
            "Local UniFi console URL for authoritative adopted-device state. "
            "Defaults to dashboard-topology.json when enabled."
        ),
    )
    parser.add_argument(
        "--unifi-site-id",
        default=os.environ.get("DASHBOARD_UNIFI_SITE_ID"),
        help="Optional UniFi site ID; a single site is selected automatically.",
    )
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
    unifi_settings = configured_unifi_settings(args.ansible_dir)
    prometheus_url = args.prometheus_url or unifi_settings.get("prometheus_url")
    unifi_controller_url = (
        args.unifi_controller_url or unifi_settings.get("controller_url")
    )
    unifi_api_key = os.environ.get("DASHBOARD_UNIFI_API_KEY", "").strip()
    unifi_site_id = (
        args.unifi_site_id or unifi_settings.get("controller_site_id") or None
    )
    unifi_controller_client = (
        UnifiControllerClient(
            unifi_controller_url,
            unifi_api_key,
            site_id=unifi_site_id,
            verify_tls=unifi_settings.get("controller_verify_tls", True),
        )
        if unifi_controller_url and unifi_api_key
        else None
    )
    DashboardRequestHandler.unifi_client = (
        UnifiPrometheusClient(
            prometheus_url,
            expected_offline_devices=unifi_settings.get(
                "expected_offline_devices",
                [],
            ),
            controller_client=unifi_controller_client,
        )
        if prometheus_url
        else None
    )
    handler = partial(DashboardRequestHandler, directory=str(args.reports_dir))

    server = ThreadingHTTPServer((args.bind, args.port), handler)
    server.daemon_threads = True
    print(
        f"Dashboard: http://{args.bind}:{args.port}\n"
        "Dashboard actions are restricted to manifest hosts on loopback.\n"
        f"UniFi metrics: {prometheus_url or 'disabled'}\n"
        "UniFi device inventory: "
        f"{unifi_controller_url if unifi_controller_client else 'not configured'}",
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
