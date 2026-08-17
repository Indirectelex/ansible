/*
 * TEACHER NOTE — CHAPTER 13: Browser application
 *
 * Purpose
 *   Load the versioned report contracts and turn them into a navigable fleet,
 *   selected-node inspector, full detail dialog, network view, and activity log.
 *
 * Data flow
 *   manifest -> host reports/maintenance -> state -> pure render helpers -> DOM.
 *   topology and storage topology enrich relationships. /api/unifi/summary is
 *   optional but its absence must never be mistaken for healthy network data.
 *
 * Security boundary
 *   The browser can request only server-defined actions. It does not create
 *   Ansible commands or PromQL. The server independently validates every POST.
 *
 * CHANGE INSTRUCTIONS
 *   When changing a report field, route, selector, class, or status rule, update
 *   its producer/server/HTML/CSS and contract tests in the same change. Keep
 *   rendering separate from collection policy and run node --check plus tests.
 */

"use strict";

// ---------------------------------------------------------------------------
// CHAPTER 13.1 — Single in-browser state and shared status vocabulary
// ---------------------------------------------------------------------------
// This object is the only mutable application model. Render functions read it;
// load/action functions update it. Do not hide authoritative state in DOM text.

const state = {
  reports: [],
  selectedHost: null,
  unifi: null,
  collapsedHosts: new Set(),
  collapsedSections: new Set(),
  topology: {
    datacenter_label: "Datacenter",
    nodes: {},
  },
  storageTopology: {
    hosts: [],
  },
  healthCheckJob: {
    state: "idle",
    action: null,
    host: null,
    message: "",
  },
  healthCheckPollId: null,
};

const UNIFI_NODE_ID = "@unifi-network";

const healthSeverityOrder = {
  CRITICAL: 0,
  UNREACHABLE: 1,
  WARNING: 2,
  UNKNOWN: 3,
  WATCH: 4,
  OK: 5,
};

const patchSeverityOrder = {
  ERROR: 0,
  AUTOMATION_ERROR: 1,
  AUTOMATION_OVERDUE: 2,
  REVIEW_REQUIRED: 3,
  ACTION_NEEDED: 4,
  DATA_STALE: 5,
  REBOOT_PENDING: 6,
  INSTALLING: 7,
  SCHEDULED: 8,
  ROUTINE_MAINTENANCE: 9,
  UNKNOWN: 10,
  CURRENT: 11,
};

const patchLabels = {
  ERROR: "Data error",
  AUTOMATION_ERROR: "Automation error",
  AUTOMATION_OVERDUE: "Automation overdue",
  REVIEW_REQUIRED: "Review required",
  ACTION_NEEDED: "Action needed",
  DATA_STALE: "Data stale",
  REBOOT_PENDING: "Reboot pending",
  INSTALLING: "Installing",
  SCHEDULED: "Scheduled",
  ROUTINE_MAINTENANCE: "Routine maintenance",
  UNKNOWN: "Unknown",
  CURRENT: "Current",
};

const grid = document.querySelector("#host-grid");
const fleetSummary = document.querySelector("#fleet-summary");
const inspector = document.querySelector("#host-inspector");
const filterCount = document.querySelector("#filter-count");
const meta = document.querySelector("#dashboard-meta");
const dialog = document.querySelector("#host-dialog");
const dialogTitle = document.querySelector("#dialog-title");
const dialogContent = document.querySelector("#dialog-content");
const healthCheckStatus = document.querySelector("#health-check-status");
const activityDrawer = document.querySelector("#activity-drawer");
const activityDrawerToggle = document.querySelector(
  "#activity-drawer-toggle",
);
const activityDrawerBody = document.querySelector("#activity-drawer-body");
const activityLogContext = document.querySelector("#activity-log-context");
const activityLogOutput = document.querySelector("#activity-log-output");

// ---------------------------------------------------------------------------
// CHAPTER 13.2 — Defensive formatting and status normalization
// ---------------------------------------------------------------------------
// Report/upstream strings are escaped before interpolation. Status helpers keep
// severity ordering and CSS class naming consistent across all renderers.

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function healthStatusName(value) {
  const status = String(value || "UNKNOWN").toUpperCase();

  if (status === "HEALTHY") {
    return "OK";
  }

  return Object.hasOwn(healthSeverityOrder, status)
    ? status
    : "UNKNOWN";
}

function patchStatusName(value) {
  const status = String(value || "UNKNOWN").toUpperCase();

  return Object.hasOwn(patchSeverityOrder, status)
    ? status
    : "UNKNOWN";
}

function healthStatusClass(value) {
  return `status-${healthStatusName(value).toLowerCase()}`;
}

function patchStatusClass(value) {
  return `patch-${patchStatusName(value)
    .toLowerCase()
    .replaceAll("_", "-")}`;
}

function patchStatusLabel(value) {
  return patchLabels[patchStatusName(value)];
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatAge(value) {
  const date = new Date(value);

  if (!value || Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));

  if (seconds < 60) {
    return "Now";
  }

  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m ago`;
  }

  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h ago`;
  }

  return `${Math.floor(seconds / 86400)}d ago`;
}

function formatDuration(value) {
  const seconds = Number(value);

  if (!Number.isFinite(seconds)) {
    return "Unknown duration";
  }

  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }

  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  return remainingSeconds > 0
    ? `${minutes}m ${remainingSeconds}s`
    : `${minutes}m`;
}

function numberValue(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function plural(value, singular, pluralForm = `${singular}s`) {
  return numberValue(value) === 1 ? singular : pluralForm;
}

function metricDisplayValue(metric) {
  const display = metric.display || "text";
  const value = metric.value;
  const unit = metric.unit ? ` ${metric.unit}` : "";

  if (display === "boolean") {
    return value === true || String(value).toLowerCase() === "true"
      ? "Yes"
      : "No";
  }

  if (typeof value === "number") {
    const rounded = Number.isInteger(value)
      ? value
      : Math.round(value * 100) / 100;

    return `${rounded}${unit}`;
  }

  return `${String(value ?? "—")}${unit}`;
}

function metricOrder(metric) {
  return Number(metric.order ?? 9999);
}

function getMetric(report, id) {
  return (report.metrics || []).find((metric) => metric.id === id);
}

function metricValue(report, id, fallback = "—") {
  const metric = getMetric(report, id);
  return metric ? metricDisplayValue(metric) : fallback;
}

function metadataAge(report) {
  const age = Number(report.package_metadata_age_hours);

  if (!Number.isFinite(age)) {
    return "Unknown";
  }

  if (age < 48) {
    return `${Math.round(age * 10) / 10}h`;
  }

  return `${Math.round((age / 24) * 10) / 10}d`;
}

function reasonMarkup(
  reasons,
  emptyText = "No active status reasons.",
  className = "",
) {
  if (!Array.isArray(reasons) || reasons.length === 0) {
    return `<p class="muted compact-note">${escapeHtml(emptyText)}</p>`;
  }

  return `
    <ul class="reason-list ${escapeHtml(className)}">
      ${reasons
        .map((reason) => `<li>${escapeHtml(reason)}</li>`)
        .join("")}
    </ul>
  `;
}

function patchPolicyLabel(report) {
  if (report.patch_policy === "all_security_manual_approval") {
    return "Manual approval";
  }

  if (report.patch_policy === "os_managed_security") {
    return "OS security automation enabled";
  }

  return "Monitor only";
}

function firstReason(report, type) {
  const reasons = type === "health"
    ? report.health_status_reasons || report.status_reasons
    : report.patch_status_reasons;

  return Array.isArray(reasons) && reasons.length > 0
    ? String(reasons[0])
    : "Open the host details for the collected evidence.";
}

// ---------------------------------------------------------------------------
// CHAPTER 13.3 — Operator guidance and controlled-action presentation
// ---------------------------------------------------------------------------
// Guidance summarizes already-decided policy; it must not invent health rules
// that disagree with Ansible/module results.

function hostActionGuidance(report) {
  const healthStatus = healthStatusName(
    report.health_status || report.status,
  );
  const patchStatus = patchStatusName(report.patch_posture_status);
  const securityUpdates = numberValue(report.security_updates_available);
  const reviewRequired = numberValue(report.review_required);

  if (healthStatus === "CRITICAL") {
    return {
      requiresAction: true,
      tone: "critical",
      title: "Investigate this host now",
      text: firstReason(report, "health"),
    };
  }

  if (healthStatus === "UNREACHABLE") {
    return {
      requiresAction: true,
      tone: "critical",
      title: "Restore monitoring connectivity",
      text: firstReason(report, "health"),
    };
  }

  if (healthStatus === "WARNING") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Review the health warning",
      text: firstReason(report, "health"),
    };
  }

  if (healthStatus === "UNKNOWN") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Review unavailable health data",
      text: firstReason(report, "health"),
    };
  }

  if (patchStatus === "ERROR") {
    return {
      requiresAction: true,
      tone: "critical",
      title: "Check patch-data collection",
      text: "Rerun the health check, then inspect the APT collection evidence in details.",
    };
  }

  if (patchStatus === "AUTOMATION_ERROR") {
    return {
      requiresAction: true,
      tone: "critical",
      title: "Inspect the automatic update failure",
      text: firstReason(report, "patch"),
    };
  }

  if (patchStatus === "AUTOMATION_OVERDUE") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Investigate OS update automation",
      text: firstReason(report, "patch"),
    };
  }

  if (
    patchStatus === "DATA_STALE" ||
    (
      report.patch_counts_trusted !== true &&
      !["ERROR", "UNKNOWN"].includes(patchStatus)
    )
  ) {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Refresh package metadata",
      text: `Cached package data is ${metadataAge(
        report,
      )} old or incomplete. Refresh metadata separately, then rerun the health check.`,
    };
  }

  if (patchStatus === "REVIEW_REQUIRED") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Plan reviewed maintenance",
      text: `${reviewRequired} infrastructure-sensitive ${plural(
        reviewRequired,
        "package requires",
        "packages require",
      )} approval before installation.`,
    };
  }

  if (patchStatus === "ACTION_NEEDED") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Schedule security maintenance",
      text: `${securityUpdates} ${plural(
        securityUpdates,
        "security update is",
        "security updates are",
      )} pending; monitoring will not install them.`,
    };
  }

  if (patchStatus === "REBOOT_PENDING") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Schedule a controlled reboot",
      text: "The host reports that a reboot is required; monitoring will not reboot it.",
    };
  }

  if (patchStatus === "UNKNOWN") {
    return {
      requiresAction: true,
      tone: "warning",
      title: "Review unavailable maintenance data",
      text: firstReason(report, "patch"),
    };
  }

  if (healthStatus === "WATCH") {
    return {
      requiresAction: false,
      tone: "watch",
      title: "Keep under observation",
      text: firstReason(report, "health"),
    };
  }

  if (patchStatus === "INSTALLING") {
    return {
      requiresAction: false,
      tone: "neutral",
      title: "No action while updates are running",
      text: "The OS-managed update attempt is in progress. Check the next report for its result.",
    };
  }

  if (patchStatus === "SCHEDULED") {
    return {
      requiresAction: false,
      tone: "neutral",
      title: "No action now",
      text: report.os_update_next_attempt_at
        ? `The OS-managed updater is scheduled to try ${formatDate(
          report.os_update_next_attempt_at,
        )}.`
        : "The OS-managed updater is enabled and has a scheduled attempt.",
    };
  }

  if (patchStatus === "ROUTINE_MAINTENANCE") {
    return {
      requiresAction: false,
      tone: "neutral",
      title: "No urgent action",
      text: "Only routine package maintenance is pending.",
    };
  }

  if (patchStatus === "CURRENT") {
    return {
      requiresAction: false,
      tone: "ok",
      title: "No action required",
      text: "Health and patch posture are current.",
    };
  }

  return {
    requiresAction: true,
    tone: "warning",
    title: "Review unavailable status data",
    text: "Open details to see which collection result is missing or unknown.",
  };
}

function renderActionGuidance(report) {
  const guidance = hostActionGuidance(report);

  return `
    <section class="next-step next-step-${escapeHtml(guidance.tone)}">
      <span class="next-step-label">Next step</span>
      <strong>${escapeHtml(guidance.title)}</strong>
      <p>${escapeHtml(guidance.text)}</p>
    </section>
  `;
}

function latestMaintenanceRun(report) {
  return report.maintenance_history?.latest || null;
}

function maintenanceResult(run) {
  if (run?.state === "success") {
    return {label: "Successful", className: "maintenance-success"};
  }

  const installation = (run?.phases || []).find(
    (phase) => phase.name === "installation",
  );

  if (installation?.state === "success") {
    return {
      label: "Installed; report refresh failed",
      className: "maintenance-warning",
    };
  }

  return {label: "Failed", className: "maintenance-failed"};
}

function renderLastMaintenance(report) {
  const run = latestMaintenanceRun(report);

  if (!run) {
    return "";
  }

  const result = maintenanceResult(run);
  const packageCount = numberValue(run.approved_package_count);

  return `
    <div class="last-maintenance">
      <span class="last-maintenance-label">Last security update</span>
      <strong class="${escapeHtml(result.className)}">
        ${escapeHtml(result.label)}
      </strong>
      <span class="muted">
        ${escapeHtml(formatDate(run.finished_at))} ·
        ${packageCount} approved ${escapeHtml(plural(packageCount, "package"))}
      </span>
    </div>
  `;
}

function healthCheckIsRunning() {
  return state.healthCheckJob.state === "running";
}

function renderHealthCheckButton(report) {
  const isThisJob =
    state.healthCheckJob.action === "health_check" &&
    state.healthCheckJob.host === report.host;
  const isRunning = healthCheckIsRunning();
  const label = isRunning && isThisJob
    ? "Checking"
    : "Run health check";

  return `
    <button
      class="secondary-button run-check-button"
      type="button"
      data-action="health-check"
      data-host="${escapeHtml(report.host)}"
      ${isRunning ? "disabled" : ""}
      ${isRunning && isThisJob ? 'aria-busy="true"' : ""}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function securityPackageNames(report) {
  const groups = report.security_packages || {};

  return [
    ...(groups.review_required || []),
    ...(groups.restart_sensitive || []),
    ...(groups.standard_security || []),
  ]
    .map((item) => String(item.name || ""))
    .filter((name) => name.length > 0)
    .sort();
}

function renderSecurityUpdateButton(report) {
  const securityUpdates = numberValue(report.security_updates_available);

  if (securityUpdates < 1) {
    return "";
  }

  const isThisJob =
    state.healthCheckJob.action === "security_update" &&
    state.healthCheckJob.host === report.host;
  const isRunning = healthCheckIsRunning();
  const label = isRunning && isThisJob
    ? "Installing"
    : `Install security (${securityUpdates})`;

  return `
    <button
      class="security-update-button"
      type="button"
      data-action="security-update"
      data-host="${escapeHtml(report.host)}"
      ${isRunning ? "disabled" : ""}
      ${isRunning && isThisJob ? 'aria-busy="true"' : ""}
      title="Refresh APT metadata and install packages detected in security pockets"
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function setActivityDrawerOpen(isOpen) {
  activityDrawer.classList.toggle("is-open", isOpen);
  activityDrawerToggle.setAttribute("aria-expanded", String(isOpen));
  activityDrawerBody.hidden = !isOpen;
}

function dashboardActionLabel(action) {
  return action === "security_update" ? "Security update" : "Health check";
}

function renderHealthCheckStatus() {
  const job = state.healthCheckJob;

  if (!job || job.state === "idle") {
    healthCheckStatus.className = "run-status";
    healthCheckStatus.textContent = "No dashboard activity yet.";
    activityLogContext.textContent = "Idle";
    activityLogOutput.textContent = "No dashboard command output yet.";
    return;
  }

  const messages = {
    running: job.message || `Dashboard action running for ${job.host}.`,
    success: job.message || `Dashboard action completed for ${job.host}.`,
    failed: job.message || `Dashboard action failed for ${job.host}.`,
  };

  healthCheckStatus.className = `run-status run-status-${job.state}`;
  healthCheckStatus.textContent = messages[job.state] || job.message;
  activityLogContext.textContent = [
    dashboardActionLabel(job.action),
    job.host || "Unknown host",
    job.state,
  ].join(" · ");

  const outputLines = Array.isArray(job.output_tail) ? job.output_tail : [];
  activityLogOutput.textContent = outputLines.length > 0
    ? outputLines.join("\n")
    : job.state === "running"
      ? "Waiting for command output…"
      : "No command output was returned.";
  activityLogOutput.scrollTop = activityLogOutput.scrollHeight;

  if (["running", "failed"].includes(job.state)) {
    setActivityDrawerOpen(true);
  }
}

// ---------------------------------------------------------------------------
// CHAPTER 13.4 — Datacenter tree, parent-child topology, and node selection
// ---------------------------------------------------------------------------
// Manifest membership controls existence. Topology only adds parent, kind, and
// guest identity. Unmapped hosts remain visible at the datacenter root.

function topologyFor(report) {
  const manifest = report.dashboard_manifest || {};
  const configured = state.topology.nodes?.[report.host] || {};

  return {
    parent:
      configured.parent ||
      manifest.parent ||
      manifest.dashboard_parent ||
      report.dashboard_parent ||
      null,
    guestId:
      configured.guest_id ??
      manifest.guest_id ??
      manifest.vm_id ??
      report.guest_id ??
      null,
    kind:
      configured.kind ||
      manifest.kind ||
      manifest.dashboard_kind ||
      report.dashboard_kind ||
      null,
  };
}

function hostKind(report) {
  const configuredKind = String(topologyFor(report).kind || "").toLowerCase();
  const features = report.features || report.detected_features || {};

  if (["lxc", "container"].includes(configuredKind)) {
    return "container";
  }

  if (configuredKind === "pbs" || features.pbs) {
    return "pbs";
  }

  if (configuredKind === "vm") {
    return features.truenas ? "truenas" : "vm";
  }

  if (features.proxmox) {
    return "proxmox";
  }

  if (features.truenas) {
    return "truenas";
  }

  if (features.lxc_container) {
    return "container";
  }

  if (features.vm) {
    return "vm";
  }

  if (features.docker) {
    return "docker";
  }

  return "linux";
}

function hostTypeLabel(report) {
  const labels = {
    proxmox: "Proxmox node",
    pbs: "Proxmox Backup Server VM",
    container: report.features?.docker ? "Docker LXC" : "LXC container",
    truenas: report.features?.vm ? "TrueNAS VM" : "TrueNAS",
    vm: "Virtual machine",
    docker: "Docker host",
    linux: "Linux server",
  };

  return labels[hostKind(report)] || "Monitored host";
}

function hostIconMarkup(report) {
  const kind = hostKind(report);
  const icons = {
    proxmox: `
      <svg viewBox="0 0 24 24">
        <rect x="4" y="3" width="16" height="5" rx="1"></rect>
        <rect x="4" y="10" width="16" height="5" rx="1"></rect>
        <rect x="4" y="17" width="16" height="4" rx="1"></rect>
        <path d="M7 5.5h.01M7 12.5h.01M7 19h.01"></path>
      </svg>
    `,
    pbs: `
      <svg viewBox="0 0 24 24">
        <path d="M4 7.5 12 3l8 4.5v9L12 21l-8-4.5v-9Z"></path>
        <path d="M4.5 7.7 12 12l7.5-4.3M12 12v8.5"></path>
        <path d="M8.5 6.2 16 10.5"></path>
      </svg>
    `,
    container: `
      <svg viewBox="0 0 24 24">
        <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"></path>
        <path d="m4.5 7.7 7.5 4.2 7.5-4.2M12 12v8.5"></path>
      </svg>
    `,
    truenas: `
      <svg viewBox="0 0 24 24">
        <ellipse cx="12" cy="5.5" rx="7.5" ry="3"></ellipse>
        <path d="M4.5 5.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"></path>
        <path d="M4.5 11.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"></path>
      </svg>
    `,
    vm: `
      <svg viewBox="0 0 24 24">
        <rect x="3" y="4" width="18" height="13" rx="1.5"></rect>
        <path d="M8 21h8M12 17v4"></path>
      </svg>
    `,
    docker: `
      <svg viewBox="0 0 24 24">
        <rect x="4" y="5" width="7" height="6" rx="1"></rect>
        <rect x="13" y="5" width="7" height="6" rx="1"></rect>
        <rect x="8.5" y="13" width="7" height="6" rx="1"></rect>
      </svg>
    `,
    linux: `
      <svg viewBox="0 0 24 24">
        <rect x="3" y="4" width="18" height="16" rx="2"></rect>
        <path d="m7 9 3 3-3 3M12.5 15H17"></path>
      </svg>
    `,
  };

  return `
    <span class="node-icon node-icon-${escapeHtml(kind)}" aria-hidden="true">
      ${icons[kind]}
    </span>
  `;
}

function treeReportSort(left, right) {
  const leftRank = hostKind(left) === "proxmox" ? 0 : 1;
  const rightRank = hostKind(right) === "proxmox" ? 0 : 1;
  const topologyDifference = leftRank - rightRank;

  if (topologyDifference !== 0) {
    return topologyDifference;
  }

  return reportSort(left, right);
}

function topologyTree(reports) {
  const reportsByHost = new Map(
    reports.map((report) => [String(report.host), report]),
  );
  const children = new Map();
  const roots = [];

  for (const report of reports) {
    const parent = String(topologyFor(report).parent || "");

    if (parent && parent !== report.host && reportsByHost.has(parent)) {
      if (!children.has(parent)) {
        children.set(parent, []);
      }

      children.get(parent).push(report);
    } else {
      roots.push(report);
    }
  }

  roots.sort(treeReportSort);

  for (const items of children.values()) {
    items.sort((left, right) => {
      const leftId = Number(topologyFor(left).guestId);
      const rightId = Number(topologyFor(right).guestId);

      if (Number.isFinite(leftId) && Number.isFinite(rightId)) {
        return leftId - rightId;
      }

      return treeReportSort(left, right);
    });
  }

  return {roots, children};
}

function renderHostRow(report, depth, hasChildren) {
  const healthStatus = healthStatusName(
    report.health_status || report.status,
  );
  const topology = topologyFor(report);
  const collapsed = state.collapsedHosts.has(report.host);
  const selected = state.selectedHost === report.host;
  const guestId = topology.guestId === null || topology.guestId === undefined
    ? ""
    : `<span class="guest-id">${escapeHtml(topology.guestId)}</span>`;
  const toggle = hasChildren
    ? `
      <button
        class="tree-toggle"
        type="button"
        data-action="toggle-node"
        data-host="${escapeHtml(report.host)}"
        aria-label="${collapsed ? "Expand" : "Collapse"} ${escapeHtml(report.host)}"
        aria-expanded="${collapsed ? "false" : "true"}"
      >
        <svg aria-hidden="true" viewBox="0 0 16 16">
          <path d="m5 3 5 5-5 5"></path>
        </svg>
      </button>
    `
    : '<span class="tree-toggle-spacer" aria-hidden="true"></span>';

  return `
    <div
      class="tree-row ${selected ? "is-selected" : ""}"
      style="--tree-depth: ${depth}"
      role="treeitem"
      aria-level="${depth + 2}"
      aria-selected="${selected ? "true" : "false"}"
      aria-label="${escapeHtml(report.host)} · Health ${escapeHtml(healthStatus)}"
      ${hasChildren ? `aria-expanded="${collapsed ? "false" : "true"}"` : ""}
      tabindex="0"
      data-action="select-host"
      data-host="${escapeHtml(report.host)}"
    >
      <span class="tree-name-cell">
        <span class="tree-indent" aria-hidden="true"></span>
        ${toggle}
        ${hostIconMarkup(report)}
        <span class="host-identity">
          <span class="host-name-line">
            <strong>${guestId}${escapeHtml(report.host)}</strong>
            <span
              class="status-dot ${healthStatusClass(healthStatus)}"
              aria-hidden="true"
              title="Health ${escapeHtml(healthStatus)}"
            ></span>
          </span>
          <small>${escapeHtml(hostTypeLabel(report))}</small>
        </span>
      </span>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// CHAPTER 13.5 — Conditional Network node and UniFi incident view
// ---------------------------------------------------------------------------
// The Network node exists only when the custom server returns a valid summary.
// Findings and health appear before raw inventory to support incident response.

function unifiIconMarkup() {
  return `
    <span class="node-icon node-icon-unifi" aria-hidden="true">
      <svg viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="3"></circle>
        <path d="M7.8 7.8a6 6 0 0 1 8.4 0M4.9 4.9a10 10 0 0 1 14.2 0"></path>
        <path d="M7.8 16.2a6 6 0 0 0 8.4 0M4.9 19.1a10 10 0 0 0 14.2 0"></path>
      </svg>
    </span>
  `;
}

function renderUnifiTreeRow() {
  if (!state.unifi) {
    return "";
  }

  const status = healthStatusName(state.unifi.status);
  const selected = state.selectedHost === UNIFI_NODE_ID;

  return `
    <div
      class="tree-row integration-tree-row ${selected ? "is-selected" : ""}"
      style="--tree-depth: 0"
      role="treeitem"
      aria-level="2"
      aria-selected="${selected ? "true" : "false"}"
      aria-label="UniFi Network · Health ${escapeHtml(status)}"
      tabindex="0"
      data-action="select-host"
      data-host="${UNIFI_NODE_ID}"
    >
      <span class="tree-name-cell">
        <span class="tree-indent" aria-hidden="true"></span>
        <span class="tree-toggle-spacer" aria-hidden="true"></span>
        ${unifiIconMarkup()}
        <span class="host-identity">
          <span class="host-name-line">
            <strong>${escapeHtml(state.unifi.name || "UniFi Network")}</strong>
            <span
              class="status-dot ${healthStatusClass(status)}"
              aria-hidden="true"
              title="Health ${escapeHtml(status)}"
            ></span>
          </span>
          <small>Live network integration</small>
        </span>
      </span>
    </div>
  `;
}

function renderInfrastructureSection(
  sectionId,
  label,
  countLabel,
  iconMarkup,
  content,
) {
  const collapsed = state.collapsedSections.has(sectionId);

  return `
    <div
      class="datacenter-row infrastructure-section-row ${sectionId}-section-row"
      role="treeitem"
      aria-level="1"
      aria-expanded="${collapsed ? "false" : "true"}"
    >
      <button
        class="tree-toggle section-toggle"
        type="button"
        data-action="toggle-section"
        data-section="${escapeHtml(sectionId)}"
        aria-label="${collapsed ? "Expand" : "Collapse"} ${escapeHtml(label)}"
        aria-expanded="${collapsed ? "false" : "true"}"
      >
        <svg aria-hidden="true" viewBox="0 0 16 16">
          <path d="m5 3 5 5-5 5"></path>
        </svg>
      </button>
      ${iconMarkup}
      <strong>${escapeHtml(label)}</strong>
      <span>${escapeHtml(countLabel)}</span>
    </div>
    ${collapsed ? "" : content}
  `;
}

function renderFleetTree(reports) {
  const integrationCount = state.unifi ? 1 : 0;
  filterCount.textContent = integrationCount
    ? `${reports.length} hosts · ${integrationCount} integration`
    : `${reports.length} of ${state.reports.length} hosts`;

  if (reports.length === 0 && !state.unifi) {
    grid.innerHTML = `
      <div class="tree-empty-state">
        <strong>No matching hosts</strong>
        <span>Change the hostname, health, or maintenance filter.</span>
      </div>
    `;
    return;
  }

  const {roots, children} = topologyTree(reports);
  const rows = [];

  function addRows(items, depth) {
    for (const report of items) {
      const childReports = children.get(report.host) || [];
      rows.push(renderHostRow(report, depth, childReports.length > 0));

      if (
        childReports.length > 0 &&
        !state.collapsedHosts.has(report.host)
      ) {
        addRows(childReports, depth + 1);
      }
    }
  }

  addRows(roots, 0);

  const datacenterIcon = `
    <svg class="datacenter-icon" aria-hidden="true" viewBox="0 0 24 24">
      <rect x="4" y="3" width="16" height="5" rx="1"></rect>
      <rect x="4" y="10" width="16" height="5" rx="1"></rect>
      <rect x="4" y="17" width="16" height="4" rx="1"></rect>
    </svg>
  `;
  const networkIcon = `
    <svg class="datacenter-icon network-section-icon" aria-hidden="true" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="2.5"></circle>
      <circle cx="5" cy="6" r="2"></circle>
      <circle cx="19" cy="6" r="2"></circle>
      <circle cx="5" cy="18" r="2"></circle>
      <circle cx="19" cy="18" r="2"></circle>
      <path d="m7 7.5 3 3M17 7.5l-3 3M7 16.5l3-3M17 16.5l-3-3"></path>
    </svg>
  `;

  grid.innerHTML = `
    ${renderInfrastructureSection(
      "datacenter",
      state.topology.datacenter_label || "Datacenter",
      `${reports.length} ${plural(reports.length, "host")}`,
      datacenterIcon,
      rows.join(""),
    )}
    ${
      state.unifi
        ? renderInfrastructureSection(
            "network",
            "Network",
            "1 integration",
            networkIcon,
            renderUnifiTreeRow(),
          )
        : ""
    }
  `;
}

// ---------------------------------------------------------------------------
// CHAPTER 13.6 — Selected-node compact inspector
// ---------------------------------------------------------------------------
// The inspector is intentionally concise; exhaustive evidence belongs in the
// dialog so the navigator remains useful on ordinary laptop screens.

function renderInspectorModules(report) {
  const modules = Array.isArray(report.module_results)
    ? report.module_results
    : [];

  if (modules.length === 0) {
    return "";
  }

  return `
    <section class="inspector-section">
      <h3>Monitoring modules</h3>
      <div class="inspector-modules">
        ${modules
          .map((module) => {
            const status = String(module.status || "unknown").toLowerCase();
            return `
              <div class="inspector-module">
                <span class="module-dot module-${escapeHtml(status)}" aria-hidden="true"></span>
                <strong>${escapeHtml(String(module.check || "module").toUpperCase())}</strong>
                <span>${escapeHtml(module.summary || status)}</span>
              </div>
            `;
          })
          .join("")}
      </div>
    </section>
  `;
}

function formatByteRate(value) {
  const bytes = numberValue(value);
  const units = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
  let amount = bytes;
  let unitIndex = 0;

  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }

  const precision = amount >= 100 || unitIndex === 0 ? 0 : 1;
  return `${amount.toFixed(precision)} ${units[unitIndex]}`;
}

function formatLongUptime(value) {
  const seconds = numberValue(value);

  if (seconds <= 0) {
    return "Unavailable";
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days > 0 ? `${days}d ${hours}h` : `${hours}h`;
}

function unifiDeviceTypeLabel(value, model) {
  if (String(model || "").toUpperCase() === "UP1") {
    return "SmartPower plug";
  }

  const labels = {
    uap: "Access point",
    udm: "Gateway",
    usw: "Switch",
  };
  return labels[String(value || "").toLowerCase()] || "UniFi device";
}

function formatUnifiNumber(value, suffix = "", precision = 0) {
  const amount = Number(value);

  if (value == null || !Number.isFinite(amount)) {
    return "Not reported";
  }

  return `${amount.toFixed(precision)}${suffix}`;
}

function formatUnifiCountWithRatio(count, ratio) {
  const numericCount = Number(count);
  const numericRatio = Number(ratio);

  if (count == null || !Number.isFinite(numericCount)) {
    return "Not reported";
  }

  const countLabel = Math.round(numericCount).toLocaleString();
  if (ratio == null || !Number.isFinite(numericRatio)) {
    return countLabel;
  }

  const ratioPrecision = numericRatio < 0.1 ? 3 : numericRatio < 1 ? 2 : 1;
  return `${countLabel} · ${numericRatio.toFixed(ratioPrecision)}%`;
}

function renderUnifiHealthCard(title, data, facts) {
  const status = healthStatusName(data?.status);

  return `
    <article class="unifi-health-card ${healthStatusClass(status)}">
      <header>
        <h3>${escapeHtml(title)}</h3>
        <span class="status-badge ${healthStatusClass(status)}">
          ${escapeHtml(status)}
        </span>
      </header>
      <dl>
        ${facts.map((fact) => `
          <div>
            <dt>${escapeHtml(fact.label)}</dt>
            <dd>${escapeHtml(fact.value)}</dd>
          </div>
        `).join("")}
      </dl>
    </article>
  `;
}

function renderUnifiTrendChart(title, points, formatter) {
  const values = (Array.isArray(points) ? points : [])
    .filter((point) => (
      Array.isArray(point)
      && point.length >= 2
      && Number.isFinite(Number(point[0]))
      && Number.isFinite(Number(point[1]))
    ))
    .map((point) => [Number(point[0]), Number(point[1])]);

  if (values.length < 2) {
    return `
      <article class="unifi-trend-card unifi-trend-empty">
        <header><h3>${escapeHtml(title)}</h3><strong>Not reported</strong></header>
        <p>Prometheus has not collected enough history yet.</p>
      </article>
    `;
  }

  const samples = values.map((point) => point[1]);
  const minimum = Math.min(...samples);
  const maximum = Math.max(...samples);
  const range = maximum - minimum || 1;
  const width = 320;
  const height = 72;
  const coordinates = values.map((point, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - (((point[1] - minimum) / range) * (height - 12)) - 6;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const current = samples[samples.length - 1];

  return `
    <article class="unifi-trend-card">
      <header>
        <h3>${escapeHtml(title)}</h3>
        <strong>${escapeHtml(formatter(current))}</strong>
      </header>
      <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(title)} over the last 24 hours">
        <line x1="0" y1="${height - 1}" x2="${width}" y2="${height - 1}"></line>
        <polyline points="${coordinates.join(" ")}"></polyline>
      </svg>
      <footer>
        <span>Low ${escapeHtml(formatter(minimum))}</span>
        <span>24 hours</span>
        <span>High ${escapeHtml(formatter(maximum))}</span>
      </footer>
    </article>
  `;
}

function renderUnifiInspector(unifi) {
  const status = healthStatusName(unifi?.status);
  const summary = unifi?.summary || {};
  const health = unifi?.health || {};
  const findings = Array.isArray(unifi?.findings) ? unifi.findings : [];
  const trends = unifi?.trends || {};
  const subsystems = Array.isArray(unifi?.subsystems) ? unifi.subsystems : [];
  const devices = Array.isArray(unifi?.devices) ? unifi.devices : [];
  const guidanceClass = status === "CRITICAL"
    ? "next-step-critical"
    : status === "WARNING"
      ? "next-step-warning"
    : status === "WATCH"
      ? "next-step-watch"
      : "next-step-ok";

  inspector.innerHTML = `
    <header class="inspector-header unifi-inspector-header">
      <div class="inspector-title">
        ${unifiIconMarkup()}
        <div>
          <p>UniFi source · Prometheus history</p>
          <h2>${escapeHtml(unifi?.name || "UniFi Network")}</h2>
        </div>
      </div>
      <span class="status-badge ${healthStatusClass(status)}">
        ${escapeHtml(status)}
      </span>
    </header>

    <section class="next-step ${guidanceClass}">
      <span>NETWORK POSTURE</span>
      <strong>${escapeHtml(unifi?.message || "UniFi data is unavailable.")}</strong>
      <p>
        Roster from UniFi · Metrics from Unpoller · Sample ${escapeHtml(formatAge(unifi?.collected_at))}
      </p>
    </section>

    <section class="inspector-section unifi-findings-section">
      <div class="unifi-section-heading">
        <div>
          <span>Needs attention first</span>
          <h3>Active findings</h3>
        </div>
        <strong>${escapeHtml(findings.length)}</strong>
      </div>
      <div class="unifi-findings-list">
        ${
          findings.length > 0
            ? findings.map((finding) => {
                const findingStatus = healthStatusName(finding.severity);
                return `
                  <article class="unifi-finding ${healthStatusClass(findingStatus)}">
                    <span class="status-dot ${healthStatusClass(findingStatus)}" aria-hidden="true"></span>
                    <div>
                      <span>${escapeHtml(finding.area || "network")}</span>
                      <strong>${escapeHtml(finding.title || "Review UniFi finding")}</strong>
                      <p>${escapeHtml(finding.detail || "No additional detail was returned.")}</p>
                    </div>
                    <span class="status-badge ${healthStatusClass(findingStatus)}">${escapeHtml(findingStatus)}</span>
                  </article>
                `;
              }).join("")
            : `
                <article class="unifi-finding unifi-finding-clear status-ok">
                  <span class="status-dot status-ok" aria-hidden="true"></span>
                  <div>
                    <span>network</span>
                    <strong>No active findings</strong>
                    <p>All monitored UniFi domains are within the dashboard policy.</p>
                  </div>
                </article>
              `
        }
      </div>
      <p class="unifi-metric-note">
        Adopted-device state comes directly from UniFi. Prometheus history only enriches that roster with metrics and last-seen data.
      </p>
    </section>

    <section class="inspector-section unifi-health-section">
      <div class="unifi-section-heading">
        <div>
          <span>Current condition</span>
          <h3>Operational health</h3>
        </div>
      </div>
      <div class="unifi-health-grid">
        ${renderUnifiHealthCard("WAN", health.wan, [
          {label: "Latency", value: formatUnifiNumber(health.wan?.latency_ms, " ms", 1)},
          {label: "Errors · 24h", value: formatUnifiNumber(health.wan?.errors_24h)},
          {label: "Drops · 24h", value: formatUnifiNumber(health.wan?.drops_24h)},
          {label: "Uptime", value: formatUnifiNumber(health.wan?.uptime_pct, "%", 1)},
          {label: "Receive", value: formatByteRate(summary.receive_rate_bytes)},
          {label: "Transmit", value: formatByteRate(summary.transmit_rate_bytes)},
        ])}
        ${renderUnifiHealthCard("Wi-Fi", health.wifi, [
          {label: "Access points", value: String(summary.access_points ?? "Not reported")},
          {label: "Connected clients", value: String(summary.clients ?? "Not reported")},
          {label: "Channel use", value: formatUnifiNumber(health.wifi?.channel_utilization_pct, "%", 1)},
          {label: "Satisfaction", value: formatUnifiNumber(health.wifi?.satisfaction_pct, "%", 1)},
          {label: "Retry ratio · 24h", value: formatUnifiNumber(health.wifi?.retry_ratio_pct, "%", 1)},
          {label: "Weak signal", value: formatUnifiNumber(health.wifi?.weak_signal_clients, " clients")},
        ])}
        ${renderUnifiHealthCard("Switching", health.switching, [
          {label: "Switches", value: String(summary.switches ?? "Not reported")},
          {label: "Port errors · 24h", value: formatUnifiCountWithRatio(health.switching?.port_errors_24h, health.switching?.port_error_ratio_pct)},
          {label: "Port drops · 24h", value: formatUnifiCountWithRatio(health.switching?.port_drops_24h, health.switching?.port_drop_ratio_pct)},
          {label: "PoE load", value: health.switching?.poe_capacity_watts > 0
            ? `${formatUnifiNumber(health.switching?.poe_watts, " W", 1)} / ${formatUnifiNumber(health.switching?.poe_capacity_watts, " W", 1)}`
            : formatUnifiNumber(health.switching?.poe_watts, " W", 1)},
          {label: "Pending adoption", value: String(summary.pending ?? 0)},
          {label: "Gateways", value: String(summary.gateways ?? "Not reported")},
        ])}
        ${renderUnifiHealthCard("Devices", health.devices, [
          {label: summary.inventory_authoritative ? "Online · UniFi roster" : "Online · metric fallback", value: health.devices?.total == null
            ? "Not reported"
            : `${health.devices?.online ?? 0} / ${health.devices.total}`},
          {label: "Unexpected offline", value: String(health.devices?.unexpected_offline ?? 0)},
          {label: "Expected offline", value: String(health.devices?.expected_offline ?? 0)},
          {label: "Updates", value: String(health.devices?.updates ?? 0)},
          {label: "Highest temperature", value: formatUnifiNumber(health.devices?.hottest_c, " °C", 1)},
          {label: "Peak CPU / memory", value: `${formatUnifiNumber(health.devices?.max_cpu_pct, "%", 1)} / ${formatUnifiNumber(health.devices?.max_memory_pct, "%", 1)}`},
        ])}
      </div>
    </section>

    <section class="inspector-section unifi-trends-section">
      <div class="unifi-section-heading">
        <div>
          <span>Prometheus history</span>
          <h3>Last 24 hours</h3>
        </div>
      </div>
      <div class="unifi-trend-grid">
        ${renderUnifiTrendChart("WAN latency", trends.latency_ms, (value) => `${value.toFixed(1)} ms`)}
        ${renderUnifiTrendChart("Connected clients", trends.clients, (value) => `${Math.round(value)}`)}
        ${renderUnifiTrendChart("Receive rate", trends.receive_rate_bytes, formatByteRate)}
        ${renderUnifiTrendChart("Transmit rate", trends.transmit_rate_bytes, formatByteRate)}
      </div>
    </section>

    <details class="unifi-details unifi-subsystem-details">
      <summary>
        <span>Controller subsystem details</span>
        <small>${escapeHtml(subsystems.length)} reported</small>
      </summary>
      <div class="unifi-subsystem-grid">
        ${
          subsystems.length > 0
            ? subsystems.map((subsystem) => {
                const reportedStatus = String(subsystem.status || "unknown").toLowerCase();
                const dotStatus = reportedStatus === "ok" ? "ok" : reportedStatus === "error" ? "watch" : "unknown";
                const facts = [
                  subsystem.gateways ? `${subsystem.gateways} gateway` : "",
                  subsystem.switches ? `${subsystem.switches} switches` : "",
                  subsystem.access_points ? `${subsystem.access_points} AP` : "",
                  subsystem.clients != null ? `${subsystem.clients} clients` : "",
                  subsystem.disconnected ? `${subsystem.disconnected} disconnected` : "",
                ].filter(Boolean);
                return `
                  <article class="unifi-subsystem-card">
                    <div>
                      <span class="status-dot status-${escapeHtml(dotStatus)}" aria-hidden="true"></span>
                      <strong>${escapeHtml(String(subsystem.name || "other").toUpperCase())}</strong>
                    </div>
                    <span>${escapeHtml(facts.join(" · ") || "No reported activity")}</span>
                    <small>Controller status: ${escapeHtml(reportedStatus)}</small>
                  </article>
                `;
              }).join("")
            : '<p class="muted">No subsystem samples were returned.</p>'
        }
      </div>
    </details>

    <details class="unifi-details unifi-inventory-details">
      <summary>
        <span>UniFi device inventory</span>
        <small>${escapeHtml(devices.length)} ${summary.inventory_authoritative ? "adopted devices" : "currently reported devices"}</small>
      </summary>
      <div class="unifi-device-grid">
        ${
          devices.length > 0
            ? devices.map((device) => {
                const deviceOffline = device.reported_online === false;
                return `
                  <article class="unifi-device-card ${deviceOffline && !device.expected_offline ? "unifi-device-card-offline" : ""}">
                    <header>
                      <div>
                        <strong>${escapeHtml(device.name || "Unnamed device")}</strong>
                        <span>${escapeHtml(unifiDeviceTypeLabel(device.type, device.model))}</span>
                      </div>
                      <div class="unifi-device-badges">
                        ${
                          deviceOffline && device.expected_offline
                            ? '<span class="unifi-device-state unifi-device-expected">Expected offline</span>'
                            : deviceOffline
                              ? '<span class="unifi-device-state unifi-device-offline">Disconnected</span>'
                              : device.reported_online === true
                                ? '<span class="unifi-device-state unifi-device-online">Online</span>'
                                : ""
                        }
                        ${device.upgradable ? '<span class="unifi-update-badge">Update</span>' : ""}
                      </div>
                    </header>
                    <dl>
                      <div><dt>Model</dt><dd>${escapeHtml(device.model || "—")}</dd></div>
                      <div><dt>IP</dt><dd>${escapeHtml(device.ip || "—")}</dd></div>
                      <div><dt>Version</dt><dd>${escapeHtml(device.version || "—")}</dd></div>
                      <div><dt>${deviceOffline ? "Last seen" : "Uptime"}</dt><dd>${deviceOffline ? escapeHtml(formatAge(device.last_seen_at)) : escapeHtml(formatLongUptime(device.uptime_seconds))}</dd></div>
                      <div><dt>CPU</dt><dd>${deviceOffline || device.cpu_ratio == null ? "—" : `${escapeHtml((numberValue(device.cpu_ratio) * 100).toFixed(1))}%`}</dd></div>
                      <div><dt>Memory</dt><dd>${deviceOffline || device.memory_ratio == null ? "—" : `${escapeHtml((numberValue(device.memory_ratio) * 100).toFixed(1))}%`}</dd></div>
                      <div><dt>Temperature</dt><dd>${deviceOffline || device.temperature_c == null ? "—" : `${escapeHtml(device.temperature_c)} °C`}</dd></div>
                      <div><dt>Stations</dt><dd>${deviceOffline ? "—" : escapeHtml(device.stations ?? "—")}</dd></div>
                    </dl>
                  </article>
                `;
              }).join("")
            : '<p class="muted">No UniFi device inventory was returned.</p>'
        }
      </div>
    </details>
  `;
}

function renderInspector(report) {
  if (!report) {
    inspector.innerHTML = `
      <div class="inspector-empty">
        Select a host to see its summary.
      </div>
    `;
    return;
  }

  const healthStatus = healthStatusName(
    report.health_status || report.status,
  );
  const patchStatus = patchStatusName(report.patch_posture_status);
  const topology = topologyFor(report);
  const guestLabel = topology.guestId === null || topology.guestId === undefined
    ? ""
    : `ID ${topology.guestId} · `;

  inspector.innerHTML = `
    <header class="inspector-header">
      <div class="inspector-title">
        ${hostIconMarkup(report)}
        <div>
          <p>${escapeHtml(guestLabel + hostTypeLabel(report))}</p>
          <h2>${escapeHtml(report.host)}</h2>
        </div>
      </div>
      <span class="status-badge ${healthStatusClass(healthStatus)}">
        ${escapeHtml(healthStatus)}
      </span>
    </header>

    ${renderActionGuidance(report)}

    <dl class="inspector-metrics">
      <div>
        <dt>CPU / core</dt>
        <dd>${escapeHtml(metricValue(report, "load_per_cpu"))}</dd>
      </div>
      <div>
        <dt>Memory</dt>
        <dd>${escapeHtml(metricValue(report, "memory"))}</dd>
      </div>
      <div>
        <dt>Root disk</dt>
        <dd>${escapeHtml(metricValue(report, "root_disk"))}</dd>
      </div>
      <div>
        <dt>Failed services</dt>
        <dd>${escapeHtml(metricValue(report, "failed_services"))}</dd>
      </div>
      <div>
        <dt>Maintenance</dt>
        <dd class="${patchStatusClass(patchStatus)}">
          ${escapeHtml(patchStatusLabel(patchStatus))}
        </dd>
      </div>
      <div>
        <dt>Last checked</dt>
        <dd title="${escapeHtml(formatDate(report.generated_at))}">
          ${escapeHtml(formatAge(report.generated_at))}
        </dd>
      </div>
    </dl>

    ${renderInspectorModules(report)}

    ${renderLastMaintenance(report)}

    <div class="inspector-actions">
      ${renderHealthCheckButton(report)}
      ${renderSecurityUpdateButton(report)}
      <button
        type="button"
        data-action="details"
        data-host="${escapeHtml(report.host)}"
      >
        Full details
      </button>
      <a
        class="report-link"
        href="${encodeURIComponent(report.host)}.md"
        target="_blank"
        rel="noopener"
      >
        Markdown report
      </a>
    </div>
  `;
}

function renderFleetSummary(reports) {
  const okHosts = reports.filter(
    (report) =>
      healthStatusName(report.health_status || report.status) === "OK",
  ).length;
  const watchHosts = reports.filter(
    (report) =>
      healthStatusName(report.health_status || report.status) === "WATCH",
  ).length;
  const attentionHosts = reports.filter(
    (report) => hostActionGuidance(report).requiresAction,
  ).length;
  const reboots = reports.filter((report) => report.reboot_required).length;
  const criticalHosts = reports.filter((report) =>
    ["CRITICAL", "UNREACHABLE"].includes(
      healthStatusName(report.health_status || report.status),
    ),
  ).length;
  const fleetTone = criticalHosts > 0
    ? "critical"
    : attentionHosts > 0
      ? "warning"
      : watchHosts > 0
        ? "watch"
        : "ok";
  const fleetMessage = criticalHosts > 0
    ? `${criticalHosts} critical ${plural(criticalHosts, "host")}`
    : attentionHosts > 0
      ? `${attentionHosts} ${plural(attentionHosts, "host needs", "hosts need")} review`
      : watchHosts > 0
        ? `${watchHosts} ${plural(watchHosts, "host", "hosts")} under watch · No immediate action required`
        : "No immediate action required";

  fleetSummary.innerHTML = `
    <div class="fleet-status-strip">
      <div class="fleet-status-title">
        <span class="fleet-state-dot fleet-state-${escapeHtml(fleetTone)}" aria-hidden="true"></span>
        <div>
          <strong>Fleet status</strong>
          <span>${escapeHtml(fleetMessage)}</span>
        </div>
      </div>

      <dl class="fleet-stat-list">
        <div><dt>Hosts</dt><dd>${reports.length}</dd></div>
        <div><dt>OK</dt><dd>${okHosts}</dd></div>
        <div><dt>Watch</dt><dd>${watchHosts}</dd></div>
        <div><dt>Attention</dt><dd>${attentionHosts}</dd></div>
        <div><dt>Reboots</dt><dd>${reboots}</dd></div>
      </dl>
    </div>
  `;
}

function renderFleet() {
  const reports = state.reports;
  const unifiSelected = state.unifi && state.selectedHost === UNIFI_NODE_ID;

  if (
    !state.selectedHost ||
    (!unifiSelected && !reports.some((report) => report.host === state.selectedHost))
  ) {
    state.selectedHost = reports[0]?.host || null;
  }

  renderFleetTree(reports);
  if (state.unifi && state.selectedHost === UNIFI_NODE_ID) {
    renderUnifiInspector(state.unifi);
  } else {
    renderInspector(
      reports.find((report) => report.host === state.selectedHost) || null,
    );
  }
}

// ---------------------------------------------------------------------------
// CHAPTER 13.7 — Generic schema-driven metrics and detail sections
// ---------------------------------------------------------------------------
// Prefer adding data through schema display types over adding host-specific UI.
// Specialized renderers below exist only where storage evidence needs context.

function groupByCategory(items) {
  const groups = new Map();

  for (const item of items || []) {
    const category = String(item.category || "other");

    if (!groups.has(category)) {
      groups.set(category, []);
    }

    groups.get(category).push(item);
  }

  return groups;
}

function renderGauge(metric) {
  const value = Number(metric.value);
  const minimum = Number(metric.min ?? 0);
  const maximum = Number(
    metric.max ?? (metric.unit === "%" ? 100 : 100),
  );

  if (!Number.isFinite(value)) {
    return "";
  }

  return `
    <meter min="${minimum}" max="${maximum}" value="${value}">
      ${escapeHtml(metricDisplayValue(metric))}
    </meter>
  `;
}

function renderMetric(metric) {
  const status = healthStatusName(metric.status);

  return `
    <article class="metric-detail">
      <div class="metric-detail-header">
        <h4>${escapeHtml(metric.label || metric.id)}</h4>
        <span class="${healthStatusClass(status)}">
          ${escapeHtml(status)}
        </span>
      </div>
      <div class="metric-value">
        ${escapeHtml(metricDisplayValue(metric))}
      </div>
      ${metric.display === "gauge" ? renderGauge(metric) : ""}
    </article>
  `;
}

function humanizeKey(value) {
  return String(value)
    .replaceAll("_", " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}

function statusSortedItems(items) {
  return [...items]
    .map((item, index) => ({item, index}))
    .sort((left, right) => {
      const leftStatus = healthStatusName(left.item?.status);
      const rightStatus = healthStatusName(right.item?.status);
      const severityDifference =
        healthSeverityOrder[leftStatus] - healthSeverityOrder[rightStatus];

      return severityDifference || left.index - right.index;
    })
    .map(({item}) => item);
}

function renderStructuredValue(value, key = "") {
  if (value === null || value === undefined || value === "") {
    return '<span class="muted">—</span>';
  }

  if (key === "status") {
    const status = healthStatusName(value);

    return `
      <span class="status-badge ${healthStatusClass(status)}">
        ${escapeHtml(status)}
      </span>
    `;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return '<span class="muted">None</span>';
    }

    if (value.every((item) => item && typeof item === "object")) {
      return renderGenericTable(statusSortedItems(value));
    }

    return `
      <ul class="structured-list">
        ${value
          .map((item) => `<li>${renderStructuredValue(item)}</li>`)
          .join("")}
      </ul>
    `;
  }

  if (typeof value === "object") {
    const entries = Object.entries(value);

    if (entries.length === 0) {
      return '<span class="muted">None</span>';
    }

    return `
      <dl class="structured-details">
        ${entries
          .map(
            ([entryKey, entryValue]) => `
              <div>
                <dt>${escapeHtml(humanizeKey(entryKey))}</dt>
                <dd>${renderStructuredValue(entryValue, entryKey)}</dd>
              </div>
            `,
          )
          .join("")}
      </dl>
    `;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return escapeHtml(value);
}

function renderGenericTable(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return '<p class="muted">No items.</p>';
  }

  if (!items.every((item) => item && typeof item === "object")) {
    return `
      <ul>
        ${items
          .map((item) => `<li>${escapeHtml(item)}</li>`)
          .join("")}
      </ul>
    `;
  }

  const columns = [
    ...new Set(items.flatMap((item) => Object.keys(item))),
  ];

  return `
    <div class="table-scroll">
      <table class="generic-table">
        <thead>
          <tr>
            ${columns
              .map((column) => `<th>${escapeHtml(humanizeKey(column))}</th>`)
              .join("")}
          </tr>
        </thead>
        <tbody>
          ${items
            .map(
              (item) => `
                <tr>
                  ${columns
                    .map(
                      (column) => `
                        <td>${renderStructuredValue(item[column], column)}</td>
                      `,
                    )
                    .join("")}
                </tr>
              `,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// CHAPTER 13.8 — SMART, ZFS, PBS, and live physical-storage presentation
// ---------------------------------------------------------------------------
// These functions explain evidence produced by storage_health.py. They display
// status and relationships but do not recalculate the monitoring decision.

function smartAttribute(device, name) {
  return device.attributes?.[name] ?? 0;
}

function smartDisplayValue(value, suffix = "") {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  return `${value}${suffix}`;
}

function smartCounterHistory(device, name) {
  return device.history?.attributes?.[name] || null;
}

function smartEvidenceFor(device, attribute) {
  return (device.evidence || []).filter(
    (item) => !attribute || item.attribute === attribute,
  );
}

function smartFactClass(device, attribute) {
  const evidence = smartEvidenceFor(device, attribute);

  if (evidence.some((item) => item.confirmed && item.level === "critical")) {
    return "smart-fact-critical";
  }
  if (evidence.some((item) => item.confirmed && item.level === "warning")) {
    return "smart-fact-warning";
  }
  if (evidence.some((item) => item.level === "watch")) {
    return "smart-fact-watch";
  }
  if (evidence.length > 0) {
    return "smart-fact-uncertain";
  }
  return "";
}

function renderCounterChange(device, attribute) {
  const history = smartCounterHistory(device, attribute);

  if (!history) {
    return "";
  }
  if (history.previous === null || history.previous === undefined) {
    return '<span class="smart-counter-change trend-baseline">Baseline captured</span>';
  }

  const change = numberValue(history.change);
  const signed = change > 0 ? `+${change}` : String(change);
  const firstNonzero = history.first_nonzero_at
    ? ` · First nonzero ${formatDate(history.first_nonzero_at)}`
    : "";
  return `
    <span class="smart-counter-change trend-${escapeHtml(history.trend || "stable")}">
      Previous ${escapeHtml(history.previous)} · Change ${escapeHtml(signed)}${escapeHtml(firstNonzero)}
    </span>
  `;
}

function renderSmartObservationHistory(device) {
  const history = device.history || {};
  const parts = [];

  if (history.first_observed_at) {
    parts.push(`First observed ${formatDate(history.first_observed_at)}`);
  }
  if (history.previous_observed_at) {
    parts.push(`Previous sample ${formatDate(history.previous_observed_at)}`);
  }
  if (history.last_observed_at) {
    parts.push(`Current sample ${formatDate(history.last_observed_at)}`);
  }

  return parts.length > 0
    ? `<p class="smart-observation-history">${parts.map(escapeHtml).join(" · ")}</p>`
    : "";
}

function renderSmartFact(device, label, value, attribute = null) {
  return `
    <div class="${attribute ? smartFactClass(device, attribute) : ""}">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value)}</dd>
      ${attribute ? renderCounterChange(device, attribute) : ""}
    </div>
  `;
}

function renderSmartEvidence(device) {
  const evidence = Array.isArray(device.evidence) ? device.evidence : [];
  const confirmed = evidence.filter((item) => item.confirmed);
  const reported = evidence.filter((item) => !item.confirmed);
  const confidence = device.interpretation || {level: "unknown", reasons: []};

  return `
    <section class="smart-evidence-panel">
      <div class="smart-evidence-heading">
        <strong>Current evidence</strong>
        <span class="confidence-badge confidence-${escapeHtml(confidence.level)}">
          ${escapeHtml(confidence.level)} confidence
        </span>
      </div>

      ${
        confirmed.length > 0
          ? `
            <div class="evidence-group evidence-confirmed">
              <span>Confirmed</span>
              <ul>${confirmed.map((item) => `<li>${escapeHtml(item.message)}</li>`).join("")}</ul>
            </div>
          `
          : '<p class="evidence-clear">No direct failure evidence was collected in this run.</p>'
      }

      ${
        reported.length > 0
          ? `
            <div class="evidence-group evidence-reported">
              <span>Reported, interpretation uncertain</span>
              <ul>${reported.map((item) => `<li>${escapeHtml(item.message)}</li>`).join("")}</ul>
            </div>
          `
          : ""
      }

      ${
        Array.isArray(confidence.reasons) && confidence.reasons.length > 0
          ? `
            <details class="confidence-explanation">
              <summary>Why ${escapeHtml(confidence.level)} confidence?</summary>
              <ul>${confidence.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
            </details>
          `
          : ""
      }
    </section>
  `;
}

function renderSmartTopology(device) {
  const topology = device.topology || {};
  const proxmox = topology.proxmox || {};
  const consumer = topology.consumer || {};
  const zfs = topology.zfs || {};
  const isLive = topology.source === "proxmox_qemu_guest_agent";
  const stages = [
    {
      label: "Physical",
      value: `${device.device || "Unknown"} · ${device.serial || "unknown serial"}`,
    },
    proxmox.slot
      ? {
          label: "Proxmox passthrough",
          value: `${proxmox.vm_name || `VM ${proxmox.vm_id}`} · ${proxmox.slot}`,
        }
      : null,
    consumer.device
      ? {
          label: "TrueNAS consumer",
          value: `${consumer.host || "Guest"} · ${consumer.device}${consumer.member ? ` → ${consumer.member}` : ""}`,
        }
      : null,
    zfs.pool
      ? {
          label: "ZFS membership",
          value: `${zfs.pool} · ${zfs.vdev || "unknown vdev"} · ${zfs.member || "unknown member"}`,
        }
      : null,
  ].filter(Boolean);

  if (stages.length === 1) {
    return `
      <p class="smart-topology-missing">
        No live Proxmox consumer was discovered for this serial.
      </p>
    `;
  }

  return `
    <section class="smart-topology">
      <strong>Storage path</strong>
      <div class="smart-topology-flow">
        ${stages.map((stage) => `
          <div>
            <span>${escapeHtml(stage.label)}</span>
            <b>${escapeHtml(stage.value)}</b>
          </div>
        `).join("")}
      </div>
      ${
        isLive
          ? `<p class="storage-topology-source">Live via Proxmox QEMU Guest Agent${topology.observed_at ? ` · confirmed ${escapeHtml(formatDate(topology.observed_at))}` : ""}</p>`
          : zfs.pool
          ? '<p class="storage-topology-source">Fallback inventory mapping; live guest confirmation is unavailable.</p>'
          : ""
      }
    </section>
  `;
}

function renderKernelEvidence(device) {
  const kernel = device.kernel_evidence || {};

  if (numberValue(kernel.event_count) === 0) {
    return '<p class="kernel-evidence-clear">Kernel evidence: no matching storage errors in the configured lookback.</p>';
  }

  return `
    <details class="kernel-evidence kernel-evidence-${escapeHtml(kernel.severity)}">
      <summary>${escapeHtml(kernel.event_count)} recent kernel event(s)</summary>
      <ul>${(kernel.samples || []).map((line) => `<li><code>${escapeHtml(line)}</code></li>`).join("")}</ul>
    </details>
  `;
}

function smartStatusContext(device) {
  const status = healthStatusName(device.status);
  const evidence = Array.isArray(device.evidence) ? device.evidence : [];
  const confidence = device.interpretation?.level || "unknown";
  const hasUncertainEvidence =
    confidence === "low" || evidence.some((item) => !item.confirmed);
  const hasConfirmedIssue = evidence.some(
    (item) =>
      item.confirmed && ["warning", "critical"].includes(item.level),
  );

  if (status === "WATCH") {
    return hasUncertainEvidence
      ? {label: "Uncertain data", kind: "uncertain"}
      : {label: "Stable", kind: "stable"};
  }

  if (status === "WARNING" && hasConfirmedIssue) {
    return {label: "Confirmed issue", kind: "confirmed"};
  }

  return null;
}

function renderSmartDeviceCards(devices) {
  if (!Array.isArray(devices) || devices.length === 0) {
    return '<p class="muted">No drives in this group.</p>';
  }

  return `
    <div class="smart-drive-grid">
      ${devices
        .map((device) => {
          const status = healthStatusName(device.status);
          const statusContext = smartStatusContext(device);
          const offline = smartAttribute(device, "offline_uncorrectable");
          const reported = smartAttribute(device, "reported_uncorrectable");
          const reallocatedSectors = smartAttribute(
            device,
            "reallocated_sectors",
          );
          const reallocationEvents = smartAttribute(
            device,
            "reallocated_events",
          );
          const pendingSectors = smartAttribute(device, "pending_sectors");
          const crcErrors = smartAttribute(device, "interface_crc_errors");
          const selfTest = device.latest_self_test?.status || "Not available";

          return `
            <article class="smart-drive-card ${healthStatusClass(status)}">
              <div class="smart-drive-header">
                <div>
                  <strong>${escapeHtml(device.device || "Unknown device")}</strong>
                  <span>${escapeHtml(device.model || "Unknown model")}</span>
                </div>
                <div
                  class="smart-status-summary"
                  ${statusContext ? `aria-label="${escapeHtml(status)} — ${escapeHtml(statusContext.label)}"` : ""}
                >
                  <span class="status-badge ${healthStatusClass(status)}">
                    ${escapeHtml(status)}
                  </span>
                  ${
                    statusContext
                      ? `<span class="smart-status-reason smart-status-reason-${escapeHtml(statusContext.kind)}">${escapeHtml(statusContext.label)}</span>`
                      : ""
                  }
                </div>
              </div>

              <div class="smart-drive-identity">
                <span>Serial <code>${escapeHtml(device.serial || "Unknown")}</code></span>
                <span>Firmware <code>${escapeHtml(device.firmware || "Unknown")}</code></span>
              </div>
              ${renderSmartObservationHistory(device)}

              ${renderSmartEvidence(device)}
              ${renderSmartTopology(device)}
              ${renderKernelEvidence(device)}

              <dl class="smart-drive-facts">
                ${renderSmartFact(
                  device,
                  "SMART overall",
                  device.smart_passed === true ? "Passed" :
                    device.smart_passed === false ? "Failed" : "Unknown",
                )}
                ${renderSmartFact(device, "Temperature", smartDisplayValue(device.temperature_c, " °C"))}
                ${renderSmartFact(device, "Power-on hours", smartDisplayValue(device.power_on_hours))}
                ${renderSmartFact(device, "Pending sectors", pendingSectors, "pending_sectors")}
                ${renderSmartFact(device, "Reallocated sectors", reallocatedSectors, "reallocated_sectors")}
                ${renderSmartFact(device, "Reallocation events", reallocationEvents, "reallocated_events")}
                ${renderSmartFact(device, "Offline uncorrectable", offline, "offline_uncorrectable")}
                ${renderSmartFact(device, "Reported uncorrectable", reported, "reported_uncorrectable")}
                ${renderSmartFact(device, "CRC errors", crcErrors, "interface_crc_errors")}
                ${renderSmartFact(device, "Latest self-test", selfTest)}
              </dl>
            </article>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderSmartModuleDetails(details) {
  const devices = statusSortedItems(details.devices || []);
  const attention = devices.filter(
    (device) => ["CRITICAL", "WARNING", "UNKNOWN"].includes(
      healthStatusName(device.status),
    ),
  );
  const watches = devices.filter(
    (device) => healthStatusName(device.status) === "WATCH",
  );
  const healthy = devices.filter(
    (device) => healthStatusName(device.status) === "OK",
  );
  const activeFindings = devices.filter((device) =>
    (device.evidence || []).some(
      (item) => item.active === true || ["warning", "critical"].includes(item.level),
    ),
  );
  const kernelEvents = devices.reduce(
    (total, device) => total + numberValue(device.kernel_evidence?.event_count),
    0,
  );

  return `
    <div class="smart-overview">
      <div>
        <span>Drives detected</span>
        <strong>${escapeHtml(devices.length)}</strong>
      </div>
      <div class="${attention.length > 0 ? "smart-attention" : ""}">
        <span>Need review</span>
        <strong>${escapeHtml(attention.length)}</strong>
      </div>
      <div class="${activeFindings.length > 0 ? "smart-active" : ""}">
        <span>Active findings</span>
        <strong>${escapeHtml(activeFindings.length)}</strong>
      </div>
      <div class="${watches.length > 0 ? "smart-watch" : ""}">
        <span>Under watch</span>
        <strong>${escapeHtml(watches.length)}</strong>
      </div>
      <div class="${kernelEvents > 0 ? "smart-active" : ""}">
        <span>Recent kernel events</span>
        <strong>${escapeHtml(kernelEvents)}</strong>
      </div>
    </div>

    ${
      attention.length > 0
        ? `
          <section class="smart-drive-group">
            <h6>Drives needing review</h6>
            ${renderSmartDeviceCards(attention)}
          </section>
        `
        : '<p class="muted">No SMART warnings or unavailable devices were detected.</p>'
    }

    ${
      watches.length > 0
        ? `
          <section class="smart-drive-group smart-watch-group">
            <h6>Drives under watch</h6>
            <p class="muted compact-note">Stable or historical evidence is visible below; no active deterioration was detected.</p>
            ${renderSmartDeviceCards(watches)}
          </section>
        `
        : ""
    }

    ${
      healthy.length > 0
        ? `
          <details class="smart-healthy-drives">
            <summary>Show ${escapeHtml(healthy.length)} healthy drive(s)</summary>
            ${renderSmartDeviceCards(healthy)}
          </details>
        `
        : ""
    }
  `;
}

function byteSize(value) {
  const bytes = Number(value);

  if (!Number.isFinite(bytes) || bytes < 0) {
    return "Unknown";
  }

  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let size = bytes;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }

  const rounded = size >= 100 ? Math.round(size) : Math.round(size * 10) / 10;
  return `${rounded} ${units[unit]}`;
}

function storageTopologyGuests(host) {
  const expected = String(host || "").toLowerCase();

  return (state.storageTopology.hosts || []).flatMap((proxmox) =>
    (proxmox.guests || [])
      .filter((guest) => String(guest.vm_name || "").toLowerCase() === expected)
      .map((guest) => ({
        ...guest,
        proxmox_host: proxmox.proxmox_host,
        observed_at: proxmox.observed_at,
        topology_source: proxmox.source,
      })),
  );
}

function renderZfsPhysicalTopology(poolName, report) {
  const matches = storageTopologyGuests(report?.host)
    .map((guest) => ({
      guest,
      pool: (guest.pools || []).find((pool) => pool.name === poolName),
    }))
    .filter((item) => item.pool);

  if (matches.length === 0) {
    return "";
  }

  return matches
    .map(({guest, pool}) => {
      const memberCount = (pool.vdevs || []).reduce(
        (total, vdev) => total + (vdev.members || []).length,
        0,
      );
      return `
        <details class="zfs-physical-topology">
          <summary>
            <span>Physical layout</span>
            <span>${escapeHtml(memberCount)} ${memberCount === 1 ? "member" : "members"}</span>
          </summary>
          <div class="zfs-vdev-list">
            ${(pool.vdevs || [])
              .map(
                (vdev) => `
                  <section class="zfs-vdev-group">
                    <div class="zfs-vdev-heading">
                      <strong>${escapeHtml(vdev.name || "direct")}</strong>
                      <span>${escapeHtml(vdev.class || "data")} · ${escapeHtml(vdev.state || "UNKNOWN")}</span>
                    </div>
                    <div class="zfs-member-list">
                      ${(vdev.members || [])
                        .map((member) => {
                          const physical = member.trace_status === "physical";
                          const virtual = member.trace_status === "virtual";
                          const smartStatus = physical
                            ? healthStatusName(member.smart_status)
                            : member.member_state === "ONLINE"
                            ? "OK"
                            : "UNKNOWN";
                          const physicalLabel = physical
                            ? `${guest.proxmox_host || "Proxmox"} · ${member.host_device || member.source_path || "physical disk"} · ${member.slot || "unknown slot"}`
                            : virtual
                            ? `Virtual VM disk · ${member.slot || "unknown slot"}`
                            : "Physical source unresolved";
                          return `
                            <div class="zfs-member-row">
                              <span class="status-dot ${healthStatusClass(smartStatus)}" aria-label="${escapeHtml(smartStatus)}"></span>
                              <div>
                                <strong>${escapeHtml(member.guest_member || member.member || "Unknown member")}</strong>
                                <span>${escapeHtml(physicalLabel)}</span>
                              </div>
                              <div class="zfs-member-identity">
                                <span>${escapeHtml(member.physical_serial || (virtual ? "virtual" : "unresolved"))}</span>
                                ${physical ? `<span class="status-badge ${healthStatusClass(smartStatus)}">SMART ${escapeHtml(smartStatus)}</span>` : ""}
                              </div>
                            </div>
                          `;
                        })
                        .join("")}
                    </div>
                  </section>
                `,
              )
              .join("")}
          </div>
          <p class="storage-topology-source">
            Live via ${escapeHtml(guest.proxmox_host || "Proxmox")} QEMU Guest Agent${guest.observed_at ? ` · confirmed ${escapeHtml(formatDate(guest.observed_at))}` : ""}
          </p>
        </details>
      `;
    })
    .join("");
}

function renderZfsModuleDetails(details, report = null) {
  const pools = Array.isArray(details.pools) ? details.pools : [];
  const scans = Array.isArray(details.scans) ? details.scans : [];
  const attention = Array.isArray(details.devices_requiring_attention)
    ? details.devices_requiring_attention
    : [];

  return `
    <div class="zfs-pool-grid">
      ${pools
        .map((pool) => {
          const health = healthStatusName(
            pool.health === "ONLINE" ? "OK" : "CRITICAL",
          );
          const scan = scans.find((item) => item.pool === pool.name);

          return `
            <article class="zfs-pool-card ${healthStatusClass(health)}">
              <div class="zfs-pool-header">
                <strong>${escapeHtml(pool.name || "Unknown pool")}</strong>
                <span class="status-badge ${healthStatusClass(health)}">
                  ${escapeHtml(pool.health || "UNKNOWN")}
                </span>
              </div>
              <dl class="zfs-pool-facts">
                <div>
                  <dt>Capacity used</dt>
                  <dd>${escapeHtml(
                    smartDisplayValue(pool.capacity_percent, "%"),
                  )}</dd>
                </div>
                <div>
                  <dt>Allocated</dt>
                  <dd>${escapeHtml(byteSize(pool.allocated_bytes))}</dd>
                </div>
                <div>
                  <dt>Free</dt>
                  <dd>${escapeHtml(byteSize(pool.free_bytes))}</dd>
                </div>
                <div>
                  <dt>Pool size</dt>
                  <dd>${escapeHtml(byteSize(pool.size_bytes))}</dd>
                </div>
              </dl>
              <p class="zfs-scan-status">
                <strong>Scrub / resilver:</strong>
                ${escapeHtml(scan?.status || "No scan information available")}
              </p>
              ${renderZfsPhysicalTopology(pool.name, report)}
            </article>
          `;
        })
        .join("")}
    </div>

    ${
      attention.length > 0
        ? `
          <section class="zfs-attention">
            <h6>Devices requiring attention</h6>
            ${renderGenericTable(attention)}
          </section>
        `
        : ""
    }
  `;
}

function renderPbsModuleDetails(details) {
  const datastores = Array.isArray(details.datastores)
    ? details.datastores
    : [];
  const versions = Array.isArray(details.versions) ? details.versions : [];

  return `
    <div class="pbs-datastore-grid">
      ${
        datastores.length > 0
          ? datastores
              .map((datastore) => {
                const status = healthStatusName(datastore.status);
                return `
                  <article class="pbs-datastore-card ${healthStatusClass(status)}">
                    <div class="pbs-datastore-header">
                      <div>
                        <strong>${escapeHtml(datastore.name || "Unknown datastore")}</strong>
                        <span>${escapeHtml(datastore.path || "Unknown path")}</span>
                      </div>
                      <span class="status-badge ${healthStatusClass(status)}">${escapeHtml(status)}</span>
                    </div>
                    <dl class="zfs-pool-facts">
                      <div><dt>Capacity used</dt><dd>${escapeHtml(smartDisplayValue(datastore.capacity_percent, "%"))}</dd></div>
                      <div><dt>Filesystem size</dt><dd>${escapeHtml(byteSize(numberValue(datastore.size_kib) * 1024))}</dd></div>
                      <div><dt>Available</dt><dd>${escapeHtml(byteSize(numberValue(datastore.available_kib) * 1024))}</dd></div>
                      <div><dt>Mounted at</dt><dd>${escapeHtml(datastore.mountpoint || "Unknown")}</dd></div>
                    </dl>
                  </article>
                `;
              })
              .join("")
          : '<p class="muted">No PBS datastore measurements were returned.</p>'
      }
    </div>
    <details class="pbs-version-details">
      <summary>Component versions</summary>
      ${renderStructuredValue(versions)}
    </details>
  `;
}

const moduleDisplayRegistry = {
  smart: {
    category: "storage",
    renderDetails: renderSmartModuleDetails,
  },
  zfs: {
    category: "storage",
    renderDetails: renderZfsModuleDetails,
  },
  pbs: {
    category: "backup",
    renderDetails: renderPbsModuleDetails,
  },
  docker: {category: "docker"},
  proxmox: {category: "proxmox"},
};

function moduleCategory(result) {
  return result.category ||
    moduleDisplayRegistry[result.check]?.category ||
    "health";
}

function renderModuleResults(items, report = null) {
  if (!Array.isArray(items) || items.length === 0) {
    return '<p class="muted">No monitoring module results.</p>';
  }

  return `
    <div class="module-result-list">
      ${statusSortedItems(items)
        .map((result) => {
          const status = healthStatusName(result.status);
          const renderer = moduleDisplayRegistry[result.check]?.renderDetails;

          return `
            <article class="module-result ${healthStatusClass(status)}">
              <div class="module-result-header">
                <h5>${escapeHtml(humanizeKey(result.check || "module"))}</h5>
                <span class="status-badge ${healthStatusClass(status)}">
                  ${escapeHtml(status)}
                </span>
              </div>
              <p>${escapeHtml(result.summary || "No summary provided.")}</p>
              <div class="module-result-details">
                ${
                  renderer
                    ? renderer(result.details || {}, report)
                    : renderStructuredValue(result.details || {})
                }
              </div>
            </article>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderSection(section, report = null) {
  let body;

  if (
    section.display === "module-results" ||
    section.id === "monitoring_modules"
  ) {
    return renderModuleResults(section.items || [], report);
  } else if (section.display === "list" || section.display === "table") {
    body = renderGenericTable(section.items || []);
  } else if (section.display === "preformatted") {
    body = `<pre>${escapeHtml(section.content || "")}</pre>`;
  } else if (section.content !== undefined) {
    body = `<p>${escapeHtml(section.content)}</p>`;
  } else {
    body = `<pre>${escapeHtml(JSON.stringify(section, null, 2))}</pre>`;
  }

  return `
    <article class="section-card">
      <h4>${escapeHtml(section.label || section.id)}</h4>
      ${body}
    </article>
  `;
}

const detailCategoryOrder = {
  health: 0,
  storage: 10,
  backup: 15,
  resources: 20,
  maintenance: 30,
  services: 40,
  docker: 50,
  proxmox: 60,
  technical: 90,
};

function detailCategoryNeedsAttention(group) {
  const metricWarning = group.metrics.some(
    (metric) => healthStatusName(metric.status) !== "OK",
  );
  const sectionWarning = group.sections.some((section) =>
    (section.items || []).some(
      (item) => item?.status && healthStatusName(item.status) !== "OK",
    ),
  );

  return metricWarning || sectionWarning;
}

function renderDetailCategories(report) {
  const groups = new Map();

  function categoryGroup(category) {
    const normalized = String(category || "other");

    if (!groups.has(normalized)) {
      groups.set(normalized, {
        category: normalized,
        metrics: [],
        sections: [],
        maintenanceHistory: false,
      });
    }

    return groups.get(normalized);
  }

  for (const metric of report.metrics || []) {
    categoryGroup(metric.category).metrics.push(metric);
  }

  for (const section of report.sections || []) {
    if (section.id === "monitoring_modules") {
      for (const result of section.items || []) {
        categoryGroup(moduleCategory(result)).sections.push({
          ...section,
          id: `monitoring_module_${result.check || "unknown"}`,
          label: `${humanizeKey(result.check || "module")} monitoring`,
          display: "module-results",
          items: [result],
        });
      }
    } else {
      categoryGroup(section.category).sections.push(section);
    }
  }

  categoryGroup("maintenance").maintenanceHistory = true;

  return [...groups.values()]
    .sort((left, right) => {
      const leftOrder = detailCategoryOrder[left.category] ?? 999;
      const rightOrder = detailCategoryOrder[right.category] ?? 999;

      return leftOrder - rightOrder ||
        left.category.localeCompare(right.category);
    })
    .map((group) => {
      group.metrics.sort(
        (left, right) => metricOrder(left) - metricOrder(right),
      );
      group.sections.sort(
        (left, right) =>
          Number(left.order ?? 9999) - Number(right.order ?? 9999),
      );

      const needsAttention = detailCategoryNeedsAttention(group);
      const itemCount =
        group.metrics.length +
        group.sections.length +
        (group.maintenanceHistory ? 1 : 0);

      return `
        <details
          class="category-block detail-category ${
            needsAttention ? "detail-category-attention" : ""
          }"
          ${needsAttention ? "open" : ""}
        >
          <summary>
            <span>${escapeHtml(humanizeKey(group.category))}</span>
            <span class="category-count">
              ${escapeHtml(itemCount)} ${itemCount === 1 ? "item" : "items"}
            </span>
          </summary>
          <div class="detail-category-body">
            ${
              group.metrics.length > 0
                ? `
                  <div class="metric-detail-grid">
                    ${group.metrics.map(renderMetric).join("")}
                  </div>
                `
                : ""
            }
            ${group.sections.map((section) => renderSection(section, report)).join("")}
            ${group.maintenanceHistory ? renderMaintenanceHistory(report) : ""}
          </div>
        </details>
      `;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// CHAPTER 13.9 — Controlled-maintenance history and phase explanations
// ---------------------------------------------------------------------------
// Maintenance history is server-written evidence. Phase rendering distinguishes
// installation success from a later report-refresh failure.

function phaseLabel(value) {
  const labels = {
    installation: "Package installation",
    report_refresh: "Health and report refresh",
  };

  return labels[value] || humanizeKey(value || "phase");
}

function phaseStateLabel(value) {
  const labels = {
    success: "Successful",
    failed: "Failed",
    timed_out: "Timed out",
    could_not_start: "Could not start",
  };

  return labels[value] || humanizeKey(value || "unknown");
}

function renderMaintenancePhase(phase) {
  const output = Array.isArray(phase.output_tail)
    ? phase.output_tail.join("\n")
    : "No output was captured.";

  return `
    <section class="maintenance-phase">
      <div class="maintenance-phase-heading">
        <strong>${escapeHtml(phaseLabel(phase.name))}</strong>
        <span class="maintenance-phase-${escapeHtml(phase.state || "unknown")}">
          ${escapeHtml(phaseStateLabel(phase.state))}
        </span>
      </div>
      <p class="muted">
        ${escapeHtml(formatDuration(phase.duration_seconds))} ·
        return code ${escapeHtml(phase.return_code ?? "none")}
      </p>
      <details class="maintenance-log">
        <summary>View captured output</summary>
        <pre>${escapeHtml(output)}</pre>
      </details>
    </section>
  `;
}

function renderMaintenanceRun(run, index) {
  const result = maintenanceResult(run);
  const packages = Array.isArray(run.approved_packages)
    ? run.approved_packages
    : [];
  const finalReport = run.final_report || null;

  return `
    <details class="maintenance-run" ${index === 0 ? "open" : ""}>
      <summary>
        <span>${escapeHtml(formatDate(run.finished_at))}</span>
        <strong class="${escapeHtml(result.className)}">
          ${escapeHtml(result.label)}
        </strong>
      </summary>
      <div class="maintenance-run-body">
        <dl class="maintenance-facts">
          <div>
            <dt>Started</dt>
            <dd>${escapeHtml(formatDate(run.started_at))}</dd>
          </div>
          <div>
            <dt>Duration</dt>
            <dd>${escapeHtml(formatDuration(run.duration_seconds))}</dd>
          </div>
          <div>
            <dt>Approved package set</dt>
            <dd>${escapeHtml(run.approved_package_count ?? packages.length)}</dd>
          </div>
          <div>
            <dt>Automatic reboot</dt>
            <dd>${run.automatic_reboot === true ? "Yes" : "No"}</dd>
          </div>
          <div>
            <dt>Final health</dt>
            <dd>${escapeHtml(finalReport?.health_status ?? "Not refreshed")}</dd>
          </div>
          <div>
            <dt>Security updates remaining</dt>
            <dd>${escapeHtml(
              finalReport?.security_updates_available ?? "Not refreshed",
            )}</dd>
          </div>
          <div>
            <dt>Reboot required afterward</dt>
            <dd>${
              finalReport === null
                ? "Not refreshed"
                : finalReport.reboot_required === true
                ? "Yes"
                : "No"
            }</dd>
          </div>
        </dl>

        <p class="maintenance-message">${escapeHtml(run.message || "")}</p>

        <details class="approved-packages">
          <summary>
            View approved package set (${escapeHtml(packages.length)})
          </summary>
          ${
            packages.length > 0
              ? `<ul>${packages
                  .map((name) => `<li><code>${escapeHtml(name)}</code></li>`)
                  .join("")}</ul>`
              : '<p class="muted">No cached package names were available.</p>'
          }
        </details>

        <div class="maintenance-phases">
          ${(run.phases || []).map(renderMaintenancePhase).join("")}
        </div>
      </div>
    </details>
  `;
}

function renderMaintenanceHistory(report) {
  const history = report.maintenance_history;
  const runs = Array.isArray(history?.runs) ? history.runs : [];

  return `
    <section class="section-card maintenance-history">
      <h4>Security maintenance history</h4>
      ${
        runs.length > 0
          ? runs.map(renderMaintenanceRun).join("")
          : `
            <p class="muted">
              No dashboard-triggered security update has been recorded yet.
              History begins with the next update run after this feature is installed.
            </p>
          `
      }
    </section>
  `;
}

function openHostDetails(host) {
  const report = state.reports.find((item) => item.host === host);

  if (!report) {
    return;
  }

  const healthStatus = healthStatusName(
    report.health_status || report.status,
  );
  const patchStatus = patchStatusName(report.patch_posture_status);

  dialogTitle.textContent = report.host;
  dialogContent.innerHTML = `
    ${renderActionGuidance(report)}

    <div class="detail-summary">
      <div class="dialog-status-grid">
        <section>
          <span class="panel-label">Health</span>
          <span class="status-badge ${healthStatusClass(healthStatus)}">
            ${escapeHtml(healthStatus)}
          </span>
          ${reasonMarkup(
            report.health_status_reasons || report.status_reasons,
            "No active health reasons.",
          )}
        </section>

        <section>
          <span class="panel-label">Patch posture</span>
          <span class="patch-badge ${patchStatusClass(patchStatus)}">
            ${escapeHtml(patchStatusLabel(patchStatus))}
          </span>
          ${reasonMarkup(
            report.patch_status_reasons,
            "No active patch reasons.",
            "patch-reasons",
          )}
        </section>
      </div>

      <div class="detail-actions">
        <p class="detail-policy">
          ${escapeHtml(patchPolicyLabel(report))}
        </p>
        <p class="muted">
          Generated ${escapeHtml(formatDate(report.generated_at))}
        </p>
        <a
          class="report-link"
          href="${encodeURIComponent(report.host)}.md"
          target="_blank"
          rel="noopener"
        >
          Open Markdown report
        </a>
      </div>
    </div>

    ${renderDetailCategories(report)}
  `;

  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
}

// ---------------------------------------------------------------------------
// CHAPTER 13.10 — Data loading, graceful degradation, and refresh cycle
// ---------------------------------------------------------------------------
// The manifest is mandatory. Individual host reports degrade to UNKNOWN.
// Topology/storage/UniFi are optional enrichments and have distinct fallbacks.

async function loadMaintenanceHistory(host) {
  try {
    const response = await fetch(
      `maintenance/${encodeURIComponent(host)}.json`,
      {cache: "no-store"},
    );

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    return null;
  }
}

async function loadReport(entry) {
  try {
    const [response, maintenanceHistory] = await Promise.all([
      fetch(entry.report, {cache: "no-store"}),
      loadMaintenanceHistory(entry.id),
    ]);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const report = await response.json();
    return {
      ...report,
      host: report.host || entry.id,
      maintenance_history: maintenanceHistory,
      dashboard_manifest: entry,
    };
  } catch (error) {
    return {
      schema_version: 3,
      report_type: "host_health",
      host: entry.id,
      generated_at: null,
      status: "UNKNOWN",
      health_status: "UNKNOWN",
      health_status_reasons: [
        `Report could not be loaded: ${error.message}`,
      ],
      status_reasons: [
        `Report could not be loaded: ${error.message}`,
      ],
      patch_posture_status: "UNKNOWN",
      patch_status_reasons: ["Patch data unavailable"],
      patch_counts_trusted: false,
      package_metadata_status: "UNKNOWN",
      metrics: [],
      sections: [],
      dashboard_manifest: entry,
    };
  }
}

function reportSort(left, right) {
  const leftHealth = healthStatusName(left.health_status || left.status);
  const rightHealth = healthStatusName(right.health_status || right.status);
  const healthDifference =
    healthSeverityOrder[leftHealth] - healthSeverityOrder[rightHealth];

  if (healthDifference !== 0) {
    return healthDifference;
  }

  const patchDifference =
    patchSeverityOrder[patchStatusName(left.patch_posture_status)] -
    patchSeverityOrder[patchStatusName(right.patch_posture_status)];

  return (
    patchDifference ||
    String(left.host).localeCompare(String(right.host))
  );
}

async function loadTopology() {
  try {
    const response = await fetch(
      "assets/dashboard-topology.json",
      {cache: "no-store"},
    );

    if (!response.ok) {
      return {datacenter_label: "Datacenter", nodes: {}};
    }

    const topology = await response.json();
    return {
      datacenter_label: topology.datacenter_label || "Datacenter",
      nodes:
        topology.nodes && typeof topology.nodes === "object"
          ? topology.nodes
          : {},
    };
  } catch (error) {
    return {datacenter_label: "Datacenter", nodes: {}};
  }
}

async function loadStorageTopology() {
  try {
    const response = await fetch("storage-topology.json", {cache: "no-store"});

    if (!response.ok) {
      return {hosts: []};
    }

    const topology = await response.json();
    return {
      generated_at: topology.generated_at || null,
      hosts: Array.isArray(topology.hosts) ? topology.hosts : [],
    };
  } catch (error) {
    return {hosts: []};
  }
}

async function loadUnifiSummary() {
  try {
    const response = await fetch("api/unifi/summary", {cache: "no-store"});

    if (response.status === 404) {
      return null;
    }

    const payload = await response.json();
    return payload.integration === "unifi" ? payload : null;
  } catch (error) {
    return null;
  }
}

async function loadDashboard() {
  grid.innerHTML = '<div class="empty-state">Loading host reports…</div>';
  fleetSummary.innerHTML =
    '<div class="empty-state">Loading fleet summary…</div>';

  try {
    const [response, topology, storageTopology, unifi] = await Promise.all([
      fetch("manifest.json", {cache: "no-store"}),
      loadTopology(),
      loadStorageTopology(),
      loadUnifiSummary(),
    ]);

    if (!response.ok) {
      throw new Error(`Manifest returned HTTP ${response.status}`);
    }

    const manifest = await response.json();
    state.topology = topology;
    state.storageTopology = storageTopology;
    state.unifi = unifi;
    state.reports = await Promise.all(
      (manifest.hosts || []).map(loadReport),
    );
    state.reports.sort(reportSort);

    meta.textContent =
      `${state.reports.length} monitored ${plural(state.reports.length, "host")} · ` +
      `${state.unifi ? "UniFi live · " : ""}` +
      `Updated ${formatDate(manifest.generated_at)}`;

    renderFleetSummary(state.reports);
    renderFleet();
  } catch (error) {
    meta.textContent = "Dashboard unavailable";
    fleetSummary.innerHTML = "";
    inspector.innerHTML = "";
    grid.innerHTML = `
      <div class="error-state">
        <h2>Could not load the dashboard</h2>
        <p>${escapeHtml(error.message)}</p>
        <p class="muted">
          Open this page through a local web server rather than directly
          as a file.
        </p>
      </div>
    `;
  }
}

async function responsePayload(response) {
  try {
    return await response.json();
  } catch (error) {
    return {};
  }
}

function stopHealthCheckPolling() {
  if (state.healthCheckPollId !== null) {
    window.clearTimeout(state.healthCheckPollId);
    state.healthCheckPollId = null;
  }
}

function scheduleHealthCheckPoll() {
  stopHealthCheckPolling();
  state.healthCheckPollId = window.setTimeout(
    () => refreshHealthCheckStatus(false),
    1200,
  );
}

async function refreshHealthCheckStatus(silent = true) {
  try {
    const response = await fetch("api/health-check/status", {
      cache: "no-store",
    });
    const payload = await responsePayload(response);

    if (!response.ok || !payload.job) {
      throw new Error(`Controller returned HTTP ${response.status}.`);
    }

    const wasRunning = healthCheckIsRunning();
    state.healthCheckJob = payload.job;
    renderHealthCheckStatus();
    renderFleet();

    if (state.healthCheckJob.state === "running") {
      scheduleHealthCheckPoll();
    } else {
      stopHealthCheckPolling();

      if (wasRunning) {
        await loadDashboard();
      }
    }
  } catch (error) {
    stopHealthCheckPolling();

    if (!silent) {
      state.healthCheckJob = {
        state: "failed",
        host: state.healthCheckJob.host,
        message:
          "The health-check controller is unavailable. " +
          "Start dashboard/server.py instead of python -m http.server.",
      };
      renderHealthCheckStatus();
      renderFleet();
    }
  }
}

async function startHealthCheck(host) {
  if (healthCheckIsRunning()) {
    return;
  }

  state.healthCheckJob = {
    state: "running",
    host,
    message: `Starting health check for ${host}…`,
  };
  renderHealthCheckStatus();
  renderFleet();

  try {
    const response = await fetch(
      `api/health-check/${encodeURIComponent(host)}`,
      {
        method: "POST",
        headers: {"X-Health-Dashboard": "1"},
      },
    );
    const payload = await responsePayload(response);

    if (!response.ok || !payload.job) {
      throw new Error(
        payload.error || `Controller returned HTTP ${response.status}.`,
      );
    }

    state.healthCheckJob = payload.job;
    renderHealthCheckStatus();
    renderFleet();
    scheduleHealthCheckPoll();
  } catch (error) {
    state.healthCheckJob = {
      state: "failed",
      host,
      message:
        `${error.message} ` +
        "Launch dashboard/server.py to enable this button.",
    };
    renderHealthCheckStatus();
    renderFleet();
  }
}

function confirmSecurityUpdate(report) {
  const names = securityPackageNames(report);
  const count = numberValue(report.security_updates_available);
  const reviewCount = numberValue(report.review_required);
  const visibleNames = names.slice(0, 12);
  const remaining = Math.max(0, names.length - visibleNames.length);
  const packageSummary = visibleNames.length > 0
    ? `\n\nCurrently detected:\n- ${visibleNames.join("\n- ")}`
    : "";
  const remainingSummary = remaining > 0
    ? `\n- …and ${remaining} more`
    : "";
  const reviewWarning = reviewCount > 0
    ? `\n\n${reviewCount} package(s) are infrastructure-sensitive.`
    : "";

  return window.confirm(
    `Install all detected security updates on ${report.host}?` +
    `\n\nCached count: ${count}. APT metadata will be refreshed, so the ` +
    "exact package set may change." +
    reviewWarning +
    packageSummary +
    remainingSummary +
    "\n\nNo reboot will be performed. Package services may restart as part " +
    "of normal package installation. Continue?",
  );
}

async function startSecurityUpdate(host) {
  if (healthCheckIsRunning()) {
    return;
  }

  const report = state.reports.find((item) => item.host === host);

  if (!report || !confirmSecurityUpdate(report)) {
    return;
  }

  state.healthCheckJob = {
    state: "running",
    action: "security_update",
    phase: "starting",
    host,
    message: `Starting security update for ${host}…`,
  };
  renderHealthCheckStatus();
  renderFleet();

  try {
    const response = await fetch(
      `api/security-update/${encodeURIComponent(host)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Health-Dashboard": "1",
        },
        body: JSON.stringify({
          confirm_host: host,
          install_security_updates: true,
          automatic_reboot: false,
        }),
      },
    );
    const payload = await responsePayload(response);

    if (!response.ok || !payload.job) {
      throw new Error(
        payload.error || `Controller returned HTTP ${response.status}.`,
      );
    }

    state.healthCheckJob = payload.job;
    renderHealthCheckStatus();
    renderFleet();
    scheduleHealthCheckPoll();
  } catch (error) {
    state.healthCheckJob = {
      state: "failed",
      action: "security_update",
      host,
      message:
        `${error.message} ` +
        "Launch dashboard/server.py to enable this button.",
    };
    renderHealthCheckStatus();
    renderFleet();
  }
}

async function initializeDashboard() {
  await loadDashboard();
  await refreshHealthCheckStatus(true);
}

document
  .querySelector("#refresh-button")
  .addEventListener("click", loadDashboard);

activityDrawerToggle.addEventListener("click", () => {
  const isOpen = activityDrawerToggle.getAttribute("aria-expanded") === "true";
  setActivityDrawerOpen(!isOpen);
});

document
  .querySelector("#dialog-close")
  .addEventListener("click", () => dialog.close());

dialog.addEventListener("click", (event) => {
  if (event.target === dialog) {
    dialog.close();
  }
});

// ---------------------------------------------------------------------------
// CHAPTER 13.11 — Event delegation and application startup
// ---------------------------------------------------------------------------
// One delegated handler covers dynamically rendered buttons and rows. Every
// action is mapped to a fixed function; arbitrary data-action values do nothing.

function handleDashboardAction(event) {
  const securityUpdateButton = event.target.closest(
    'button[data-action="security-update"]',
  );

  if (securityUpdateButton) {
    startSecurityUpdate(securityUpdateButton.dataset.host);
    return;
  }

  const healthCheckButton = event.target.closest(
    'button[data-action="health-check"]',
  );

  if (healthCheckButton) {
    startHealthCheck(healthCheckButton.dataset.host);
    return;
  }

  const detailsButton = event.target.closest(
    'button[data-action="details"]',
  );

  if (detailsButton) {
    openHostDetails(detailsButton.dataset.host);
    return;
  }

  const toggleButton = event.target.closest(
    'button[data-action="toggle-node"]',
  );

  if (toggleButton) {
    const host = toggleButton.dataset.host;

    if (state.collapsedHosts.has(host)) {
      state.collapsedHosts.delete(host);
    } else {
      state.collapsedHosts.add(host);
    }

    renderFleet();
    return;
  }

  const sectionToggle = event.target.closest(
    'button[data-action="toggle-section"]',
  );

  if (sectionToggle) {
    const section = sectionToggle.dataset.section;

    if (state.collapsedSections.has(section)) {
      state.collapsedSections.delete(section);
    } else {
      state.collapsedSections.add(section);
    }

    renderFleet();
    return;
  }

  const hostRow = event.target.closest('[data-action="select-host"]');

  if (hostRow) {
    state.selectedHost = hostRow.dataset.host;
    renderFleet();
  }
}

grid.addEventListener("click", handleDashboardAction);
inspector.addEventListener("click", handleDashboardAction);

grid.addEventListener("keydown", (event) => {
  const hostRow = event.target.closest('[data-action="select-host"]');

  if (!hostRow || event.target.closest("button")) {
    return;
  }

  if (["Enter", " "].includes(event.key)) {
    event.preventDefault();
    state.selectedHost = hostRow.dataset.host;
    renderFleet();
  }
});

initializeDashboard();
