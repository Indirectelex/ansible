"use strict";

const state = {
  reports: [],
  search: "",
  healthStatus: "ALL",
  patchStatus: "ALL",
  healthCheckJob: {
    state: "idle",
    action: null,
    host: null,
    message: "",
  },
  healthCheckPollId: null,
};

const healthSeverityOrder = {
  CRITICAL: 0,
  UNREACHABLE: 1,
  WARNING: 2,
  UNKNOWN: 3,
  OK: 4,
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
const meta = document.querySelector("#dashboard-meta");
const dialog = document.querySelector("#host-dialog");
const dialogTitle = document.querySelector("#dialog-title");
const dialogContent = document.querySelector("#dialog-content");
const healthCheckStatus = document.querySelector("#health-check-status");

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

function renderHealthCheckStatus() {
  const job = state.healthCheckJob;

  if (!job || job.state === "idle") {
    healthCheckStatus.hidden = true;
    healthCheckStatus.textContent = "";
    healthCheckStatus.className = "run-status";
    return;
  }

  const messages = {
    running: job.message || `Dashboard action running for ${job.host}.`,
    success: job.message || `Dashboard action completed for ${job.host}.`,
    failed: job.message || `Dashboard action failed for ${job.host}.`,
  };

  healthCheckStatus.hidden = false;
  healthCheckStatus.className = `run-status run-status-${job.state}`;
  healthCheckStatus.textContent = messages[job.state] || job.message;
}

function renderHostCard(report) {
  const healthStatus = healthStatusName(
    report.health_status || report.status,
  );
  const patchStatus = patchStatusName(report.patch_posture_status);

  return `
    <article
      class="host-card ${healthStatusClass(healthStatus)} ${patchStatusClass(patchStatus)}"
      data-host="${escapeHtml(report.host)}"
    >
      <div class="host-card-header">
        <div>
          <h2>${escapeHtml(report.host)}</h2>
          <p class="muted">
            ${escapeHtml(formatDate(report.generated_at))}
          </p>
        </div>
      </div>

      <div class="compact-status-row">
        <div>
          <span class="panel-label">Health</span>
          <span class="status-badge ${healthStatusClass(healthStatus)}">
            ${escapeHtml(healthStatus)}
          </span>
        </div>
        <div>
          <span class="panel-label">Maintenance</span>
          <span class="patch-badge ${patchStatusClass(patchStatus)}">
            ${escapeHtml(patchStatusLabel(patchStatus))}
          </span>
        </div>
      </div>

      <dl class="key-metrics">
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
      </dl>

      ${renderActionGuidance(report)}

      ${renderLastMaintenance(report)}

      <div class="card-actions">
        ${renderHealthCheckButton(report)}

        ${renderSecurityUpdateButton(report)}

        <button
          type="button"
          data-action="details"
          data-host="${escapeHtml(report.host)}"
        >
          View details
        </button>
      </div>
    </article>
  `;
}

function renderFleetSummary(reports) {
  const healthyHosts = reports.filter(
    (report) =>
      healthStatusName(report.health_status || report.status) === "OK",
  ).length;
  const attentionHosts = reports.filter(
    (report) => hostActionGuidance(report).requiresAction,
  ).length;
  const reboots = reports.filter((report) => report.reboot_required).length;
  const freshHosts = reports.filter(
    (report) =>
      report.package_metadata_status === "FRESH" &&
      report.patch_counts_trusted === true,
  ).length;
  const staleHosts = reports.length - freshHosts;

  const cards = [
    [
      "Healthy hosts",
      `${healthyHosts} / ${reports.length}`,
      "summary-fresh",
    ],
    [
      "Need your attention",
      attentionHosts,
      attentionHosts > 0 ? "summary-review" : "summary-fresh",
    ],
    ["Reboots required", reboots, "summary-reboot"],
    [
      "Package data current",
      `${freshHosts} / ${reports.length}`,
      staleHosts > 0 ? "summary-action" : "summary-fresh",
    ],
  ];

  fleetSummary.innerHTML = `
    <div class="summary-heading">
      <div>
        <p class="eyebrow">Fleet status</p>
        <h2>At a glance</h2>
      </div>
      <p class="muted">Open a host only when you need evidence or detail</p>
    </div>

    <div class="summary-grid">
      ${cards
        .map(
          ([label, value, className]) => `
            <article class="summary-card ${escapeHtml(className)}">
              <span>${escapeHtml(label)}</span>
              <strong>${escapeHtml(value)}</strong>
            </article>
          `,
        )
        .join("")}
    </div>

    ${
      attentionHosts > 0
        ? `
          <p class="fleet-warning">
            ${attentionHosts} ${plural(attentionHosts, "host needs", "hosts need")}
            your attention. Each affected host card gives the next step.
          </p>
        `
        : '<p class="fleet-ok">No immediate operator action is required.</p>'
    }
  `;
}

function filteredReports() {
  return state.reports.filter((report) => {
    const healthStatus = healthStatusName(
      report.health_status || report.status,
    );
    const patchStatus = patchStatusName(report.patch_posture_status);
    const matchesSearch = String(report.host || "")
      .toLowerCase()
      .includes(state.search.toLowerCase());
    const matchesHealth =
      state.healthStatus === "ALL" ||
      healthStatus === state.healthStatus;
    const matchesPatch =
      state.patchStatus === "ALL" ||
      patchStatus === state.patchStatus ||
      (
        state.patchStatus === "DATA_STALE" &&
        report.patch_counts_trusted !== true
      );

    return matchesSearch && matchesHealth && matchesPatch;
  });
}

function renderCards() {
  const reports = filteredReports();

  if (reports.length === 0) {
    grid.innerHTML = `
      <div class="empty-state">
        <h2>No matching hosts</h2>
        <p class="muted">
          Change the hostname, health, or patch-posture filter.
        </p>
      </div>
    `;
    return;
  }

  grid.innerHTML = reports.map(renderHostCard).join("");
}

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

function renderMetricGroups(report) {
  const groups = groupByCategory(
    [...(report.metrics || [])].sort(
      (left, right) => metricOrder(left) - metricOrder(right),
    ),
  );

  return [...groups.entries()]
    .map(
      ([category, metrics]) => `
        <section class="category-block">
          <h3 class="category-title">${escapeHtml(category)}</h3>
          <div class="metric-detail-grid">
            ${metrics.map(renderMetric).join("")}
          </div>
        </section>
      `,
    )
    .join("");
}

function humanizeKey(value) {
  return String(value)
    .replaceAll("_", " ")
    .replace(/^./, (letter) => letter.toUpperCase());
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
                        <td>${escapeHtml(
                          typeof item[column] === "object"
                            ? JSON.stringify(item[column])
                            : item[column],
                        )}</td>
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

function renderSection(section) {
  let body;

  if (section.display === "list" || section.display === "table") {
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

function renderSectionGroups(report) {
  const sections = [...(report.sections || [])].sort(
    (left, right) =>
      Number(left.order ?? 9999) - Number(right.order ?? 9999),
  );
  const groups = groupByCategory(sections);

  return [...groups.entries()]
    .map(
      ([category, categorySections]) => `
        <section class="category-block">
          <h3 class="category-title">${escapeHtml(category)}</h3>
          ${categorySections.map(renderSection).join("")}
        </section>
      `,
    )
    .join("");
}

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
    <section class="category-block maintenance-history">
      <h3 class="category-title">Security maintenance history</h3>
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

    ${renderMaintenanceHistory(report)}
    ${renderMetricGroups(report)}
    ${renderSectionGroups(report)}
  `;

  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
}

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

async function loadDashboard() {
  grid.innerHTML = '<div class="empty-state">Loading host reports…</div>';
  fleetSummary.innerHTML =
    '<div class="empty-state">Loading fleet summary…</div>';

  try {
    const response = await fetch("manifest.json", {cache: "no-store"});

    if (!response.ok) {
      throw new Error(`Manifest returned HTTP ${response.status}`);
    }

    const manifest = await response.json();
    state.reports = await Promise.all(
      (manifest.hosts || []).map(loadReport),
    );
    state.reports.sort(reportSort);

    meta.textContent =
      `${state.reports.length} monitored host(s) · ` +
      `Dashboard generated ${formatDate(manifest.generated_at)}`;

    renderFleetSummary(state.reports);
    renderCards();
  } catch (error) {
    meta.textContent = "Dashboard unavailable";
    fleetSummary.innerHTML = "";
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
    renderCards();

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
      renderCards();
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
  renderCards();

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
    renderCards();
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
    renderCards();
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
  renderCards();

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
    renderCards();
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
    renderCards();
  }
}

async function initializeDashboard() {
  await loadDashboard();
  await refreshHealthCheckStatus(true);
}

document
  .querySelector("#host-search")
  .addEventListener("input", (event) => {
    state.search = event.target.value;
    renderCards();
  });

document
  .querySelector("#health-filter")
  .addEventListener("change", (event) => {
    state.healthStatus = event.target.value;
    renderCards();
  });

document
  .querySelector("#patch-filter")
  .addEventListener("change", (event) => {
    state.patchStatus = event.target.value;
    renderCards();
  });

document
  .querySelector("#refresh-button")
  .addEventListener("click", loadDashboard);

document
  .querySelector("#dialog-close")
  .addEventListener("click", () => dialog.close());

dialog.addEventListener("click", (event) => {
  if (event.target === dialog) {
    dialog.close();
  }
});

grid.addEventListener("click", (event) => {
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
  }
});

initializeDashboard();
