"use strict";

const state = {
  reports: [],
  search: "",
  healthStatus: "ALL",
  patchStatus: "ALL",
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

function securityCountDisplay(report) {
  const count = numberValue(report.security_updates_available);

  if (report.patch_counts_trusted === true) {
    return String(count);
  }

  return count > 0 ? `${count} detected` : "Unknown";
}

function renderRows(rows) {
  return `
    <dl class="status-metrics">
      ${rows
        .map(
          ([label, value, className = ""]) => `
            <div class="status-metric ${escapeHtml(className)}">
              <dt>${escapeHtml(label)}</dt>
              <dd>${escapeHtml(value)}</dd>
            </div>
          `,
        )
        .join("")}
    </dl>
  `;
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

function renderHealthPanel(report) {
  const status = healthStatusName(report.health_status || report.status);
  const reasons = report.health_status_reasons || report.status_reasons || [];

  return `
    <section class="status-panel health-panel ${healthStatusClass(status)}">
      <div class="status-panel-heading">
        <span class="panel-label">Health</span>
        <span class="status-badge ${healthStatusClass(status)}">
          ${escapeHtml(status)}
        </span>
      </div>

      ${renderRows([
        ["CPU load / core", metricValue(report, "load_per_cpu")],
        ["Memory", metricValue(report, "memory")],
        ["Root disk", metricValue(report, "root_disk")],
        ["Failed services", metricValue(report, "failed_services")],
      ])}

      ${
        reasons.length > 0
          ? reasonMarkup(reasons, "", "health-reasons")
          : ""
      }
    </section>
  `;
}

function renderPatchPanel(report) {
  const status = patchStatusName(report.patch_posture_status);
  const trusted = report.patch_counts_trusted === true;
  const staleClass = trusted ? "" : "metric-untrusted";
  const rows = [
    ["Security updates", securityCountDisplay(report), staleClass],
    [
      "Regular updates",
      String(numberValue(report.regular_updates_available)),
      staleClass,
    ],
    ["Review required", String(numberValue(report.review_required))],
    ["Restart-sensitive", String(numberValue(report.restart_sensitive))],
    ["Reboot required", report.reboot_required ? "Yes" : "No"],
    [
      "Package metadata",
      `${metadataAge(report)} · ${report.package_metadata_status || "UNKNOWN"}`,
      staleClass,
    ],
  ];

  if (report.os_update_automation_enabled === true) {
    rows.push(
      ["Pending since", formatDate(report.security_pending_since_at)],
      ["Next automatic attempt", formatDate(report.os_update_next_attempt_at)],
      [
        "Last automatic attempt",
        report.os_update_last_attempt_at
          ? `${formatDate(report.os_update_last_attempt_at)} · ${report.os_update_last_result || "unknown"}`
          : "No recorded attempt",
      ],
      [
        "Automatic reboot",
        report.os_update_automatic_reboot ? "Enabled" : "No",
      ],
    );
  }

  return `
    <section class="status-panel patch-panel ${patchStatusClass(status)}">
      <div class="status-panel-heading">
        <span class="panel-label">Patch posture</span>
        <span class="patch-badge ${patchStatusClass(status)}">
          ${escapeHtml(patchStatusLabel(status))}
        </span>
      </div>

      ${renderRows(rows)}

      ${
        trusted
          ? ""
          : `
            <p class="data-warning">
              Cached package data is stale or incomplete. Security totals
              are detections, not a current complete count.
            </p>
          `
      }
    </section>
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

function packageGroupMarkup(label, packages, className) {
  if (!Array.isArray(packages) || packages.length === 0) {
    return "";
  }

  return `
    <section class="package-group ${escapeHtml(className)}">
      <h4>${escapeHtml(label)} <span>${packages.length}</span></h4>
      <ul>
        ${packages
          .map(
            (packageItem) => `
              <li>
                <code>${escapeHtml(packageItem.name)}</code>
                <span>${escapeHtml(
                  packageItem.classification_reason || "Security update",
                )}</span>
              </li>
            `,
          )
          .join("")}
      </ul>
    </section>
  `;
}

function renderSecurityDisclosure(report) {
  const groups = report.security_packages || {};
  const total = numberValue(report.security_updates_available);

  if (total === 0) {
    return "";
  }

  return `
    <details class="security-disclosure">
      <summary>
        View ${total} detected ${plural(total, "security package")}
      </summary>
      <div class="package-groups">
        ${packageGroupMarkup(
          "Review required",
          groups.review_required,
          "package-review",
        )}
        ${packageGroupMarkup(
          "Restart-sensitive",
          groups.restart_sensitive,
          "package-restart",
        )}
        ${packageGroupMarkup(
          "Standard security",
          groups.standard_security,
          "package-standard",
        )}
      </div>
    </details>
  `;
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
        <span class="host-policy">
          ${escapeHtml(patchPolicyLabel(report))}
        </span>
      </div>

      <div class="host-status-grid">
        ${renderHealthPanel(report)}
        ${renderPatchPanel(report)}
      </div>

      ${renderSecurityDisclosure(report)}

      <div class="card-actions">
        <a
          class="report-link"
          href="${encodeURIComponent(report.host)}.md"
          target="_blank"
          rel="noopener"
        >
          Markdown report
        </a>

        <button
          type="button"
          data-action="details"
          data-host="${escapeHtml(report.host)}"
        >
          View all details
        </button>
      </div>
    </article>
  `;
}

function renderFleetSummary(reports) {
  const securityUpdates = reports.reduce(
    (total, report) =>
      total + numberValue(report.security_updates_available),
    0,
  );
  const manualSecurityHosts = reports.filter(
    (report) =>
      numberValue(report.security_updates_available) > 0 &&
      report.os_update_automation_enabled !== true,
  ).length;
  const osManagedSecurityHosts = reports.filter(
    (report) =>
      numberValue(report.security_updates_available) > 0 &&
      report.os_update_automation_enabled === true,
  ).length;
  const automationAttention = reports.filter((report) =>
    ["AUTOMATION_OVERDUE", "AUTOMATION_ERROR"].includes(
      patchStatusName(report.patch_posture_status),
    ),
  ).length;
  const reboots = reports.filter((report) => report.reboot_required).length;
  const freshHosts = reports.filter(
    (report) =>
      report.package_metadata_status === "FRESH" &&
      report.patch_counts_trusted === true,
  ).length;
  const staleHosts = reports.length - freshHosts;

  const cards = [
    ["Security updates detected", securityUpdates, "summary-action"],
    ["Hosts needing manual patching", manualSecurityHosts, "summary-review"],
    ["OS-managed pending hosts", osManagedSecurityHosts, "summary-scheduled"],
    ["Automation needing attention", automationAttention, "summary-error"],
    ["Reboots required", reboots, "summary-reboot"],
    ["Fresh package metadata", `${freshHosts} / ${reports.length}`, "summary-fresh"],
  ];

  fleetSummary.innerHTML = `
    <div class="summary-heading">
      <div>
        <p class="eyebrow">Fleet maintenance</p>
        <h2>Security &amp; maintenance</h2>
      </div>
      <p class="muted">Cached APT observations from the latest report run</p>
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
      staleHosts > 0
        ? `
          <p class="fleet-warning">
            ${staleHosts} ${plural(staleHosts, "host has", "hosts have")}
            stale or incomplete package metadata. Fleet security totals are
            detected cached updates, not a guaranteed current total.
          </p>
        `
        : '<p class="fleet-ok">Package metadata is fresh on every host.</p>'
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

    ${renderMetricGroups(report)}
    ${renderSectionGroups(report)}
  `;

  if (typeof dialog.showModal === "function") {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
}

async function loadReport(entry) {
  try {
    const response = await fetch(entry.report, {cache: "no-store"});

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const report = await response.json();
    return {...report, host: report.host || entry.id};
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
  const button = event.target.closest(
    'button[data-action="details"]',
  );

  if (button) {
    openHostDetails(button.dataset.host);
  }
});

loadDashboard();
