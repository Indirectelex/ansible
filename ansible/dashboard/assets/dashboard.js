"use strict";

const state = {
  reports: [],
  search: "",
  status: "ALL",
};

const severityOrder = {
  CRITICAL: 0,
  UNREACHABLE: 1,
  WARNING: 2,
  UNKNOWN: 3,
  OK: 4,
};

const grid = document.querySelector("#host-grid");
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

function statusName(value) {
  const status = String(value || "UNKNOWN").toUpperCase();

  return Object.hasOwn(severityOrder, status)
    ? status
    : "UNKNOWN";
}

function statusClass(value) {
  return `status-${statusName(value).toLowerCase()}`;
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

function getPreviewMetrics(report) {
  return [...(report.metrics || [])]
    .sort((left, right) => {
      const leftSeverity =
        severityOrder[statusName(left.status)] ?? 99;
      const rightSeverity =
        severityOrder[statusName(right.status)] ?? 99;

      return (
        leftSeverity - rightSeverity ||
        metricOrder(left) - metricOrder(right)
      );
    })
    .slice(0, 4);
}

function reasonMarkup(report) {
  const reasons = report.status_reasons || [];

  if (reasons.length === 0) {
    return '<p class="muted">No active status reasons.</p>';
  }

  return `
    <ul class="reason-list">
      ${reasons
        .map((reason) => `<li>${escapeHtml(reason)}</li>`)
        .join("")}
    </ul>
  `;
}

function renderHostCard(report) {
  const status = statusName(report.status);
  const metrics = getPreviewMetrics(report);

  const metricMarkup =
    metrics.length > 0
      ? `
        <div class="metric-preview-grid">
          ${metrics
            .map(
              (metric) => `
                <div class="metric-preview">
                  <span class="metric-preview-label">
                    ${escapeHtml(metric.label || metric.id)}
                  </span>
                  <span class="metric-preview-value">
                    ${escapeHtml(metricDisplayValue(metric))}
                  </span>
                </div>
              `,
            )
            .join("")}
        </div>
      `
      : '<p class="muted">No metrics were collected.</p>';

  return `
    <article
      class="host-card ${statusClass(status)}"
      data-host="${escapeHtml(report.host)}"
    >
      <div class="host-card-header">
        <div>
          <h2>${escapeHtml(report.host)}</h2>
          <p class="muted">
            ${escapeHtml(formatDate(report.generated_at))}
          </p>
        </div>

        <span class="status-badge ${statusClass(status)}">
          ${escapeHtml(status)}
        </span>
      </div>

      ${reasonMarkup(report)}
      ${metricMarkup}

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
          View details
        </button>
      </div>
    </article>
  `;
}

function filteredReports() {
  return state.reports.filter((report) => {
    const matchesSearch = String(report.host || "")
      .toLowerCase()
      .includes(state.search.toLowerCase());

    const matchesStatus =
      state.status === "ALL" ||
      statusName(report.status) === state.status;

    return matchesSearch && matchesStatus;
  });
}

function renderCards() {
  const reports = filteredReports();

  if (reports.length === 0) {
    grid.innerHTML = `
      <div class="empty-state">
        <h2>No matching hosts</h2>
        <p class="muted">
          Change the hostname search or status filter.
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
    <meter
      min="${minimum}"
      max="${maximum}"
      value="${value}"
    >
      ${escapeHtml(metricDisplayValue(metric))}
    </meter>
  `;
}

function renderMetric(metric) {
  const status = statusName(metric.status);

  return `
    <article class="metric-detail">
      <div class="metric-detail-header">
        <h4>${escapeHtml(metric.label || metric.id)}</h4>

        <span class="${statusClass(status)}">
          ${escapeHtml(status)}
        </span>
      </div>

      <div class="metric-value">
        ${escapeHtml(metricDisplayValue(metric))}
      </div>

      ${
        metric.display === "gauge"
          ? renderGauge(metric)
          : ""
      }
    </article>
  `;
}

function renderMetricGroups(report) {
  const groups = groupByCategory(
    [...(report.metrics || [])].sort(
      (left, right) => metricOrder(left) - metricOrder(right),
    ),
  );

  if (groups.size === 0) {
    return "";
  }

  return [...groups.entries()]
    .map(
      ([category, metrics]) => `
        <section class="category-block">
          <h3 class="category-title">
            ${escapeHtml(category)}
          </h3>

          <div class="metric-detail-grid">
            ${metrics.map(renderMetric).join("")}
          </div>
        </section>
      `,
    )
    .join("");
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
              .map((column) => `<th>${escapeHtml(column)}</th>`)
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
                        <td>
                          ${escapeHtml(
                            typeof item[column] === "object"
                              ? JSON.stringify(item[column])
                              : item[column],
                          )}
                        </td>
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

  if (section.display === "list") {
    body = renderGenericTable(section.items || []);
  } else if (section.display === "table") {
    body = renderGenericTable(section.items || []);
  } else if (section.display === "preformatted") {
    body = `<pre>${escapeHtml(section.content || "")}</pre>`;
  } else if (section.content !== undefined) {
    body = `<p>${escapeHtml(section.content)}</p>`;
  } else {
    body = `
      <pre>${escapeHtml(
        JSON.stringify(section, null, 2),
      )}</pre>
    `;
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

  if (groups.size === 0) {
    return "";
  }

  return [...groups.entries()]
    .map(
      ([category, categorySections]) => `
        <section class="category-block">
          <h3 class="category-title">
            ${escapeHtml(category)}
          </h3>

          ${categorySections.map(renderSection).join("")}
        </section>
      `,
    )
    .join("");
}

function openHostDetails(host) {
  const report = state.reports.find(
    (item) => item.host === host,
  );

  if (!report) {
    return;
  }

  dialogTitle.textContent = report.host;

  dialogContent.innerHTML = `
    <div class="detail-summary">
      <div>
        <span
          class="status-badge ${statusClass(report.status)}"
        >
          ${escapeHtml(statusName(report.status))}
        </span>

        <p class="muted" style="margin-top: 12px">
          Generated ${escapeHtml(formatDate(report.generated_at))}
        </p>

        ${reasonMarkup(report)}
      </div>

      <a
        class="report-link"
        href="${encodeURIComponent(report.host)}.md"
        target="_blank"
        rel="noopener"
      >
        Open Markdown report
      </a>
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
    const response = await fetch(entry.report, {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const report = await response.json();

    return {
      ...report,
      host: report.host || entry.id,
    };
  } catch (error) {
    return {
      schema_version: 1,
      report_type: "host_health",
      host: entry.id,
      generated_at: null,
      status: "UNKNOWN",
      status_reasons: [
        `Report could not be loaded: ${error.message}`,
      ],
      metrics: [],
      sections: [],
    };
  }
}

async function loadDashboard() {
  grid.innerHTML = `
    <div class="empty-state">
      Loading host reports…
    </div>
  `;

  try {
    const response = await fetch("manifest.json", {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`Manifest returned HTTP ${response.status}`);
    }

    const manifest = await response.json();

    state.reports = await Promise.all(
      (manifest.hosts || []).map(loadReport),
    );

    state.reports.sort((left, right) => {
      const severityDifference =
        (severityOrder[statusName(left.status)] ?? 99) -
        (severityOrder[statusName(right.status)] ?? 99);

      return (
        severityDifference ||
        String(left.host).localeCompare(String(right.host))
      );
    });

    meta.textContent =
      `${state.reports.length} monitored host(s) · ` +
      `Dashboard generated ${formatDate(manifest.generated_at)}`;

    renderCards();
  } catch (error) {
    meta.textContent = "Dashboard unavailable";

    grid.innerHTML = `
      <div class="error-state">
        <h2>Could not load the dashboard</h2>
        <p>${escapeHtml(error.message)}</p>
        <p class="muted">
          Open this page through a local web server rather than
          directly as a file.
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
  .querySelector("#status-filter")
  .addEventListener("change", (event) => {
    state.status = event.target.value;
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
