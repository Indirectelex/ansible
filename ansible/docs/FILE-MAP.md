# File-by-file infrastructure map

Use this map when you know the symptom but not where to begin. Each maintained
file also carries its own `TEACHER NOTE` and `CHANGE INSTRUCTIONS`.

## Controller and fleet declaration

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `ansible.cfg` | Default inventory, roles, SSH, become, timeout and forks | Every `ansible-playbook` invocation | `ansible-config dump`, inventory graph, syntax check |
| `inventory/hosts.yml` | Hosts, functional groups, connection identities and feature intent | Play host patterns and feature policy | `ansible-inventory --graph`, limited health check |
| `inventory/infrastructure-registry.yml` | Stable host identity/topology, runtime workloads, edge providers and service relationships | Publication play, `/api/registry`, dashboard | Registry tests, syntax check, published registry smoke check |
| `inventory/host_vars/nimbus.yml` | Nimbus-only policy notes; live storage discovery is preferred | Health role for Nimbus | Storage topology tests plus Nimbus limited run |

## Monitoring entry points

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `playbooks/health-check.yml` | Linux, TrueNAS and publication order | CLI and custom server action controller | Syntax check, full tests, generated manifest |
| `playbooks/tasks/connectivity-check.yml` | Reachability fallback and fact boundary | Linux play pre-tasks | Reachable and unreachable report fixtures |
| `playbooks/security-update.yml` | Exact-host, exact-package security mutation | Custom server security action | Static safety tests and maintenance-window run |

## Health role policy and orchestration

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `roles/health_check/defaults/main.yml` | Thresholds, feature/module defaults, patch rules | All health task files | Boundary fixtures and syntax check |
| `tasks/main.yml` | Complete Linux stage order | Role entry point | Full suite and one limited host run |
| `tasks/feature_discovery.yml` | Read-only capability observation | `feature_policy.yml` | Capability present/absent cases |
| `tasks/feature_policy.yml` | Defaults + discovery + overrides = effective policy | Module `when` conditions | Valid, disabled and impossible configurations |
| `tasks/resource_thresholds.yml` | Swap and load-per-CPU policy | Internal report and overall state | Just-below/at warning and critical values |
| `tasks/service_allowlist.yml` | Effective versus ignored failed units | `policy_checks.yml` | Exact unit allowlist and retained evidence |
| `tasks/policy_checks.yml` | Time and service policy enrichment | Final report | Synchronized/unsynchronized cases |
| `tasks/collection_policy.yml` | Applicable failure versus disabled feature | Final report/status | Disabled, success and failed collector cases |
| `tasks/dashboard_schema.yml` | Versioned browser metrics/sections/reasons | JSON report and browser | Layout/schema tests and sample report |
| `tasks/truenas.yml` | TrueNAS-specific evidence and compatible report | TrueNAS play | TrueNAS command fixtures and layout tests |

## Optional monitoring modules

| File | Evidence collected | Normalizer / consumer | Focused validation |
| --- | --- | --- | --- |
| `modules/docker.yml` | Docker daemon and container listing | Generic module renderer | Enabled/disabled and failed command |
| `modules/proxmox.yml` | PVE version and storage status | Generic module renderer | Active/inactive/failed storage |
| `modules/pbs.yml` | PBS versions, datastores and filesystem usage | `pbs_health.py` | PBS normalization tests |
| `modules/zfs.yml` | Pool state/topology and capacity | `storage_health.py` | Online/degraded/failed collection |
| `modules/smart.yml` | Device JSON, kernel log, history and topology | `storage_health.py` | SMART and topology suite |
| `modules/proxmox_guest_storage.yml` | VM configs, QGA, lsblk and zpool evidence | `storage_health.py` | QGA/identity/partial join fixtures |

## Patch posture

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `tasks/patch_intelligence.yml` | Metadata freshness, candidate classification, posture reasons | Internal report/schema | Patch-intelligence suite |
| `tasks/patch_automation.yml` | Unattended-upgrades and systemd attempt evidence | Patch filter/posture | Parser and automation-state fixtures |
| `tasks/patch_state.yml` | Trusted pending-since history on controller | Patch posture | First-seen/persist/clear transitions |
| `filter_plugins/patch_intelligence.py` | Pure parsing, classification, history merge and posture | Ansible Jinja filters | `test_patch_intelligence.py` |

## Storage and PBS interpretation

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `filter_plugins/storage_health.py` | SMART/ZFS parsing, confidence, history, and physical-to-guest joins | SMART/ZFS module results and storage topology | `test_storage_health.py` |
| `filter_plugins/pbs_health.py` | PBS JSON/path/df normalization and thresholds | PBS module result | `test_pbs_health.py` |
| `templates/health-report.md.j2` | Human-readable view of final report | Reports publication | Render representative OK/WATCH/WARNING reports |

## Dashboard application

| File | Teaches / controls | Immediate consumer | Focused validation |
| --- | --- | --- | --- |
| `dashboard/index.html` | Semantic mount points and accessibility structure | Browser and JS selectors | Layout tests plus browser inspection |
| `dashboard/assets/dashboard.css` | Theme, state presentation and responsive workspace | Browser DOM classes | Light/dark/narrow/reduced-motion inspection |
| `dashboard/assets/dashboard.js` | Load/state/render/action lifecycle | Browser DOM and custom API | Node syntax, layout tests, functional browser run |
| `dashboard/assets/dashboard-topology.json` | Non-secret UniFi integration endpoints only | Server integration config | JSON parse, layout/server tests |
| `dashboard/server.py` | Static report server, registry/workload validation and API, validated actions, UniFi merge and history | Browser and systemd | Server/registry suite plus HTTP smoke checks |

## Generated and runtime boundaries

| Path | Producer | Why it is not maintained source |
| --- | --- | --- |
| `reports/manifest.json` | Publication play | Rebuilt from `monitoring_enabled` |
| `reports/infrastructure-registry.json` | Publication play | Validated projection of the maintained infrastructure registry |
| `reports/<host>.json` | Health role/TrueNAS tasks | Snapshot of live evidence |
| `reports/<host>.md` | Markdown template/TrueNAS tasks | Human rendering of snapshot |
| `reports/storage-topology.json` | Publication play | Snapshot of live correlation |
| `reports/index.html`, `reports/assets/` | Publication play | Copies of `dashboard/` source |
| `reports/maintenance/` | Custom server | Bounded action evidence |
| `.state/health_check/` | Patch-state task | Private trusted history |
| `.state/dashboard/events.db` | Dashboard server | Private SQLite event history, comparison state and 90-day retained timeline |

## Runtime and documentation enforcement

| File | Teaches / controls | Focused validation |
| --- | --- | --- |
| `systemd/hackwell-dashboard.service.example` | Correct persistent custom-server command | Compare installed unit and HTTP smoke checks |
| `AGENTS.md` | Mandatory repository editing rules | Documentation contract test |
| `docs/CHANGE-PROTOCOL.md` | Before/during/after change process | Handoff review |
| `docs/RUNTIME-OPERATIONS.md` | Install, status, smoke test and recovery | Run exact local commands |
| `tests/test_documentation_contract.py` | Required teacher/change notes for maintained files | Full unit suite |

## Executable behaviour chapters

| Test | Contract protected |
| --- | --- |
| `test_dashboard_layout.py` | Navigator/inspector, drawer, UniFi and storage presentation |
| `test_dashboard_server.py` | Trust boundary, fixed actions, history and UniFi clients |
| `test_infrastructure_registry.py` | Registry host/workload/service schema, references, publication and browser consumption |
| `test_patch_intelligence.py` | APT parsing, trusted history and posture transitions |
| `test_pbs_health.py` | PBS datastore identity/capacity normalization |
| `test_storage_health.py` | SMART/ZFS evidence and storage joins |
| `test_watch_pipeline.py` | WATCH propagation through every layer |
| `test_security_update_playbook.py` | Exact-host, no-removal, no-schedule/no-reboot safety |
| `test_documentation_contract.py` | Continuous in-file teaching-note requirement |

## Separate ERPNext update workflow

| File | Responsibility | Risk level |
| --- | --- | --- |
| `playbooks/erpnext-update-check.yml` | Read-only current/latest release comparison | Read-only |
| `playbooks/erpnext-backup-test.yml` | Run verified backup workflow alone | Controlled writes to backup storage |
| `playbooks/erpnext-update.yml` | Request gated production update | Production mutation |
| `roles/erpnext_update/defaults/main.yml` | Site, Compose, backup, health and delay policy | Configuration |
| `tasks/check.yml` | Parse current tag and choose stable upstream release | Read-only |
| `tasks/backup.yml` | Create, copy, verify and retain recovery artifacts | Data-protection critical |
| `tasks/update.yml` | Release gate, deployment, migration and health verification | Production mutation |
