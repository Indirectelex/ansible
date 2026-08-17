# Mandatory maintenance instructions

This repository is both an infrastructure tool and its own teaching material.
These instructions apply to every file below this directory.

## Read before changing anything

1. Read `README.md` for the short operational model.
2. Read `docs/INFRASTRUCTURE-TEACHER-GUIDE.md` for the end-to-end data flow.
3. Read the `TEACHER NOTE` and `CHANGE INSTRUCTIONS` in the target file.
4. Decide whether the file is source, configuration, state, or generated output.
5. Never edit a generated file as the way to implement a lasting change.

## Non-negotiable documentation rule

Every maintained source or configuration file must explain:

- its purpose;
- its inputs and outputs;
- the next consumer in the pipeline;
- the assumptions that are easy to break;
- the exact validation required after changing it.

When code behaviour, a schema, a command, a threshold, a route, or a data
source changes, update the nearby `TEACHER NOTE` and `CHANGE INSTRUCTIONS` in
the same change. A code change without matching instructions is incomplete.

For a new maintained file:

1. Add a `TEACHER NOTE` at the beginning.
2. Add a `CHANGE INSTRUCTIONS` section in the same comment block.
3. Link it to the relevant chapter in
   `docs/INFRASTRUCTURE-TEACHER-GUIDE.md`.
4. Add or update a focused test.
5. Run `python3 -m unittest discover -s tests -v`.

`tests/test_documentation_contract.py` enforces this minimum contract.

## Source-of-truth boundaries

| Area | Source of truth | Generated or runtime copy |
| --- | --- | --- |
| Browser interface | `dashboard/index.html`, `dashboard/assets/` | `reports/index.html`, `reports/assets/` |
| Local controller | `dashboard/server.py` | Running systemd process |
| Host selection | `inventory/hosts.yml` | `reports/manifest.json` |
| Host policy | Inventory variables and `roles/health_check/defaults/main.yml` | Effective policy embedded in host reports |
| Host reports | Health-check role and schema tasks | `reports/*.json`, `reports/*.md` |
| Storage relationship | Live Proxmox/QEMU/ZFS/SMART discovery | `reports/storage-topology.json` |
| Network configuration | `dashboard/assets/dashboard-topology.json` | Published copy under `reports/assets/` |
| UniFi measurements | UniFi API plus Prometheus/Unpoller | `/api/unifi/summary` response |
| Maintenance history | Dashboard controller | `reports/maintenance/*.json` |

Do not hand-edit `reports/*.json`, `reports/*.md`, or copied dashboard assets
under `reports/`. Run the publishing play instead.

## Runtime invariant

The dashboard must be launched with `dashboard/server.py`. A generic
`python3 -m http.server` process can display static HTML but cannot provide
UniFi data, validated Ansible actions, maintenance history, or the action-status
API. Treat substitution of the custom server as a functional outage.

The service must bind to loopback unless the security model is deliberately
redesigned and approved. Never expose the current action API directly to a LAN
or the Internet.

## Required validation

Run the smallest relevant checks and always run the full unit suite before
handoff:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile dashboard/server.py roles/health_check/filter_plugins/*.py
node --check dashboard/assets/dashboard.js
ansible-playbook --syntax-check playbooks/health-check.yml
ansible-playbook --syntax-check playbooks/security-update.yml
```

If Ansible is unavailable in the editing environment, report that limitation;
do not claim the syntax checks passed.

## Safety boundaries

- Health collection is read-only.
- Security installation requires one exact host, explicit browser confirmation,
  a fixed playbook, and no automatic reboot.
- Secrets never belong in browser-served JSON, reports, Git, or examples.
- UniFi API keys belong in the server process environment only.
- Preserve user changes and avoid broad Git restore/reset operations.
