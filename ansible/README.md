# Hackwell infrastructure monitoring

This repository collects infrastructure health with Ansible, converts the
results into a stable JSON contract, and serves a local interactive dashboard.
It also contains a separate controlled ERPNext update workflow.

Start with this mental model:

```mermaid
flowchart TD
    I[Inventory and policy] --> C[Ansible collectors]
    C --> N[Python normalization filters]
    N --> R[Generated reports]
    R --> S[Custom local server]
    U[UniFi and Prometheus] --> S
    S --> B[Browser dashboard]
    B -->|validated local action| S
    S -->|one allowed host| C
```

The critical distinction is between **source files** and **published files**:

- `dashboard/` contains the maintained interface and custom server source.
- `reports/` contains generated host data and published interface copies.
- `dashboard/server.py` serves `reports/` and provides the local APIs.
- `python3 -m http.server` is not a valid replacement.

## Normal operating flow

1. `inventory/hosts.yml` defines which machines belong to each functional
   group.
2. `playbooks/health-check.yml` checks Linux and TrueNAS hosts.
3. `roles/health_check/` discovers capabilities, applies policy, collects raw
   evidence, normalizes it, assigns status, and builds the dashboard schema.
4. Reports are written into `reports/` on the controller laptop.
5. The playbook publishes the maintained HTML/CSS/JavaScript into `reports/`
   and writes `manifest.json`.
6. `dashboard/server.py` serves that directory on `127.0.0.1:8088`, adds UniFi
   data, and exposes narrowly validated maintenance endpoints.
7. The browser loads the manifest, host reports, topology, storage topology,
   maintenance history, and optional UniFi summary.

## Run or refresh the system

Generate fresh data and publish the interface:

```bash
cd "$HOME/infrastructure/ansible"
ansible-playbook playbooks/health-check.yml
```

Inspect the persistent dashboard service:

```bash
systemctl --user status hackwell-dashboard.service --no-pager
journalctl --user -u hackwell-dashboard.service -n 100 --no-pager
```

Open <http://127.0.0.1:8088/>.

The tracked service example is in
`systemd/hackwell-dashboard.service.example`. See
`docs/RUNTIME-OPERATIONS.md` before installing or changing it.

## Status language

| State | Meaning |
| --- | --- |
| `OK` | Evidence is healthy and no action is required. |
| `WATCH` | Stable or uncertain evidence should remain visible, but it is not active deterioration. |
| `WARNING` | A real condition needs review or planned action. |
| `CRITICAL` | Strong evidence indicates an immediate health or data-protection risk. |
| `UNKNOWN` | Required evidence could not be collected or interpreted safely. |
| `UNREACHABLE` | Ansible could not reach the host; the remaining checks did not run. |

`WATCH` must not be silently promoted to `WARNING`, and failed collection must
not be presented as `OK`.

## Documentation is part of the implementation

Every maintained file begins with a `TEACHER NOTE` and
`CHANGE INSTRUCTIONS`. Long files are divided into chapters explaining why the
sections exist and how data crosses their boundaries.

Read:

- `docs/INFRASTRUCTURE-TEACHER-GUIDE.md` for the complete system walkthrough;
- `docs/FILE-MAP.md` to locate the producer and consumer of every maintained file;
- `docs/CHANGE-PROTOCOL.md` before editing;
- `docs/RUNTIME-OPERATIONS.md` for service and troubleshooting commands;
- `AGENTS.md` for the mandatory repository rules.
