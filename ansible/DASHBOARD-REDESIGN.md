# Dashboard design and integration rationale

> **TEACHER NOTE — design history:** This file explains why the compact layout,
> UniFi merge, and live storage topology were designed this way. It is not the
> current installation procedure. Use `README.md` and
> `docs/RUNTIME-OPERATIONS.md` for current operation.
>
> **CHANGE INSTRUCTIONS:** When a design invariant changes, update the relevant
> source-file chapter, executable test, teacher-guide chapter, and this rationale.
> Do not use the old archive-install commands below as a deployment shortcut.

## Original compact-dashboard package notes

This package replaces the repeated host cards with a compact Proxmox-style
fleet navigator.

## Install

From the Ansible repository on Hackwell:

```bash
cd "$HOME/infrastructure/ansible" || exit 1

backup_dir="$HOME/dashboard-backup-$(date +%Y%m%d-%H%M%S)"
cp -a dashboard "$backup_dir"

tar -xzf "$HOME/Downloads/ansible-dashboard-proxmox-layout-upgrade.tar.gz" \
  -C "$HOME/infrastructure"

ansible-playbook playbooks/health-check.yml --tags dashboard
```

Refresh the browser with `Ctrl+Shift+R`.

## Topology

`dashboard/assets/dashboard-topology.json` controls guest placement without
hardcoding it in the renderer. Hosts still come from the generated manifest;
the topology file only adds the parent, guest ID, and display type.

The included mappings are:

- `nimbus` → VM `1000` (`scale`)
- `zebulon` → LXC `555` (`docker-ct`)

An unmapped monitored host appears directly below `Datacenter`, so adding a
host never prevents the dashboard from loading.

## Live UniFi integration

The dashboard uses two read-only data paths with separate responsibilities:

- the official local UniFi Network API supplies the authoritative adopted
  device roster and current controller state;
- Unpoller and Prometheus supply measurements, counters, and history.

Only devices currently returned by UniFi are included in inventory. Removing
or forgetting a retired device therefore removes it automatically from the
dashboard. An adopted device in the `OFFLINE` state remains visible and raises
a finding. Prometheus history can enrich an adopted device with last-seen data,
but it cannot add an old device back to the roster.

The integration is configured in
`dashboard/assets/dashboard-topology.json`. It is optional and does not stop
the host dashboard when Prometheus is unavailable.

The included endpoint is:

```json
{
  "integrations": {
    "unifi": {
      "enabled": true,
      "prometheus_url": "http://192.168.40.214:9090",
      "controller_url": "https://192.168.2.12",
      "controller_verify_tls": false,
      "expected_offline_devices": []
    }
  }
}
```

Create one dedicated API key in UniFi Network under `Control Plane >
Integrations`, then provide it only to the server process. Do not put the key
in `dashboard-topology.json`, because that file is served to the browser.

For an interactive launch:

```bash
cd "$HOME/infrastructure/ansible" || exit 1

read -rsp "UniFi API key: " DASHBOARD_UNIFI_API_KEY
echo
export DASHBOARD_UNIFI_API_KEY

python3 dashboard/server.py \
  --prometheus-url http://192.168.40.214:9090
```

The controller URL and optional site ID can also be overridden with
`--unifi-controller-url` and `--unifi-site-id`. When the controller contains
exactly one site, the server discovers its ID automatically.

The browser receives a bounded summary from `/api/unifi/summary`; it cannot
submit arbitrary PromQL or choose another network endpoint. Run
`dashboard/server.py`, not `python3 -m http.server`, for this integration.

The UniFi inspector is ordered for incident response: active findings first,
then WAN, Wi-Fi, switching, and device health, followed by four 24-hour trends.
Raw controller subsystems and the full device inventory are collapsed until
needed. The server derives health from fixed PromQL queries for errors, drops,
Wi-Fi retries, traffic, latency, and connected clients; the browser still
cannot submit PromQL.

Device availability comes directly from the UniFi adopted-device endpoint.
The last seven days of `unpoller_device_info` are consulted only to enrich an
adopted offline device with its most recent sample time.

Switch-port errors and drops are evaluated as both a 24-hour count and a
percentage of total port traffic. The dashboard also queries the top affected
switches and ports. A large counter with a low traffic percentage is a watch;
warning is reserved for error rates of at least 1% or drop rates of at least
2%.

If a device is intentionally powered off, add its exact UniFi name to
`expected_offline_devices`. It remains visible in the collapsed inventory but
does not degrade network health:

```json
"expected_offline_devices": ["ModemPlug"]
```

Leave the list empty unless the device is deliberately allowed to be offline.

## Live Proxmox-to-TrueNAS storage topology

Physical disk ownership and ZFS membership are discovered automatically. No
serial-to-pool table is maintained in `inventory/host_vars`.

On each Proxmox host, the health role reads the local QEMU configurations and
selects guests with `/dev/disk/by-id` passthroughs. For guests with a responsive
QEMU Guest Agent it runs two fixed, read-only commands:

- `lsblk -J -b -p` supplies the guest disk, `drive-scsiN` identity, partition,
  and PARTUUID;
- `zpool status -pP` supplies the live pool, vdev class, vdev, member path, and
  member state.

The storage filter joins the Proxmox slot to `drive-scsiN`, then joins the ZFS
`by-partuuid` member to the matching `lsblk` partition. SMART serials match the
stable Proxmox by-id source, so changing `/dev/sdX` names does not break the
relationship.

The publish play writes `reports/storage-topology.json`. Nimbus SMART cards use
the embedded live path, while the Scale ZFS pool cards use the same artifact to
show their physical Proxmox members. A non-ZFS guest remains a consumer-only
mapping and does not create a false pool warning. A virtual guest boot disk is
identified as virtual instead of being mistaken for a missing physical disk.

## Proxmox Backup Server

The `pbs` inventory host at `192.168.12.157` is monitored as VM 999 under
Nimbus. In addition to the standard Linux resource, service, patch, and ZFS
checks, the PBS module reads component versions and configured datastores using
`proxmox-backup-manager`. Each datastore path is measured independently with
POSIX `df`, using the normal 80% warning and 90% critical capacity policy.

Guest SMART collection is disabled for PBS because its two physical
passthrough SSDs are already measured authoritatively on Nimbus. The live
Proxmox storage topology still records VM 999 as their consumer even though PBS
does not use ZFS.

## Rollback

The install command prints no backup path, so note the timestamped directory
created under `/home/hackwell`. Restore it with:

```bash
cd "$HOME/infrastructure/ansible" || exit 1
cp -a "$HOME/dashboard-backup-YYYYMMDD-HHMMSS/." dashboard/
ansible-playbook playbooks/health-check.yml --tags dashboard
```
