# Dashboard runtime operations

## Runtime contract

The dashboard URL is <http://127.0.0.1:8088/>. The service must run the custom
`dashboard/server.py` and must serve the repository’s `reports/` directory.

Do not substitute `python3 -m http.server`. It has no action controller and no
UniFi endpoint.

## Install the user service

```bash
mkdir -p "$HOME/.config/systemd/user"
cp systemd/hackwell-dashboard.service.example \
  "$HOME/.config/systemd/user/hackwell-dashboard.service"

systemctl --user daemon-reload
systemctl --user enable --now hackwell-dashboard.service
sudo loginctl enable-linger "$USER"
```

The example uses `%h`, so it remains tied to the current user’s home directory
without embedding `/home/hackwell` in the unit.

## Optional UniFi API key

Prometheus metrics work from the non-secret topology configuration. The
authoritative controller roster additionally needs `DASHBOARD_UNIFI_API_KEY`.
Keep it outside the repository and browser-served files.

Create a private environment file:

```bash
mkdir -p "$HOME/.config/hackwell-dashboard"
install -m 600 /dev/null \
  "$HOME/.config/hackwell-dashboard/environment"
```

Add this single line manually, substituting the real key:

```text
DASHBOARD_UNIFI_API_KEY=replace-with-real-key
```

Then uncomment the `EnvironmentFile=` line in the installed service and
restart it.

## Safe status checks

```bash
systemctl --user status hackwell-dashboard.service --no-pager -l
journalctl --user -u hackwell-dashboard.service -n 100 --no-pager
curl --fail --silent --show-error http://127.0.0.1:8088/manifest.json >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8088/api/registry
curl --fail --silent --show-error http://127.0.0.1:8088/api/health-check/status
curl --fail --silent --show-error 'http://127.0.0.1:8088/api/events?limit=5&period=24h'
curl --silent --show-error http://127.0.0.1:8088/api/unifi/summary
```

The event endpoint also supports bounded `host`, `severity`, `source`,
`period`, `limit`, and `offset` query parameters. The response includes the
matching event page, total count, severity/recovery summary, filter facets, and
the configured 90-day retention window.

Interpret the UniFi result carefully:

- HTTP 200: integration returned a summary;
- HTTP 404: integration is not configured or the wrong server is running;
- HTTP 503: custom server is running, but its upstream query failed.

## Refresh reports and interface

```bash
cd "$HOME/infrastructure/ansible"
ansible-playbook playbooks/health-check.yml
```

The final play validates `inventory/infrastructure-registry.yml` against live
Ansible inventory, then republishes `index.html`, CSS, JavaScript, the registry,
storage topology, and manifest. Force-refresh the browser after interface changes.

## Recovery sequence

1. Do not start a second server on port 8088.
2. Inspect the owning process and systemd status.
3. Inspect the service command; it must name `dashboard/server.py`.
4. Verify `reports/manifest.json` and `reports/infrastructure-registry.json` exist.
5. Verify `/api/registry` returns the expected host/workload/service counts and no validation error.
6. Verify published interface files exist under `reports/`.
7. Test the remaining HTTP boundaries above, including `/api/events`.
8. Inspect the journal before changing files.


## Central logging operations

Logging is a separate mutation path; the routine health check never installs or restarts Loki/Alloy. Registry intent lives under `observability.logging` in `inventory/infrastructure-registry.yml`.

Validate before deployment:

```bash
cd "$HOME/infrastructure/ansible"
python3 -m unittest discover -s tests -p 'test_*.py'
ansible-playbook --syntax-check playbooks/logging-stack.yml
```

Deploy/reconcile:

```bash
ansible-playbook playbooks/logging-stack.yml
```

Smoke checks after deployment:

```bash
curl --fail --silent --show-error http://192.168.40.214:3100/ready
ansible managed_linux -b -m command -a 'systemctl is-active alloy.service'
ansible docker-ct -b -m command -a 'docker ps --filter name=echodata-loki --format {{'"'"'{{.Names}} {{.Status}}'"'"'}}'
```

Grafana is adopted from the existing `unpoller-unifi` stack. The logging role
provisions both the `EchoDATA Loki` datasource and the `EchoDATA Logs` dashboard.
The dashboard is stored below the existing provider path rather than creating a
second provider:

```text
/opt/stacks/unpoller-unifi/grafana/provisioning/dashboards/EchoDATA/echodata-logs.json
```

To reconcile only Grafana provisioning after Loki is already healthy:

```bash
ansible-playbook playbooks/logging-stack.yml --tags grafana --limit docker-ct
```

Open Grafana, then **Dashboards → EchoDATA → EchoDATA Logs**. The default window
is one hour with 10-second refresh. Host, source, container, and regex search
filters narrow both the volume panel and the raw log stream.

Loki has no built-in authentication in this topology, so port 3100 must remain private-LAN only and must not be exposed through Cloudflare or a public reverse proxy. Alloy's local debugging HTTP endpoint remains loopback-bound by the packaged default.
