# status.echodata.ca — Configuration and Recovery Guide

This document describes the complete EchoDATA external status-page configuration hosted on the RackNerd VPS.

## Overview

- Public URL: `https://status.echodata.ca`
- RackNerd public IPv4: `23.226.136.206`
- OS: Ubuntu 24.04 LTS
- Monitoring: Gatus v5.36.0
- Container runtime: Podman
- HTTPS frontend: Caddy
- Persistence: SQLite
- Gatus local listener: `127.0.0.1:8080`

The VPS is used as an external observation point. It checks EchoDATA services from outside the home network and also verifies Stalwart SMTP through the WireGuard tunnel.

## Architecture

```text
Internet
   |
   +--> https://status.echodata.ca
   |        |
   |      Caddy
   |        |
   |   127.0.0.1:8080
   |        |
   |      Gatus
   |
   +--> https://echodata.ca
   +--> https://mail.echodata.ca
   +--> https://signal.echodata.ca
   +--> https://vault.echodata.ca
   +--> https://jmap.echodata.ca

RackNerd 10.77.0.1
        |
     WireGuard
        |
docker-ct 10.77.0.2
        |
   Stalwart :25
```

## DNS

Cloudflare DNS record:

```text
Type: A
Name: status
Value: 23.226.136.206
Proxy: DNS only
TTL: Auto
```

Verify:

```bash
dig status.echodata.ca +short
```

Expected:

```text
23.226.136.206
```

The record is intentionally DNS-only so the status page remains an independent external monitoring point.

## Directory layout

```text
/opt/gatus/
├── config/
│   └── config.yaml
└── data/
    ├── gatus.db
    ├── gatus.db-shm
    └── gatus.db-wal
```

Create the directories:

```bash
mkdir -p /opt/gatus/config /opt/gatus/data
```

## Podman

Install:

```bash
apt update
apt install -y podman
```

Gatus is run with host networking so Podman does not introduce container NAT between Gatus and the existing mail gateway.

## Gatus configuration

File:

```text
/opt/gatus/config/config.yaml
```

Current configuration:

```yaml
storage:
  type: sqlite
  path: /data/gatus.db
  maximum-number-of-results: 10000
  maximum-number-of-events: 100

web:
  address: "127.0.0.1"
  port: 8080

ui:
  title: "EchoDATA Infrastructure Status"
  header: "EchoDATA"
  dashboard-heading: "Infrastructure Status"
  dashboard-subheading: "External monitoring from the EchoDATA edge node"
  default-sort-by: "group"
  dark-mode: true

endpoints:

  - name: ERPNext
    group: Public Services
    url: "https://vault.echodata.ca"
    interval: 1m
    conditions:
      - "[STATUS] >= 200"
      - "[STATUS] < 400"
      - "[CERTIFICATE_EXPIRATION] > 168h"
      - "[RESPONSE_TIME] < 5000"

  - name: Portal
    group: Public Services
    url: "https://signal.echodata.ca"
    interval: 1m
    conditions:
      - "[STATUS] >= 200"
      - "[STATUS] < 400"
      - "[CERTIFICATE_EXPIRATION] > 168h"
      - "[RESPONSE_TIME] < 5000"

  - name: Website
    group: Public Services
    url: "https://echodata.ca"
    interval: 1m
    conditions:
      - "[STATUS] >= 200"
      - "[STATUS] < 400"
      - "[CERTIFICATE_EXPIRATION] > 168h"
      - "[RESPONSE_TIME] < 5000"

  - name: Webmail
    group: Public Services
    url: "https://mail.echodata.ca"
    interval: 1m
    conditions:
      - "[STATUS] >= 200"
      - "[STATUS] < 400"
      - "[CERTIFICATE_EXPIRATION] > 168h"
      - "[RESPONSE_TIME] < 5000"

  - name: JMAP
    group: Mail
    url: "https://jmap.echodata.ca/.well-known/jmap"
    interval: 1m
    conditions:
      - "[STATUS] >= 200"
      - "[STATUS] < 400"
      - "[CERTIFICATE_EXPIRATION] > 168h"
      - "[RESPONSE_TIME] < 5000"

  - name: Stalwart SMTP over WireGuard
    group: Mail
    url: "tcp://10.77.0.2:25"
    interval: 30s
    conditions:
      - "[CONNECTED] == true"

  - name: Mail Server A Record
    group: Mail DNS
    url: "1.1.1.1"
    interval: 5m
    dns:
      query-name: "mx1.echodata.ca"
      query-type: "A"
    conditions:
      - "[DNS_RCODE] == NOERROR"
      - "[BODY] == 23.226.136.206"

  - name: Mail Server PTR
    group: Mail DNS
    url: "1.1.1.1"
    interval: 5m
    dns:
      query-name: "23.226.136.206"
      query-type: "PTR"
    conditions:
      - "[DNS_RCODE] == NOERROR"
      - "[BODY] == mx1.echodata.ca."

  - name: EchoDATA MX
    group: Mail DNS
    url: "1.1.1.1"
    interval: 5m
    dns:
      query-name: "echodata.ca"
      query-type: "MX"
    conditions:
      - "[DNS_RCODE] == NOERROR"
      - "[BODY] == mx1.echodata.ca."

  - name: EchoDATA SPF
    group: Mail DNS
    url: "https://dns.google/resolve?name=echodata.ca&type=TXT"
    interval: 5m
    conditions:
      - "[STATUS] == 200"
      - "[BODY] == pat(*v=spf1*ip4:23.226.136.206*)"
```

### SPF implementation note

The original SPF monitor used Gatus native TXT DNS monitoring. In the installed version, Gatus did not expose the TXT body correctly and reported the query type as unsupported. The SPF monitor therefore uses Google's DNS-over-HTTPS resolver and verifies that the returned response contains:

```text
v=spf1
ip4:23.226.136.206
```

The real SPF record itself was verified separately and was healthy.

## Dashboard organization

```text
EchoDATA Infrastructure Status
│
├── Public Services
│   ├── ERPNext
│   ├── Portal
│   ├── Website
│   └── Webmail
│
├── Mail
│   ├── JMAP
│   └── Stalwart SMTP over WireGuard
│
└── Mail DNS
    ├── Mail Server A Record
    ├── Mail Server PTR
    ├── EchoDATA MX
    └── EchoDATA SPF
```

## Gatus systemd service

File:

```text
/etc/systemd/system/gatus.service
```

Contents:

```ini
[Unit]
Description=Gatus External Infrastructure Monitor
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=simple
Restart=always
RestartSec=5

ExecStartPre=-/usr/bin/podman rm -f gatus

ExecStart=/usr/bin/podman run \
  --name gatus \
  --network host \
  -v /opt/gatus/config:/config:ro \
  -v /opt/gatus/data:/data \
  ghcr.io/twin/gatus:v5.36.0

ExecStop=/usr/bin/podman stop -t 10 gatus
ExecStopPost=-/usr/bin/podman rm -f gatus

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
systemctl daemon-reload
systemctl enable --now gatus
```

Restart:

```bash
systemctl restart gatus
```

Check:

```bash
systemctl --no-pager --full status gatus
```

## Local Gatus health

Gatus listens only on:

```text
127.0.0.1:8080
```

Verify:

```bash
ss -ltnp | grep ':8080'
curl -s http://127.0.0.1:8080/health
```

Expected:

```json
{"status":"UP"}
```

## SQLite persistence

Database:

```text
/opt/gatus/data/gatus.db
```

Verify:

```bash
ls -lah /opt/gatus/data/
```

Typical files:

```text
gatus.db
gatus.db-shm
gatus.db-wal
```

Historical failed results can remain visible after a monitor is fixed because SQLite intentionally preserves monitoring history.

## Caddy installation

Install prerequisites:

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
```

Add the Caddy repository:

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | tee /etc/apt/sources.list.d/caddy-stable.list

chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
chmod o+r /etc/apt/sources.list.d/caddy-stable.list

apt update
apt install -y caddy
```

## Caddy configuration

File:

```text
/etc/caddy/Caddyfile
```

Contents:

```caddy
status.echodata.ca {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

Validate and start:

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy
systemctl enable caddy
```

Verify:

```bash
systemctl --no-pager --full status caddy
curl -I https://status.echodata.ca
```

Expected:

```text
HTTP/2 200
via: 1.1 Caddy
```

Caddy automatically obtains and renews the TLS certificate for `status.echodata.ca`.

## What each monitor checks

### ERPNext

URL:

```text
https://vault.echodata.ca
```

Checks:

- HTTP response is 2xx or 3xx
- certificate has more than 7 days remaining
- response time is under 5 seconds

### Portal

URL:

```text
https://signal.echodata.ca
```

Same HTTP, certificate and latency checks as ERPNext.

### Website

URL:

```text
https://echodata.ca
```

Same HTTP, certificate and latency checks.

### Webmail

URL:

```text
https://mail.echodata.ca
```

Same HTTP, certificate and latency checks.

### JMAP

URL:

```text
https://jmap.echodata.ca/.well-known/jmap
```

Checks public JMAP reachability, HTTPS, certificate expiration and latency.

### Stalwart SMTP over WireGuard

Target:

```text
tcp://10.77.0.2:25
```

This verifies that RackNerd can reach Stalwart over the WireGuard tunnel.

### Mail A record

Expected:

```text
mx1.echodata.ca -> 23.226.136.206
```

Manual check:

```bash
dig A mx1.echodata.ca +short
```

### Mail PTR

Expected:

```text
23.226.136.206 -> mx1.echodata.ca
```

Manual check:

```bash
dig -x 23.226.136.206 +short
```

### MX

Expected:

```text
echodata.ca MX -> mx1.echodata.ca
```

Manual check:

```bash
dig MX echodata.ca +short
```

### SPF

Expected SPF contains:

```text
ip4:23.226.136.206
```

Manual check:

```bash
dig TXT echodata.ca +short | grep 'v=spf1'
```

Example:

```text
"v=spf1 ip4:23.226.136.206 include:amazonses.com ~all"
```

## Gatus API checks

Example:

```bash
curl -sS \
  http://127.0.0.1:8080/api/v1/endpoints/mail-dns_echodata-spf/statuses \
  | python3 -m json.tool
```

A healthy current result should show:

```text
success: true
```

## Recent monitoring logs

```bash
journalctl -u gatus --since "1 minute ago" --no-pager \
  | grep 'watchdog.executeEndpoint' \
  | grep -v podman
```

Healthy lines contain:

```text
success=true
```

for the expected endpoints.

## Resource usage

RackNerd has approximately:

```text
1 vCPU
1 GB RAM
1 GB swap
20 GB disk
```

Observed initial usage was approximately:

```text
Gatus: ~70 MB RAM
Caddy: ~15 MB RAM
```

This leaves enough headroom for the status role.

## Firewall safety

Before Gatus deployment:

```bash
nft list ruleset > /root/nftables-before-gatus.txt
```

After deployment:

```bash
nft list ruleset > /root/nftables-after-gatus.txt

diff -u \
  /root/nftables-before-gatus.txt \
  /root/nftables-after-gatus.txt
```

The diff was empty, confirming that the Podman/Gatus deployment did not alter the existing SMTP gateway nftables configuration.

## Backups

Configuration snapshots created during setup included:

```text
/opt/gatus/config/config.yaml.before-sqlite
/opt/gatus/config/config.yaml.before-spf-fix
/opt/gatus/config/config.yaml.before-portal-erpnext
```

Create a complete status-page backup:

```bash
tar -czf /root/status-echodata-backup.tar.gz \
  /opt/gatus \
  /etc/systemd/system/gatus.service \
  /etc/caddy/Caddyfile
```

This is separate from the RackNerd SMTP/WireGuard disaster-recovery backup.

## Restart procedure

```bash
systemctl restart gatus
systemctl restart caddy

systemctl is-active gatus
systemctl is-active caddy
```

Expected:

```text
active
active
```

## Troubleshooting

### Public status page unavailable

```bash
dig status.echodata.ca +short
systemctl status caddy
journalctl -u caddy -n 50 --no-pager
curl -I https://status.echodata.ca
```

### Caddy works but Gatus does not

```bash
systemctl status gatus
curl http://127.0.0.1:8080/health
journalctl -u gatus -n 100 --no-pager
```

### SMTP monitor is down

```bash
wg show wg0
nc -vz 10.77.0.2 25
```

A deeper SMTP recipient test:

```bash
swaks \
  --server 10.77.0.2 \
  --port 25 \
  --ehlo mx1.echodata.ca \
  --from probe@example.net \
  --to admin@echodata.ca \
  --quit-after RCPT
```

Expected:

```text
250 2.1.5 OK
```

### SPF monitor is red

Check the real record first:

```bash
dig TXT echodata.ca +short | grep 'v=spf1'
```

Then inspect DNS-over-HTTPS:

```bash
curl -s \
  'https://dns.google/resolve?name=echodata.ca&type=TXT' \
  | python3 -m json.tool
```

Do not change DNS unless the actual SPF record is wrong.

## Recovery on a fresh RackNerd VPS

Recommended order:

```text
1. Restore RackNerd networking
2. Restore WireGuard
3. Restore nftables SMTP gateway
4. Restore status.echodata.ca DNS
5. Install Podman
6. Restore /opt/gatus/config/config.yaml
7. Restore /opt/gatus/data/
8. Restore /etc/systemd/system/gatus.service
9. Install Caddy
10. Restore /etc/caddy/Caddyfile
11. Start Gatus
12. Start Caddy
13. Verify local and public health
```

Commands:

```bash
systemctl daemon-reload
systemctl enable --now gatus
systemctl enable --now caddy

curl http://127.0.0.1:8080/health
curl -I https://status.echodata.ca
```

## If RackNerd's public IP changes

Update:

1. `status.echodata.ca` A record
2. `mx1.echodata.ca` A record
3. RackNerd PTR/rDNS
4. `echodata.ca` SPF
5. Gatus Mail Server A Record expected IP
6. Gatus EchoDATA SPF expected IP
7. the WireGuard endpoint on `docker-ct` if the VPS address changed

Then:

```bash
systemctl restart gatus
```

## Security notes

- Gatus is bound to `127.0.0.1`, not a public interface.
- Caddy is the only public frontend for the dashboard.
- Port 8080 does not need to be opened to the Internet.
- WireGuard private keys are not included in this document.
- No Stalwart, Bulwark or RackNerd account passwords are stored here.
- The status stack was installed without altering the working mail-gateway nftables rules.

## Quick health checklist

```bash
echo "===== SERVICES ====="
systemctl is-active gatus
systemctl is-active caddy
systemctl is-active wg-quick@wg0
systemctl is-active nftables

echo
echo "===== GATUS ====="
curl -s http://127.0.0.1:8080/health
echo

echo
echo "===== PUBLIC STATUS ====="
curl -I https://status.echodata.ca

echo
echo "===== DNS ====="
dig status.echodata.ca +short
dig A mx1.echodata.ca +short
dig -x 23.226.136.206 +short
dig MX echodata.ca +short
dig TXT echodata.ca +short | grep 'v=spf1'

echo
echo "===== WIREGUARD ====="
wg show wg0

echo
echo "===== RECENT GATUS RESULTS ====="
journalctl -u gatus --since "2 minutes ago" --no-pager \
  | grep 'watchdog.executeEndpoint' \
  | grep -v podman
```

A healthy deployment should show all required services active and current Gatus checks reporting `success=true`.
