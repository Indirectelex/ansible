# Gluetun + Dante + qBittorrent Audit Runbook

> **Purpose:** A practical future-audit checklist for the TrueNAS → Dante → Gluetun → NordVPN → Internet path used by qBittorrent.
>
> **Rule:** If the quick checks pass, **do not change anything**.

---

## 1. Known-Good Architecture

```text
TrueNAS / qBittorrent
192.168.12.145 ── SOCKS5 TCP ────────┐
                                     │
192.168.12.225 ── SOCKS5 UDP ────────┤
             route to 172.23.0.2     │
                                     ▼
                              nginx-ct
                           192.168.12.155
                                     │
                                   Dante
                               TCP 1080
                         UDP 20000-20099
                                     │
                                  Gluetun
                                     │
                                  NordVPN
                                     │
                                  Internet
```

### Known-good baseline

| Component | Expected value |
|---|---|
| `nginx-ct` LAN IP | `192.168.12.155` |
| TrueNAS qBittorrent TCP source | `192.168.12.145` |
| TrueNAS UDP source | `192.168.12.225` |
| Gluetun container IP | `172.23.0.2` |
| SOCKS5 TCP port | `1080` |
| Dante UDP relay range | `20000-20099` |
| Docker Engine | `28.5.2` or newer |
| Docker trusted interface | `eth0` |
| TrueNAS static route | `172.23.0.2/32 via 192.168.12.155` |

---

## 2. Five-Minute Health Check

Use this first for routine audits.

### On TrueNAS

#### Verify the UDP relay route

```bash
ip route get 172.23.0.2
```

Expected:

```text
172.23.0.2 via 192.168.12.155 dev enp6s18 src 192.168.12.225
```

#### Verify SOCKS5 TCP through the VPN

```bash
curl -sS \
  --socks5-hostname 192.168.12.155:1080 \
  https://api.ipify.org
echo
```

Note the returned public IP.

#### Verify SOCKS5 UDP

If the test script was saved persistently:

```bash
python3 /mnt/apps_configs/qbittorrent/test_dante_udp.py
```

Healthy result ends with:

```text
✅ UDP RESPONSE RECEIVED
✅ Dante SOCKS5 UDP works end-to-end.
```

### On `nginx-ct`

#### Verify Gluetun and Dante are running

```bash
docker ps --filter name=gluetun --filter name=dante
```

Expected:

```text
gluetun   Up ... (healthy)
dante     Up ...
```

#### Verify Gluetun's VPN IP

```bash
docker exec gluetun cat /tmp/gluetun/ip
echo
```

This public IP must match the IP returned by the TrueNAS SOCKS5 `curl` test.

### In qBittorrent

Confirm:

- **DHT:** greater than `0`
- **UDP trackers:** at least some `udp://` trackers show **Working**
- **Transfers:** active torrents download/upload normally

If all of these pass, the system is healthy.

---

## 3. Full Infrastructure Audit

Run this after Docker, TrueNAS networking, Gluetun, Dante, or qBittorrent changes.

### On `nginx-ct`

```bash
cd /opt/stacks/gluetun

echo "=== CONTAINERS ==="
docker ps --filter name=gluetun --filter name=dante \
  --format 'table {{.Names}}\t{{.Status}}'

echo
echo "=== DOCKER VERSION ==="
docker version --format 'Server: {{.Server.Version}}'

echo
echo "=== TRUSTED INTERFACE ==="
docker network inspect gluetun_default \
  --format '{{index .Options "com.docker.network.bridge.trusted_host_interfaces"}}'

echo
echo "=== GLUETUN OUTBOUND SUBNETS ==="
grep 'FIREWALL_OUTBOUND_SUBNETS' compose.yaml

echo
echo "=== DANTE ALLOWED CLIENTS ==="
grep -E 'from: 192\.168\.12\.(145|225)' dante/danted.conf
```

### Healthy baseline

```text
Docker Engine:
28.5.2 or newer

gluetun:
Up ... (healthy)

dante:
Up ...

trusted_host_interfaces:
eth0

FIREWALL_OUTBOUND_SUBNETS:
192.168.12.145/32,192.168.12.225/32

Dante clients:
192.168.12.145/32
192.168.12.225/32
```

---

## 4. TrueNAS Routing Audit

The TCP and UDP paths intentionally use different source addresses.

### SOCKS5 TCP route

```bash
ip route get 192.168.12.155
```

Known-good:

```text
192.168.12.155 dev enp6s19 src 192.168.12.145
```

### SOCKS5 UDP relay route

```bash
ip route get 172.23.0.2
```

Known-good:

```text
172.23.0.2 via 192.168.12.155 dev enp6s18 src 192.168.12.225
```

### Persistent TrueNAS static route

```text
Destination: 172.23.0.2/32
Gateway:     192.168.12.155
Description: Dante SOCKS5 UDP relay
```

If this route disappears, SOCKS5 TCP may still work while DHT and UDP trackers fail.

---

## 5. SOCKS5 TCP Verification

From **TrueNAS**:

```bash
curl -sS \
  --socks5-hostname 192.168.12.155:1080 \
  https://api.ipify.org
echo
```

From **nginx-ct**:

```bash
docker exec gluetun cat /tmp/gluetun/ip
echo
```

The two public IP addresses must be identical.

If they differ:

> Stop troubleshooting qBittorrent. Fix the Dante / Gluetun / VPN path first.

---

## 6. SOCKS5 UDP Verification

The deterministic UDP test is one of the most useful diagnostics because it removes qBittorrent from the equation.

Recommended permanent location:

```text
/mnt/apps_configs/qbittorrent/test_dante_udp.py
```

Run:

```bash
python3 /mnt/apps_configs/qbittorrent/test_dante_udp.py
```

Healthy output should include:

```text
SOCKS5 greeting reply: 0500

Dante UDP relay:
  Address: 172.23.0.2
  Port:    200xx

✅ UDP RESPONSE RECEIVED
✅ Dante SOCKS5 UDP works end-to-end.
```

### Interpretation

```text
SOCKS TCP ✅
SOCKS UDP ❌
```

Do **not** change qBittorrent settings.

Investigate:

1. TrueNAS static route
2. Docker direct routing
3. Dante
4. Gluetun firewall / routing

---

## 7. Verify the Old Manual iptables Workaround Is Gone

There should be **no manually maintained raw-table ACCEPT rule** for the Dante UDP relay.

On `nginx-ct`:

```bash
if iptables -t raw -C PREROUTING \
  -i eth0 \
  -s 192.168.12.225 \
  -d 172.23.0.2 \
  -p udp \
  --dport 20000:20099 \
  -j ACCEPT 2>/dev/null
then
    echo "❌ OLD MANUAL IPTABLES RULE EXISTS"
else
    echo "✅ No manual iptables workaround"
fi
```

Healthy:

```text
✅ No manual iptables workaround
```

The supported design uses:

```text
com.docker.network.bridge.trusted_host_interfaces=eth0
```

If UDP only works after re-adding the old manual rule, investigate Docker networking instead of making that rule permanent.

---

## 8. Confirm qBittorrent Is Actually Using Dante

While qBittorrent is active, on **TrueNAS**:

```bash
ss -ntp | grep '192.168.12.155:1080'
```

Known-good connections look like:

```text
192.168.12.145:xxxxx → 192.168.12.155:1080
users:(("qbittorrent-nox",...))
```

That confirms `qbittorrent-nox` itself is using Dante.

On **nginx-ct**:

```bash
docker logs --since 5m dante 2>&1 | \
grep -Eo '192\.168\.12\.(145|225)' | \
sort | uniq -c
```

Expect:

- lots of `.145` traffic from qBittorrent TCP connections
- some `.225` traffic from UDP/test traffic

---

## 9. qBittorrent UI Audit

### DHT

Look at the bottom qBittorrent status bar.

Healthy:

```text
DHT: 1+ nodes
```

Typical known-good state:

```text
DHT: hundreds of nodes
```

Warning:

```text
DHT: 0 nodes
```

for several minutes while active public torrents are running.

### UDP Trackers

1. Select a torrent.
2. Open the **Trackers** tab.
3. Find entries beginning with:

```text
udp://
```

Healthy:

```text
Working
```

Some public trackers timing out is normal.

The warning condition is:

> **All UDP trackers fail or time out.**

### Fresh Magnet Test

Add a legitimate public magnet qBittorrent has never seen before.

Initially:

```text
Downloading metadata
```

Healthy behavior:

- metadata resolves
- real torrent name appears
- files populate
- download starts
- no need to disable the proxy

If an old torrent works but a brand-new magnet cannot retrieve metadata, investigate DHT / UDP / proxy behavior.

---

## 10. Kill-Switch Audit

Use this after major changes.

Start an active torrent, then on **nginx-ct**:

```bash
cd /opt/stacks/gluetun

docker compose stop dante gluetun
```

Expected qBittorrent behavior:

```text
download stalls
upload stalls
new connections fail
```

qBittorrent must **not** continue establishing new connections through the normal WAN.

Restore the stack:

```bash
docker compose start gluetun dante
```

Wait for Gluetun:

```bash
until [ "$(docker inspect -f '{{.State.Health.Status}}' gluetun)" = "healthy" ]; do
    echo "Waiting for Gluetun..."
    sleep 2
done

echo "✅ Gluetun healthy"
```

qBittorrent should recover automatically.

### Healthy kill-switch behavior

```text
VPN/proxy available    → qBittorrent works
VPN/proxy unavailable  → qBittorrent fails closed
VPN/proxy restored     → qBittorrent recovers
```

---

## 11. Troubleshooting Order

Do not change random settings. Diagnose in this order:

```text
1. Are Gluetun and Dante running?
             ↓
2. Is Gluetun healthy?
             ↓
3. Does SOCKS5 TCP return Gluetun's VPN IP?
             ↓
4. Is the TrueNAS route to 172.23.0.2 correct?
             ↓
5. Does test_dante_udp.py succeed?
             ↓
6. Does qBittorrent connect to 192.168.12.155:1080?
             ↓
7. Is DHT > 0?
             ↓
8. Do some UDP trackers work?
             ↓
9. Can a fresh magnet obtain metadata?
```

---

## 12. Failure Interpretation

| Result | Likely area |
|---|---|
| Gluetun not healthy | VPN / Gluetun |
| Dante stopped | Dante container/config |
| SOCKS5 TCP fails | Dante / Gluetun / Docker |
| SOCKS5 TCP returns non-VPN IP | Proxy/VPN path |
| TCP works, UDP test fails | TrueNAS route / Docker / Dante UDP |
| UDP test works, DHT stays 0 | qBittorrent |
| DHT works, some trackers fail | Usually normal public tracker failure |
| All UDP trackers fail | UDP proxy path |
| Old torrent works, fresh magnet fails | DHT / metadata / UDP path |
| qBittorrent keeps downloading after Gluetun/Dante stop | **Potential traffic leak — investigate immediately** |

---

## 13. Useful Logs

### Gluetun

```bash
docker logs --tail 100 gluetun
```

### Dante

```bash
docker logs --tail 100 dante
```

Recent Dante traffic:

```bash
docker logs --since 5m dante
```

---

## 14. Final Known-Good Security State

The finished configuration should have:

```text
Docker Engine 28.5.2 or newer
Gluetun healthy
Dante running
Docker trusted interface = eth0
No manual iptables UDP workaround
TrueNAS static route persistent
Dante restricted to:
  192.168.12.145/32
  192.168.12.225/32
Gluetun FIREWALL_OUTBOUND_SUBNETS:
  192.168.12.145/32
  192.168.12.225/32
SOCKS5 TCP works
SOCKS5 UDP works
DHT works
UDP trackers work
Fresh magnets work
Kill-switch test passes
```

---

## 15. Golden Rule

> If the routing test, SOCKS5 TCP test, SOCKS5 UDP test, DHT, UDP trackers, and fresh magnet test all pass, **stop troubleshooting**.

A working system does not need more changes.
