# RackNerd Mail Gateway Disaster Recovery

This document explains how to rebuild the RackNerd VPS used as the public SMTP gateway for the EchoDATA Stalwart mail server.

The RackNerd VPS is intentionally designed to be replaceable. It provides the public IPv4 address, inbound TCP/25 forwarding, outbound SMTP NAT, and the WireGuard tunnel back to the Stalwart server running on `docker-ct`.

---

## 1. Architecture Overview

```text
Public Internet
      │
      ▼
RackNerd VPS
23.226.136.206
      │
      │ TCP/25 DNAT
      ▼
WireGuard
10.77.0.1 ↔ 10.77.0.2
      │
      ▼
Stalwart
10.77.0.2:25
```

Outbound mail follows the reverse path:

```text
Stalwart
10.77.0.2
   │
   ▼
WireGuard
   │
   ▼
RackNerd
23.226.136.206
   │
   ▼
Internet SMTP servers
```

The RackNerd VPS is not the mail store. Mailboxes, DKIM private keys, Bulwark, JMAP, and Stalwart data remain on the home infrastructure.

---

## 2. Current RackNerd Network Configuration

### Public network

```text
Hostname: racknerd-f965bbd
Public IPv4: 23.226.136.206
Interface: eth0
Gateway: 23.226.136.1
```

### DNS identity

```text
A record:
mx1.echodata.ca → 23.226.136.206

PTR / reverse DNS:
23.226.136.206 → mx1.echodata.ca
```

### Current live MX

At the time this document was written, the domain MX was still:

```text
echodata.ca MX 10 inbound-smtp.us-east-1.amazonaws.com.
```

If the live MX has since been changed to Stalwart, verify the current value before performing recovery work.

---

## 3. WireGuard Configuration

### RackNerd

```text
Interface: wg0
Address: 10.77.0.1/24
UDP port: 51820
```

RackNerd WireGuard public key:

```text
jgvY1NK0QF+deqVuMY29Dxf08pSwmcvvkUvlJY0hWHo=
```

### docker-ct

```text
Interface: wg0
Address: 10.77.0.2/24
```

docker-ct WireGuard public key:

```text
UGbgqbuo+b/e76dx39sfbNENTlFzQZEg0tPJVC3Vx3U=
```

### RackNerd `/etc/wireguard/wg0.conf`

```ini
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = <RACKNERD_PRIVATE_KEY>

[Peer]
PublicKey = UGbgqbuo+b/e76dx39sfbNENTlFzQZEg0tPJVC3Vx3U=
AllowedIPs = 10.77.0.2/32
```

The RackNerd private key is intentionally not included in this document. Back up the real `/etc/wireguard/wg0.conf` securely.

---

## 4. nftables Configuration

The RackNerd server performs two NAT functions.

### Inbound SMTP

```text
23.226.136.206:25
        ↓ DNAT
10.77.0.2:25
```

### Outbound SMTP

```text
10.77.0.2
   ↓
masquerade as
23.226.136.206
```

Recommended `/etc/nftables.conf`:

```nft
#!/usr/sbin/nft -f

flush ruleset

table ip mail_gateway {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        iifname "eth0" tcp dport 25 dnat to 10.77.0.2:25
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        ip saddr 10.77.0.0/24 oifname "eth0" masquerade
    }
}
```

IPv4 forwarding must also be enabled:

```text
net.ipv4.ip_forward=1
```

---

## 5. Fresh VPS Recovery Procedure

Assume a new Ubuntu 24.04 RackNerd VPS.

### Install required packages

```bash
apt update

apt install -y \
  wireguard \
  wireguard-tools \
  nftables \
  tcpdump \
  dnsutils \
  curl \
  swaks
```

### Enable IPv4 forwarding

```bash
cat >/etc/sysctl.d/99-mail-gateway.conf <<'EOF'
net.ipv4.ip_forward=1
EOF

sysctl --system
```

Verify:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```text
net.ipv4.ip_forward = 1
```

---

## 6. Restore WireGuard

Create:

```bash
nano /etc/wireguard/wg0.conf
```

Use:

```ini
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = <YOUR_SAVED_RACKNERD_PRIVATE_KEY>

[Peer]
PublicKey = UGbgqbuo+b/e76dx39sfbNENTlFzQZEg0tPJVC3Vx3U=
AllowedIPs = 10.77.0.2/32
```

Protect it:

```bash
chmod 600 /etc/wireguard/wg0.conf
```

Enable and start WireGuard:

```bash
systemctl enable --now wg-quick@wg0
```

Verify:

```bash
wg
ip addr show wg0
```

The VPS should have:

```text
10.77.0.1/24
```

A WireGuard handshake from `docker-ct` should eventually appear.

---

## 7. Restore nftables

```bash
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table ip mail_gateway {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        iifname "eth0" tcp dport 25 dnat to 10.77.0.2:25
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        ip saddr 10.77.0.0/24 oifname "eth0" masquerade
    }
}
EOF
```

Load and enable it:

```bash
nft -f /etc/nftables.conf
systemctl enable --now nftables
```

Verify:

```bash
nft list ruleset
```

Important rules:

```text
tcp dport 25 dnat to 10.77.0.2:25
```

and:

```text
ip saddr 10.77.0.0/24 oifname "eth0" masquerade
```

---

## 8. Recovery Tests

### Test WireGuard connectivity

From RackNerd:

```bash
ping -c 3 10.77.0.2
```

### Verify Stalwart accepts the mailbox

```bash
swaks \
  --server 10.77.0.2 \
  --port 25 \
  --ehlo mx1.echodata.ca \
  --from probe@example.net \
  --to admin@echodata.ca \
  --quit-after RCPT
```

Expected critical result:

```text
RCPT TO:<admin@echodata.ca>
250 2.1.5 OK
```

### Verify outbound SMTP uses RackNerd public IP

From `docker-ct`:

```bash
curl --interface 10.77.0.2 -4 https://icanhazip.com
```

With the current VPS, expected:

```text
23.226.136.206
```

---

## 9. Back Up the Current RackNerd Configuration

Run on the currently working RackNerd VPS:

```bash
mkdir -p /root/mail-gateway-backup

cp -a /etc/wireguard/wg0.conf \
  /root/mail-gateway-backup/

cp -a /etc/nftables.conf \
  /root/mail-gateway-backup/

sysctl net.ipv4.ip_forward \
  >/root/mail-gateway-backup/ip-forwarding.txt

wg show \
  >/root/mail-gateway-backup/wireguard-status.txt

nft list ruleset \
  >/root/mail-gateway-backup/nftables-live.txt
```

Create an archive:

```bash
tar -C /root \
  -czf /root/racknerd-mail-gateway-backup.tar.gz \
  mail-gateway-backup
```

The archive contains the WireGuard private key through `wg0.conf`. Store it securely and do not publish or paste it into chats or tickets.

---

# 10. Stalwart Changes During Recovery

## Scenario A — Replacement VPS Keeps the Same Public IPv4

If RackNerd retains:

```text
23.226.136.206
```

and the same WireGuard private key is restored, Stalwart requires no changes.

Keep:

```text
Outbound Connection Strategy
EHLO hostname: mx1.echodata.ca
Source IP: 10.77.0.2
```

Keep the SMTP listener:

```text
10.77.0.2:25
```

DNS can remain:

```text
mx1.echodata.ca → 23.226.136.206
```

SPF can remain unchanged because it already authorizes:

```text
ip4:23.226.136.206
```

PTR remains:

```text
23.226.136.206 → mx1.echodata.ca
```

---

## Scenario B — Replacement VPS Has a New Public IPv4

Assume the new address is:

```text
NEW.IP.ADDRESS
```

### 1. Change the Cloudflare A record

Change:

```text
mx1.echodata.ca → 23.226.136.206
```

To:

```text
mx1.echodata.ca → NEW.IP.ADDRESS
```

Keep the record DNS-only, not Cloudflare proxied.

### 2. Change PTR / reverse DNS

Request from the VPS provider:

```text
NEW.IP.ADDRESS → mx1.echodata.ca
```

Verify:

```bash
dig -x NEW.IP.ADDRESS +short
```

Expected:

```text
mx1.echodata.ca.
```

### 3. Update SPF

The current SPF contains:

```text
ip4:23.226.136.206
```

Replace that portion with:

```text
ip4:NEW.IP.ADDRESS
```

Do not create a second SPF TXT record.

### 4. Update docker-ct WireGuard endpoint

Current home-side peer:

```ini
Endpoint = 23.226.136.206:51820
```

Change to:

```ini
Endpoint = NEW.IP.ADDRESS:51820
```

Restart WireGuard:

```bash
systemctl restart wg-quick@wg0
```

### Stalwart itself

As long as these stay the same:

```text
WireGuard Stalwart IP = 10.77.0.2
SMTP hostname         = mx1.echodata.ca
```

Stalwart should not require changes.

Keep:

```text
Outbound Connection Strategy
EHLO hostname: mx1.echodata.ca
Source IP: 10.77.0.2
```

Keep:

```text
SMTP listener: 10.77.0.2:25
```

Keep the existing DKIM keys and Stalwart data.

---

## 11. Scenario C — New VPS Has a New WireGuard Key

If the old RackNerd private key is unavailable, generate a new keypair on the replacement VPS:

```bash
umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey
```

Use the corresponding private key in the new VPS configuration:

```ini
PrivateKey = <NEW_RACKNERD_PRIVATE_KEY>
```

On `docker-ct`, replace the old RackNerd peer public key:

```ini
PublicKey = jgvY1NK0QF+deqVuMY29Dxf08pSwmcvvkUvlJY0hWHo=
```

with the new RackNerd public key.

The `docker-ct` WireGuard keypair can stay unchanged.

Restart WireGuard after updating the peer configuration:

```bash
systemctl restart wg-quick@wg0
```

---

## 12. What Does Not Depend on RackNerd

The following services remain on the home infrastructure and do not need to be rebuilt with the VPS:

```text
Stalwart mailboxes
Stalwart database
Stalwart DKIM private keys
Bulwark Webmail
JMAP
mail.echodata.ca
jmap.echodata.ca
Cloudflare Tunnel
```

Cloudflare Tunnel handles HTTP/JMAP/webmail independently of the SMTP VPS.

The intended separation is:

```text
                    ┌───────────────────┐
Browser ───────────►│ Cloudflare Tunnel │
                    └─────────┬─────────┘
                              ↓
                         Bulwark/JMAP
                              │
                              ↓
                         STALWART
                         10.77.0.2
                              │
                         WireGuard
                              │
                              ▼
                  ┌─────────────────────┐
                  │ Replaceable SMTP VPS│
                  │ RackNerd            │
                  └─────────┬───────────┘
                            │
                         Internet
```

---

## 13. Critical Recovery Items

The most important RackNerd recovery items are:

```text
1. /etc/wireguard/wg0.conf
2. /etc/nftables.conf
3. Current public IPv4 address
4. PTR relationship
5. Cloudflare A record for mx1.echodata.ca
6. SPF authorization for the public IPv4
```

The only truly secret and non-public item among these is the WireGuard private key.

If the key is lost, recovery is still possible by generating a new RackNerd WireGuard keypair and updating the peer public key on `docker-ct`.

---

## 14. Post-Recovery Validation Checklist

After rebuilding the VPS, verify all of the following:

```bash
wg
ip addr show wg0
ping -c 3 10.77.0.2
nft list ruleset
sysctl net.ipv4.ip_forward
dig A mx1.echodata.ca +short
dig -x <PUBLIC_IP> +short
dig MX echodata.ca +short
```

Then test SMTP recipient acceptance:

```bash
swaks \
  --server 10.77.0.2 \
  --port 25 \
  --ehlo mx1.echodata.ca \
  --from probe@example.net \
  --to admin@echodata.ca \
  --quit-after RCPT
```

Finally, send a real outbound test message and verify at the receiving provider:

```text
SPF: PASS
DKIM: PASS
DMARC: PASS
```

For the current configuration, Gmail previously confirmed all three passed when mail was sent from `23.226.136.206`.
