# RayZen Vortex Server

[فارسی](README.fa.md)

A fast DNS-tunnel server for the **RayZen Vortex-53** Android app (v1.4.0 or newer), installed on a Linux VPS with one command. Installation time varies by system and network.

- **Service recovery:** a watchdog restarts the service when its DNS health checks stop succeeding. Performance depends on the network and resolver.
- **Several domains:** add more domains to the same server. The app tests them all, uses the fastest and moves on if one gets blocked.
- **Nothing compiled on your VPS:** a ready `linux/amd64` or `linux/arm64` binary is downloaded and checked against its SHA-256 before it runs.
- **Upgrade in place:** an older Vortex-53 server on the same VPS is upgraded and keeps its key and domain.

## Requirements

- A VPS with a public IPv4 address, `ss` (from iproute2), and a systemd Linux (Ubuntu 20.04+ or Debian 11+), **x86_64** or **arm64**.
- UDP port 53 reachable from the internet (open it in your provider's firewall panel too).
- A domain whose DNS you control.

## 1. DNS records

Pick a tunnel domain, for example `t.example.com`, and add two records in your domain's DNS panel:

| name | type | value |
|---|---|---|
| `ns.example.com` | A | your VPS IP |
| `t.example.com` | NS | `ns.example.com` |

It can take a few minutes until the delegation is visible.

## 2. Install

```bash
curl -fsSL https://github.com/MattyMatinSys/RayZen-Vortex-Server/releases/latest/download/install.sh | sudo bash -s -- --domain t.example.com
```

At the end it prints a `vortex://p/…` link. In the app tap **Add → Paste** (or just open the link on the phone).

More install options: `--domain` (repeatable), `--port 53`, `--ip PUBLIC_IP`, `--name "Profile name"`, `--ns-host ns.example.com`, `--version X.Y.Z`, `--from DIR` (offline install), `--yes`, `--no-dns-check`, `--no-tune`.

## 3. Manage

After the first install the same script is available as `vortexctl`:

```bash
sudo vortexctl link                       # print the connection link again
sudo vortexctl status                     # service state, live counters, real tunnel self test
sudo vortexctl check-dns                  # check the domain delegation
sudo vortexctl add-domain t2.example.net  # one more domain (then paste the new link in the app)
sudo vortexctl remove-domain t2.example.net
sudo vortexctl update                     # newest release, verified, then restart
sudo vortexctl rotate-key                 # new key: every old link stops working
sudo vortexctl backup | logs | uninstall [--purge]
```

After `add-domain`, paste the new link in the app again: the saved server only gains the new domains (name and settings stay).

## What the installer changes

`/usr/local/bin/vortex-server`, `/usr/local/sbin/vortexctl`, `/etc/vortex-server/`, `/etc/systemd/system/vortex-server.service`, `/etc/sysctl.d/90-vortex-server.conf`, the system user `vortex-server`, and (only if needed to free UDP/53) the stub listener of `systemd-resolved`. If `ufw` or `firewalld` is active, UDP/53 is opened.

## Verify a download

Every release has `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS
```

## Limits

- The current StormDNS/Vortex tunnel does not encrypt or authenticate downstream DNS response frames, even when AES-GCM is selected for query-side data. Use application-layer TLS for sensitive traffic; the tunnel itself does not provide end-to-end confidentiality or authentication.
- The link carries the server key: share it only with people you trust.
- How fast it is depends on the resolvers your phone's network allows; on a heavily filtered network add a second domain and use the app's resolver scanner.

## Licence

See [LICENSE](LICENSE) and [NOTICE](NOTICE). Built on StormDNS (MIT).

## Build from source

The server-only source, reproducible build commands, test scope, and architecture details are documented in [BUILD.md](BUILD.md). The Android application and its private code are not included.

The local status/self-check performs MTU probes and establishes a temporary tunnel session. A passing local test does not establish that a remote resolver or mobile network can reach the server. `vortexctl bench` measures DNS probe payload rates, not application throughput.
