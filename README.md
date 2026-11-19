# dfw

[![CI](https://github.com/danboy-lab/dfw/actions/workflows/ci.yml/badge.svg)](https://github.com/danboy-lab/dfw/actions/workflows/ci.yml)

**Hardened `ufw` profile for bug-bounty laptops.** Outbound-only by default,
silent DROPs for listed hosts, public abuse blocklists loaded into `ipset`,
an opt-in internet honeypot, and a terminal dashboard for live monitoring.

> Execution is intended on the local machine, **not over SSH**. The baseline
> step resets the current firewall rules. A rollback is always available.

## Features

- `deny incoming`, `allow outgoing`, `deny routed`, IPv6 enabled, explicit loopback.
- Downloads public abuse lists (Spamhaus DROP/EDROP, blocklist.de, IPsum), strips
  comments, deduplicates, and **filters private, reserved and LAN ranges** so
  local DNS/LAN traffic keeps working.
- Loads the result into an `ipset` hash named `bb-blocklist`.
- Adds two silent rules to `/etc/ufw/before.rules`:
  - `ufw-before-input` → `DROP` for listed source IPs (no REJECT/ICMP reply);
  - `ufw-before-output` → `DROP` for listed destination IPs.
- Installs `bb-ipset.service` so the set is restored before `ufw` at boot.
- Optional `--honeypot` opens `22,23,80,8080/tcp` and starts a decoy that logs
  source addresses and payloads.
- Optional `--dashboard` renders a curses monitor with firewall state, set size,
  established connections and recent honeypot hits.

## Shadowsocks

Shadowsocks is an outbound-only proxy. The local SOCKS5 listener should bind to
loopback (for example `127.0.0.1:8388`) and the client connects to the remote
server through the allowed outgoing traffic. No inbound `ufw` rule is needed,
and the local proxy port must not be exposed to the network.

## Requirements

- Arch Linux (the `--install-deps` option uses `pacman`).
- `ufw`, `iptables`, `curl`, `ipset`, `python3` (for the canary and tests).

## Quick start

```bash
git clone https://github.com/danboy-lab/dfw.git
cd dfw

sudo bash ufw-hardened.sh --install-deps   # only if ipset/curl are missing
sudo bash ufw-hardened.sh --all
sudo bash ufw-hardened.sh --verify
```

Expected `--verify` output:

```
Status:                   active
Default:                  deny (incoming), allow (outgoing), deny (routed)
```

The verify step also prints the first lines of the `ipset`, any non-loopback
listeners, and an outbound connectivity check.

To apply the profile together with the internet decoy and open the monitor:

```bash
sudo bash ufw-hardened.sh --all --honeypot --dashboard
```

## Options

| Option | Effect |
|---|---|
| `--baseline` | Back up, reset, and apply the default policies. |
| `--blocklists` | Download lists, load `ipset`, insert DROP rules, install the restore service. |
| `--all` | Baseline + blocklists. |
| `--honeypot` | Open `22,23,80,8080/tcp` to any source and start the decoy service. |
| `--dashboard` | Open the curses monitor after the selected actions finish. |
| `--verify` | Show firewall state, set contents, listeners and outbound check. |
| `--rollback` | Restore the most recent backup. |
| `--install-deps` | Install `ipset` and `curl` via `pacman`. |
| `-y`, `--yes` | Skip the reset confirmation. |
| `-h`, `--help` | Show usage. |

## Rollback

Before changing anything, the script saves state to
`/tmp/bb-ufw-backup/<timestamp>/`. To restore it:

```bash
sudo bash ufw-hardened.sh --rollback
```

The original `ufw` state is preserved, including whether it was inactive.

## Internet honeypot

`--honeypot` is an explicit deviation from the default deny-incoming profile:
it opens `22,23,80,8080/tcp` to any source and starts `dfw-honeypot.service`.
The decoy answers with simple SSH, Telnet and HTTP banners and appends every
source address and payload to `~/Documents/bugbounty/honeypot/connections.log`.

Port 8080 may conflict with a local proxy such as Burp. The script warns when a
port is already bound; the decoy keeps listening on the remaining ports. The
service runs as the invoking user with `CAP_NET_BIND_SERVICE` so ports 22 and 23
can be bound without running the decoy as root.

The log path can be overridden with `BB_HONEYPOT_LOG`.

## Dashboard

`--dashboard` starts a curses monitor after the other actions. It shows `ufw`
status, the blocklist member count, established connections and the latest
honeypot hits. Quit with `q`. It can also be started directly:

```bash
sudo python3 dashboard.py
```

Root privileges are expected so the monitor can read firewall and `ipset` state.
When launched with `sudo`, the log path is resolved from `SUDO_USER`, so hits
written by the decoy are displayed correctly.

## Tests

Run locally before opening a pull request:

```bash
bash tests/test_shell.sh
python -m unittest discover -s tests -p 'test_*.py' -v
```

CI (`.github/workflows/ci.yml`) runs on pushes and pull requests:

- **Shell job:** `bash -n`, `shellcheck`, and the shell test suite.
- **Python job:** `unittest` on Python 3.10, 3.11 and 3.12 for the honeypot and
  dashboard helpers.
- Both jobs run on `ubuntu-latest` and require no network calls to external
  targets beyond package installation.

## Limitations

- A blocklist is defense in depth, not a replacement for `deny incoming`.
- `--honeypot` intentionally opens inbound ports and is not part of `--all`.
- A port already bound by another service is reported in the honeypot log; the
  decoy keeps listening on the remaining ports.
- False positives happen: remove one with `sudo ipset del bb-blocklist <IP/CIDR>`.
- Use `sudo ufw logging medium` temporarily for investigation, then return to `low`.
- The script does not touch Docker/ufw-docker or VPNs with inbound tunnels
  (Tailscale, WireGuard). Add explicit rules there when those tunnels are in use.
- List downloads require outbound HTTPS; if a source fails, the script warns and
  continues with the remaining sources.

## Blocklist sources

- https://www.spamhaus.org/drop/
- https://lists.blocklist.de/
- https://github.com/stamparm/ipsum
