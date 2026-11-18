# dfw

[![CI](https://github.com/danboy-lab/dfw/actions/workflows/ci.yml/badge.svg)](https://github.com/danboy-lab/dfw/actions/workflows/ci.yml)

**Hardened `ufw` profile for bug-bounty laptops.** Outbound-only by default,
silent DROPs ("shadowblocks"), public abuse blocklists loaded into `ipset`,
and a loopback-only canary for local connection detection.

> Run this on the local machine, **not over SSH**. The baseline step resets the
> current firewall rules. A rollback is always available.

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
- `honeypot.py` listens only on `127.0.0.1:8088` and logs local connections.

## What "shadowblock" means

A shadowblock is a silent drop: the packet is discarded without a REJECT or
ICMP response, so a scanner gets no answer. This is implemented by the default
`deny incoming` policy plus the `ipset ... -j DROP` rules. It is a technique,
not an external product.

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

## Options

| Option | Effect |
|---|---|
| `--baseline` | Back up, reset, and apply the default policies. |
| `--blocklists` | Download lists, load `ipset`, insert DROP rules, install the restore service. |
| `--all` | Baseline + blocklists. |
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

## Local canary

An external honeypot would require an inbound rule, which conflicts with the
hardened profile. This canary is therefore local-only: it detects an internal
process making an unexpected connection to port 8088.

```bash
mkdir -p ~/.config/systemd/user
cp bb-honeypot.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now bb-honeypot.service

python3 -c "import socket; socket.create_connection(('127.0.0.1', 8088), 1).close()"
tail -1 ~/Documents/bugbounty/honeypot/connections.log
```

The log path can be overridden with the `BB_HONEYPOT_LOG` environment variable.

## Tests

Run locally before opening a pull request:

```bash
bash tests/test_shell.sh
python -m unittest discover -s tests -p 'test_*.py' -v
```

CI (`.github/workflows/ci.yml`) runs on pushes and pull requests:

- **Shell job:** `bash -n`, `shellcheck`, and the shell test suite.
- **Python job:** `unittest` on Python 3.10, 3.11 and 3.12.
- Both jobs run on `ubuntu-latest` and require no network calls to external
  targets beyond package installation.

## Limitations

- A blocklist is defense in depth, not a replacement for `deny incoming`.
- False positives happen: remove one with `sudo ipset del bb-blocklist <IP/CIDR>`.
- Use `sudo ufw logging medium` temporarily for investigation, then return to `low`.
- The script does not touch Docker/ufw-docker or VPNs with inbound tunnels
  (Tailscale, WireGuard). Add explicit rules there if you use them.
- List downloads require outbound HTTPS; if a source fails, the script warns and
  continues with the remaining sources.

## Blocklist sources

- https://www.spamhaus.org/drop/
- https://lists.blocklist.de/
- https://github.com/stamparm/ipsum
