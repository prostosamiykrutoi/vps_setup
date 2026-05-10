# vps_setup

One-command script to deploy a hardened VPN server on a clean Ubuntu 20.04/22.04/24.04 VPS.

## What it installs

- **UFW** — firewall with minimal attack surface
- **fail2ban** — SSH brute-force protection
- **ICMP blocking** — hides server from ping sweeps
- **3x-ui** — VLESS+Reality proxy panel (Xray-core)
- **telemt** — MTProto proxy for Telegram

## Requirements

- Ubuntu 20.04 / 22.04 / 24.04
- Root access
- Clean VPS (fresh install recommended)

## Usage

```bash
bash <(curl -fsSL https://example.com/setup.sh)
```

Or clone and run locally:

```bash
git clone https://github.com/prostosamiykrutoi/vps_setup.git
cd vps_setup
bash setup.sh
```

## Modes

After selecting language (EN/RU) you choose:

| Mode | Behaviour |
|------|-----------|
| **Quick** | All defaults, no questions asked |
| **Step-by-step** | Prompts at each step; press Enter to accept default |

## Defaults

| Parameter | Default |
|-----------|---------|
| SSH port | 22 (unchanged) |
| telemt port | 8443 |
| VLESS SNI | auto-detected via RealiTLScanner, fallback `www.microsoft.com` |
| SSL cert | issued for server IP via Let's Encrypt (shortlived, 6 days) |

## Output

On completion a summary is printed and saved to `/root/server-credentials.txt` (mode 600):

- SSH port
- 3x-ui panel URL, login, password
- `vless://` connection link (ready to import into v2rayN / Hiddify / etc.)
- `tg://proxy` link for Telegram

## Log

All actions are logged to `/var/log/server-setup.log` with timestamps.  
Passwords and keys are **never** written to the log.
