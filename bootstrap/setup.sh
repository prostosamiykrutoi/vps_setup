#!/usr/bin/env bash
# shroud bootstrap — thin bash layer (<=150 lines).
# Responsibilities ONLY: sanity checks, install runtime, fetch code, hand over to the
# Python orchestrator. All real logic lives in the `shroud` Python package.
#
# Usage:
#   bash <(curl -fsSL https://<host>/setup.sh) [-- <shroud args...>]
#   ./bootstrap/setup.sh -- install --role standalone --mode quick
set -Eeuo pipefail

REPO_URL="${SHROUD_REPO_URL:-https://github.com/prostosamiykrutoi/vps_setup}"
REPO_REF="${SHROUD_REPO_REF:-claude/shroud-orchestrator}"
INSTALL_DIR="${SHROUD_INSTALL_DIR:-/opt/shroud}"
VENV_DIR="${INSTALL_DIR}/.venv"

log()  { printf '\033[36m[bootstrap]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[bootstrap:err]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---- 1. sanity checks --------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must run as root"

. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04) : ;;
  ubuntu:*) log "WARNING: untested Ubuntu ${VERSION_ID}; supported: 22.04, 24.04" ;;
  *) die "unsupported OS '${ID:-?} ${VERSION_ID:-?}'; shroud supports Ubuntu 22.04/24.04" ;;
esac

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
  amd64|x86_64|arm64|aarch64) log "architecture: $ARCH" ;;
  *) die "unsupported architecture '$ARCH'; shroud supports amd64/arm64" ;;
esac

# ---- 2. base apt dependencies ------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
ensure_pkg() {
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p")
  done
}
# On a freshly-booted VPS, cloud-init / unattended-upgrades often hold the apt
# lock. Wait for it (up to ~3 min) instead of failing the whole install.
wait_for_apt() {
  local tries=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -gt 36 ] && { log "WARNING: apt still locked after ~3min; proceeding"; break; }
    log "apt is locked by another process; waiting... (${tries}/36)"
    sleep 5
  done
}
apt_get() { wait_for_apt; DEBIAN_FRONTEND=noninteractive apt-get "$@"; }

MISSING=()
ensure_pkg python3 python3-venv python3-pip git curl jq openssl ca-certificates
if [ "${#MISSING[@]}" -gt 0 ]; then
  log "installing: ${MISSING[*]}"
  apt_get update -qq || die "apt-get update failed"
  apt_get install -y -qq "${MISSING[@]}" || die "failed installing: ${MISSING[*]}"
fi

# ---- 3. Docker (official repo, not distro) -----------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker from official repository"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc || die "failed to fetch docker gpg key"
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt_get update -qq || die "apt-get update (docker repo) failed"
  apt_get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin || die "docker install failed"
  systemctl enable --now docker >/dev/null 2>&1 || true
else
  log "docker already present: $(docker --version 2>/dev/null || echo unknown)"
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

# ---- 4. fetch / update code --------------------------------------------------
if [ -d "${INSTALL_DIR}/.git" ]; then
  log "updating existing checkout in ${INSTALL_DIR}"
  git -C "$INSTALL_DIR" fetch --depth 1 origin "$REPO_REF" || die "git fetch failed"
  git -C "$INSTALL_DIR" checkout -q FETCH_HEAD || die "git checkout failed"
elif [ -f "$(dirname "$0")/../shroud/cli.py" ]; then
  # Running from inside a checkout already (local dev / acceptance test).
  INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
  VENV_DIR="${INSTALL_DIR}/.venv"
  log "running from local checkout: ${INSTALL_DIR}"
else
  log "cloning ${REPO_URL}@${REPO_REF} into ${INSTALL_DIR}"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$INSTALL_DIR" \
    || die "git clone failed"
fi

# ---- 5. python venv + package ------------------------------------------------
if [ ! -x "${VENV_DIR}/bin/python" ]; then
  log "creating venv at ${VENV_DIR}"
  python3 -m venv "$VENV_DIR" || die "venv creation failed"
fi
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
log "installing shroud package into venv (editable; keeps profiles/ + decoy/ authoritative)"
# Editable so the on-disk checkout (which holds profiles/, decoy/, render/) stays
# the source of truth — these live at the repo root, outside the importable package.
"${VENV_DIR}/bin/pip" install --quiet --editable "${INSTALL_DIR}" || die "pip install shroud failed"

# Expose `shroud` globally so `shroud status|verify|show-sub|update` work without
# the venv path.
ln -sf "${VENV_DIR}/bin/shroud" /usr/local/bin/shroud 2>/dev/null || true

# ---- 6. hand over to orchestrator -------------------------------------------
# Everything after a literal `--` is passed straight to `shroud`.
ARGS=()
seen_sep=0
for a in "$@"; do
  if [ "$seen_sep" -eq 1 ]; then ARGS+=("$a"); fi
  if [ "$a" = "--" ]; then seen_sep=1; fi
done
if [ "${#ARGS[@]}" -eq 0 ]; then
  ARGS=(install)
fi

log "handing over to: shroud ${ARGS[*]}"
exec "${VENV_DIR}/bin/shroud" "${ARGS[@]}"
