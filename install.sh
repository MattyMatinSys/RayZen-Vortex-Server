#!/usr/bin/env bash
# RayZen Vortex server — one-command installer and manager for a Linux VPS (x86_64 or arm64, systemd).
#
#   curl -fsSL https://github.com/MattyMatinSys/RayZen-Vortex-Server/releases/latest/download/install.sh \
#     | sudo bash -s -- --domain t.example.com
#
# After the first install the same script is available as `vortexctl`:
#   sudo vortexctl link                     print the connection link again
#   sudo vortexctl status                   service state, live counters, self test
#   sudo vortexctl check-dns                check the domain delegation
#   sudo vortexctl add-domain t2.example.net | remove-domain t2.example.net
#   sudo vortexctl update [--version 1.0.1] download a newer release and restart
#   sudo vortexctl rotate-key               new key (every old link stops working)
#   sudo vortexctl backup | logs | uninstall [--purge] | uninstall-legacy
#
# Install options: --domain D (repeatable) --port 53 --ip PUBLIC_IP --name "Profile name"
#   --ns-host ns.example.com --version X.Y.Z --from DIR (offline: binary + SHA256SUMS in DIR)
#   --yes (no questions) --no-dns-check --no-tune
#
# What it changes: /usr/local/bin/vortex-server, /usr/local/sbin/vortexctl, /etc/vortex-server/,
# /etc/systemd/system/vortex-server.service, /etc/sysctl.d/90-vortex-server.conf, the system user
# vortex-server, and (only if needed for UDP/53) systemd-resolved's stub listener.
set -euo pipefail

# Filled in by the release workflow; a copy from the repo falls back to the latest release.
RELEASE_VERSION="__VORTEX_VERSION__"
RELEASE_SHA256="__VORTEX_SHA256__"
RELEASE_SHA256_ARM64="__VORTEX_SHA256_ARM64__"
REPO="${VORTEX_REPO:-MattyMatinSys/RayZen-Vortex-Server}"
ASSET="vortex-server-linux-amd64"

# Paths (overridable for tests only).
BIN="${VORTEX_BIN:-/usr/local/bin/vortex-server}"
CTL="${VORTEX_CTL:-/usr/local/sbin/vortexctl}"
ETC="${VORTEX_ETC:-/etc/vortex-server}"
CFG="$ETC/server.toml"
UNIT_DIR="${VORTEX_UNIT_DIR:-/etc/systemd/system}"
UNIT="$UNIT_DIR/vortex-server.service"
SYSCTL_FILE="${VORTEX_SYSCTL_FILE:-/etc/sysctl.d/90-vortex-server.conf}"
RESOLVED_DROPIN="${VORTEX_RESOLVED_DROPIN:-/etc/systemd/resolved.conf.d/vortex-server.conf}"
LEGACY="${VORTEX_LEGACY_BASE:-/opt/vortex53}"
SVC_USER=vortex-server

DOMAINS=()
PORT=53
PUBLIC_IP=""
NAME=""
NS_HOST=""
WANT_VERSION=""
FROM_DIR=""
YES=0
DNS_CHECK=1
TUNE=0 # v2: no blanket kernel tuning unless --tune is given
PURGE=0
PIN=1 # install: use the release this script belongs to; update: latest unless --version
ARGS=()

c_blue=$'\033[1;34m' c_red=$'\033[1;31m' c_green=$'\033[1;32m' c_yellow=$'\033[1;33m' c_off=$'\033[0m'
if [ ! -t 1 ]; then c_blue="" c_red="" c_green="" c_yellow="" c_off=""; fi
log() { printf '%s==>%s %s\n' "$c_blue" "$c_off" "$*"; }
ok() { printf '%s[ok]%s %s\n' "$c_green" "$c_off" "$*"; }
warn() { printf '%s[warning]%s %s\n' "$c_yellow" "$c_off" "$*" >&2; }
die() {
  printf '%s[error]%s %s\n' "$c_red" "$c_off" "$*" >&2
  exit 1
}

have_tty() { [ "$YES" = 0 ] && { : < /dev/tty; } 2> /dev/null; }

# ask VAR "question" [default]  (reads the terminal even when the script comes from a pipe)
ask() {
  local __v=$1 q=$2 d=${3:-} a=""
  if ! have_tty; then
    printf -v "$__v" '%s' "$d"
    return
  fi
  read -r -p "$q${d:+ [$d]}: " a < /dev/tty || true
  printf -v "$__v" '%s' "${a:-$d}"
}

confirm() { # confirm "question"  -> 0 yes, 1 no; --yes answers yes
  [ "$YES" = 1 ] && return 0
  have_tty || return 0
  local a=""
  read -r -p "$1 [y/N]: " a < /dev/tty || true
  [[ "$a" =~ ^[Yy] ]]
}

need_root() { [ "$(id -u)" = 0 ] || die "run as root: curl ... | sudo bash -s -- --domain t.example.com"; }

check_platform() {
  [ "$(uname -s)" = Linux ] || die "Linux only"
  case "${VORTEX_TEST_ARCH:-$(uname -m)}" in
    x86_64 | amd64) ;;
    aarch64 | arm64) ASSET="vortex-server-linux-arm64" RELEASE_SHA256=$RELEASE_SHA256_ARM64 ;;
    *) die "this release supports x86_64 and arm64 servers only; this server is $(uname -m)" ;;
  esac
  command -v systemctl > /dev/null || die "systemd is required"
  command -v ss > /dev/null || die "ss is required to check the UDP port (install the iproute2 package)"
  local os_id="" os_name=""
  if [ -r /etc/os-release ]; then
    # Read in a subshell: os-release defines NAME, which is also our --name option.
    # shellcheck source=/dev/null
    os_id=$(. /etc/os-release && echo "${ID:-}")
    # shellcheck source=/dev/null
    os_name=$(. /etc/os-release && echo "${PRETTY_NAME:-}")
    case "$os_id" in ubuntu | debian) ;; *) warn "untested OS ${os_name:-unknown} (tested: Ubuntu 22.04/24.04, Debian 12/13)" ;; esac
  fi
}

parse() {
  ARGS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain | -d)
        [ $# -ge 2 ] || die "--domain needs a value"
        local IFS=,
        for x in $2; do [ -n "$x" ] && DOMAINS+=("$x"); done
        shift
        ;;
      --domain=*) DOMAINS+=("${1#*=}") ;;
      --port) PORT=${2:?}; shift ;;
      --ip) PUBLIC_IP=${2:?}; shift ;;
      --name) NAME=${2:?}; shift ;;
      --ns-host) NS_HOST=${2:?}; shift ;;
      --version) WANT_VERSION=${2#v}; shift ;;
      --from) FROM_DIR=${2:?}; shift ;;
      --yes | -y) YES=1 ;;
      --no-dns-check) DNS_CHECK=0 ;;
      --no-tune) TUNE=0 ;;
      --tune) TUNE=1 ;;
      --purge) PURGE=1 ;;
      -h | --help) usage; exit 0 ;;
      --*) die "unknown option $1 (see --help)" ;;
      *) ARGS+=("$1") ;;
    esac
    shift
  done
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then die "invalid --port $PORT"; fi
}

usage() {
  cat << 'USAGE'
RayZen Vortex server installer / manager (vortexctl)

  install (default)        install or upgrade:  --domain t.example.com [--domain t2.example.net]
  link                     print the connection link (app v1.4.0 or newer)
  status                   service state, version, domains, sessions, uptime and a real tunnel self test
  doctor                   check dependencies, DNS delegation, port 53, firewall, config and service (with fixes)
  bench                    loopback tunnel throughput (download and upload)
  rollback                 restore the previous binary and config
  check-dns                check that the domains are delegated to this server
  add-domain D | remove-domain D
  update [--version X.Y.Z] download, verify SHA-256, back up, swap, restart; rolls back if health fails
  rotate-key               make a new key (every old link stops working)
  backup | logs [N] | uninstall [--purge] | uninstall-legacy

Install options: --port 53  --ip PUBLIC_IP  --name "Profile name"  --ns-host ns.example.com
  --version X.Y.Z  --from DIR (offline: vortex-server-linux-amd64 + SHA256SUMS in DIR)
  --yes (no questions)  --no-dns-check  --tune (opt-in UDP buffer / BBR sysctl tuning)
USAGE
}

fetch() { # fetch URL OUT
  if command -v curl > /dev/null; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
  elif command -v wget > /dev/null; then
    wget -q -O "$2" "$1"
  else
    die "curl or wget is needed"
  fi
}

release_base() {
  local v=${WANT_VERSION:-}
  if [ -z "$v" ] && [ "$PIN" = 1 ] && [[ "$RELEASE_VERSION" != __* ]]; then v=$RELEASE_VERSION; fi
  if [ -n "$v" ]; then echo "https://github.com/$REPO/releases/download/v$v"; else echo "https://github.com/$REPO/releases/latest/download"; fi
}

# download_binary DEST_DIR -> DEST_DIR/vortex-server (checksum verified)
download_binary() {
  local d=$1 want=""
  if [ -n "$FROM_DIR" ]; then
    [ -f "$FROM_DIR/$ASSET" ] || die "$FROM_DIR/$ASSET not found"
    cp "$FROM_DIR/$ASSET" "$d/vortex-server"
    [ -f "$FROM_DIR/SHA256SUMS" ] && cp "$FROM_DIR/SHA256SUMS" "$d/SHA256SUMS"
  else
    local base
    base=$(release_base)
    log "downloading $ASSET ($base)"
    fetch "$base/$ASSET" "$d/vortex-server" || die "download failed: $base/$ASSET"
    fetch "$base/SHA256SUMS" "$d/SHA256SUMS" || true
  fi
  if [ -z "$WANT_VERSION" ] && [ -z "$FROM_DIR" ] && [ "$PIN" = 1 ] && [[ "$RELEASE_SHA256" != __* ]]; then
    want=$RELEASE_SHA256 # pinned into this script by the release
  elif [ -f "$d/SHA256SUMS" ]; then
    want=$(awk -v a="$ASSET" '$2 == a || $2 == "*"a {print $1}' "$d/SHA256SUMS" | head -1)
  fi
  [ -n "$want" ] || die "no checksum available for $ASSET; refusing to install an unverified binary"
  echo "$want  $d/vortex-server" | sha256sum -c - > /dev/null 2>&1 || die "checksum mismatch for $ASSET (download corrupted or tampered)"
  chmod 755 "$d/vortex-server"
  ok "binary verified (sha256 ${want:0:16}...)"
}

install_binary() {
  local t
  t=$(mktemp -d)
  download_binary "$t"
  "$t/vortex-server" version > /dev/null 2>&1 || die "the downloaded binary does not run on this server"
  install -d "$(dirname "$BIN")"
  [ -x "$BIN" ] && cp -f "$BIN" "$BIN.prev"
  install -m 755 "$t/vortex-server" "$BIN.new" && mv -f "$BIN.new" "$BIN"
  rm -rf "$t"
  ok "installed $("$BIN" version)"
}

install_ctl() {
  local self="${BASH_SOURCE[0]:-}"
  install -d "$(dirname "$CTL")"
  if [ -n "$self" ] && [ -f "$self" ] && [ "$self" != "$CTL" ]; then
    install -m 755 "$self" "$CTL"
  elif [ ! -f "$CTL" ] || [ -n "$WANT_VERSION" ] || [ "${1:-}" = refresh ]; then
    # Piped from curl: fetch this release's installer as the manager command.
    local t
    t=$(mktemp)
    if [ -n "$FROM_DIR" ] && [ -f "$FROM_DIR/install.sh" ]; then cp "$FROM_DIR/install.sh" "$t"; else fetch "$(release_base)/install.sh" "$t" || true; fi
    if [ -s "$t" ] && bash -n "$t" 2> /dev/null; then install -m 755 "$t" "$CTL"; fi
    rm -f "$t"
  fi
  if [ -x "$CTL" ]; then
    ln -sf "$CTL" "$(dirname "$CTL")/vortex" 2> /dev/null || true
    ok "manager command: vortexctl / vortex ($CTL)"
  else
    warn "could not install vortexctl; re-run the install command to manage the server"
  fi
}

ensure_user() {
  id -u "$SVC_USER" > /dev/null 2>&1 && return
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER" 2> /dev/null ||
    adduser --system --no-create-home --group "$SVC_USER" > /dev/null 2>&1 || die "could not create user $SVC_USER"
}

fix_perms() {
  chown root:"$SVC_USER" "$ETC" && chmod 750 "$ETC"
  [ -f "$CFG" ] && chown root:"$SVC_USER" "$CFG" && chmod 640 "$CFG"
  [ -f "$ETC/key.txt" ] && chown root:"$SVC_USER" "$ETC/key.txt" && chmod 640 "$ETC/key.txt"
  return 0
}

# ---- legacy (server/install.sh of app v1.0-v1.3, /opt/vortex53) ----
LEGACY_DOMAIN=""
LEGACY_KEY=""
legacy_detect() {
  local m="$LEGACY/instances/main"
  [ -d "$m" ] || return 1
  LEGACY_DOMAIN=$(head -1 "$m/domain" 2> /dev/null || true)
  [ -s "$m/encrypt_key.txt" ] && LEGACY_KEY="$m/encrypt_key.txt"
  return 0
}

legacy_units() {
  local u
  for u in "$UNIT_DIR"/vortex53-*.service "$UNIT_DIR"/vortex53router.service; do
    [ -e "$u" ] && basename "$u"
  done
  return 0
}

legacy_stop() {
  local u
  for u in $(legacy_units); do
    systemctl disable --now "$u" > /dev/null 2>&1 || true
  done
  [ -f "$LEGACY/router.conf" ] || true
}

legacy_friends() {
  local d n
  for d in "$LEGACY"/instances/*/; do
    n=$(basename "$d")
    [ "$n" = main ] && continue
    [ -f "$d/domain" ] && echo "$n ($(head -1 "$d/domain"))"
  done
  return 0
}

# ---- UDP/53, firewall, kernel tuning ----
port_owner() { ss -H -lunp "sport = :$PORT" 2> /dev/null | grep -oE 'users:\(\("[^"]+"' | head -1 | sed -E 's/^users:\(\("//; s/"$//'; }

free_port() {
  local owner sockets
  sockets=$(ss -H -lunp "sport = :$PORT" 2> /dev/null) || die "could not inspect UDP/$PORT with ss"
  [ -n "$sockets" ] || return 0
  owner=$(port_owner || true)
  case "$owner" in
    vortex-server) return 0 ;;
    systemd-resolve*)
      log "freeing UDP/$PORT from systemd-resolved (DNSStubListener=no)"
      mkdir -p "$(dirname "$RESOLVED_DROPIN")"
      printf '[Resolve]\nDNSStubListener=no\n' > "$RESOLVED_DROPIN"
      if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -q stub-resolv; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
      fi
      systemctl restart systemd-resolved
      sleep 1
      ;;
  esac
  sockets=$(ss -H -lunp "sport = :$PORT" 2> /dev/null) || die "could not inspect UDP/$PORT with ss"
  owner=$(port_owner || true)
  if [ -n "$sockets" ] && [ "$owner" != vortex-server ]; then
    die "UDP/$PORT is already in use by '${owner:-an unknown process}'. Stop it and run the command again."
  fi
}

open_firewall() {
  if command -v ufw > /dev/null && ufw status 2> /dev/null | grep -q "Status: active"; then
    ufw allow "$PORT"/udp > /dev/null && ok "ufw: allowed $PORT/udp"
  elif command -v firewall-cmd > /dev/null && firewall-cmd --state > /dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$PORT"/udp && firewall-cmd -q --reload && ok "firewalld: allowed $PORT/udp"
  else
    log "no active ufw/firewalld; make sure UDP $PORT is open in your provider's firewall panel"
  fi
}

tune_kernel() {
  [ "$TUNE" = 1 ] || return 0
  local cc=""
  modprobe tcp_bbr 2> /dev/null || true
  grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2> /dev/null && cc=bbr
  mkdir -p "$(dirname "$SYSCTL_FILE")"
  {
    echo "# RayZen Vortex server: bigger UDP buffers for bursts of DNS queries, faster upstream TCP."
    echo "net.core.rmem_max = 16777216"
    echo "net.core.wmem_max = 16777216"
    echo "net.core.netdev_max_backlog = 16384"
    echo "net.ipv4.udp_rmem_min = 16384"
    echo "net.ipv4.udp_wmem_min = 16384"
    echo "net.ipv4.tcp_fastopen = 3"
    echo "net.ipv4.tcp_slow_start_after_idle = 0"
    if [ -n "$cc" ]; then
      echo "net.core.default_qdisc = fq"
      echo "net.ipv4.tcp_congestion_control = bbr"
    fi
  } > "$SYSCTL_FILE"
  if sysctl -q -p "$SYSCTL_FILE" > /dev/null 2>&1; then
    ok "kernel network tuning applied${cc:+ (BBR on)}"
  else
    warn "some kernel settings could not be applied (container VPS?); the server still works"
  fi
}

write_unit() {
  install -d "$UNIT_DIR"
  cat > "$UNIT" << EOF
[Unit]
Description=RayZen Vortex DNS tunnel server
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
ExecStart=$BIN run --config $CFG
User=$SVC_USER
Group=$SVC_USER
RuntimeDirectory=vortex-server
Restart=always
RestartSec=2
TimeoutStartSec=30
TimeoutStopSec=10
WatchdogSec=30
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadOnlyPaths=$ETC

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

restart_service() {
  systemctl enable -q vortex-server 2> /dev/null || true
  if ! systemctl restart vortex-server; then
    journalctl -u vortex-server -n 30 --no-pager 2> /dev/null || true
    warn "vortex-server did not start (log above)"
    return 1
  fi
  ok "vortex-server is running"
}

dns_check() { # 0 = delegation works, 1 = not yet, 2 = skipped (--no-dns-check)
  [ "$DNS_CHECK" = 1 ] || return 2
  local ipflag=() before after rc
  [ -n "$PUBLIC_IP" ] && ipflag=(--ip "$PUBLIC_IP")
  before=$(grep -E '^VORTEX_NS_HOST' "$CFG" || true)
  while :; do
    echo
    log "checking DNS delegation"
    set +e
    "$BIN" check-dns --config "$CFG" --write-ns-host "${ipflag[@]}"
    rc=$?
    set -e
    after=$(grep -E '^VORTEX_NS_HOST' "$CFG" || true)
    if [ "$before" != "$after" ]; then
      fix_perms
      systemctl restart vortex-server && before=$after
    fi
    [ $rc = 0 ] && return 0
    if have_tty; then
      local a=""
      read -r -p "Add the DNS records shown above, wait a minute, then press Enter to check again (or type skip): " a < /dev/tty || a=skip
      [ "$a" = skip ] && break
    else
      break
    fi
  done
  warn "the domain is not reachable through public DNS yet. DNS changes can take up to an hour;"
  warn "check again later with: sudo vortexctl check-dns"
  return 1
}

show_link() {
  echo
  "$BIN" link --config "$CFG"
}

rollback_install_on_exit() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "${INSTALL_ROLLBACK_ARMED:-0}" = 1 ]; then
    warn "upgrade failed; restoring the previous binary and configuration"
    set +e
    cmd_rollback
  fi
  exit "$rc"
}

# ---- commands ----
cmd_install() {
  need_root
  check_platform
  local t0=$SECONDS upgrading=0 had_binary=0
  [ -f "$CFG" ] && upgrading=1
  [ -x "$BIN" ] && had_binary=1

  if [ $upgrading = 0 ] && legacy_detect; then
    log "found the older Vortex-53 server in $LEGACY (domain ${LEGACY_DOMAIN:-unknown}); upgrading it in place"
    local friends
    friends=$(legacy_friends)
    if [ -n "$friends" ]; then
      warn "these friend instances from the old server will stop working:"
      printf '    %s\n' "$friends" >&2
      warn "add their domains later with 'vortexctl add-domain' (they then use the new link)"
      confirm "Continue?" || die "cancelled"
    fi
    [ ${#DOMAINS[@]} -gt 0 ] || { [ -n "$LEGACY_DOMAIN" ] && DOMAINS=("$LEGACY_DOMAIN"); }
  fi

  if [ $upgrading = 0 ] && [ ${#DOMAINS[@]} -eq 0 ]; then
    local d=""
    ask d "Tunnel domain delegated to this server (e.g. t.example.com)"
    [ -n "$d" ] || die "a domain is required: --domain t.example.com"
    DOMAINS=("$d")
  fi

  if [ "$upgrading" = 1 ]; then
    PORT=$(sed -nE 's/^UDP_PORT *= *([0-9]+).*/\1/p' "$CFG" | head -1)
    [ -n "$PORT" ] || die "could not read UDP_PORT from $CFG"
    free_port
    backup_to "$ETC.prev.tar.gz"
  fi

  install_binary
  if [ "$upgrading" = 1 ] && [ "$had_binary" = 1 ] && [ -x "$BIN.prev" ]; then
    INSTALL_ROLLBACK_ARMED=1
    trap rollback_install_on_exit EXIT
  fi
  install_ctl
  ensure_user
  install -d -m 750 "$ETC"

  if [ $upgrading = 1 ]; then
    log "existing config kept: $CFG (domains: $("$BIN" domain list --config "$CFG" | paste -sd, -))"
    if [ ${#DOMAINS[@]} -gt 0 ]; then
      "$BIN" domain add --config "$CFG" "${DOMAINS[@]}" > /dev/null
    fi
    "$BIN" keygen --config "$CFG" > /dev/null
  else
    local initargs=(init --config "$CFG" --port "$PORT")
    for d in "${DOMAINS[@]}"; do initargs+=(--domain "$d"); done
    [ -n "$NS_HOST" ] && initargs+=(--ns-host "$NS_HOST")
    [ -n "$NAME" ] && initargs+=(--name "$NAME")
    [ -n "$LEGACY_KEY" ] && initargs+=(--key-from "$LEGACY_KEY")
    "$BIN" "${initargs[@]}"
    [ -n "$LEGACY_KEY" ] && ok "kept the key and domain of the old server (no DNS change needed)"
  fi
  fix_perms

  if [ -n "$LEGACY_DOMAIN$(legacy_units)" ]; then
    legacy_stop
    # The old installer turned the systemd-resolved stub off with its own drop-in; keep it off
    # under our name so removing the old files later cannot take UDP/53 back.
    if [ -f /etc/systemd/resolved.conf.d/vortex53.conf ] && [ ! -f "$RESOLVED_DROPIN" ]; then
      mkdir -p "$(dirname "$RESOLVED_DROPIN")"
      cp /etc/systemd/resolved.conf.d/vortex53.conf "$RESOLVED_DROPIN"
    fi
  fi
  PORT=$(sed -nE 's/^UDP_PORT *= *([0-9]+).*/\1/p' "$CFG" | head -1)
  free_port
  open_firewall
  tune_kernel
  write_unit
  if ! restart_service || ! "$BIN" selfcheck --config "$CFG"; then
    die "service start or self test failed: journalctl -u vortex-server -n 50"
  fi
  local dns_rc=0
  dns_check || dns_rc=$?
  if [ $dns_rc = 0 ]; then
    "$BIN" selfcheck --config "$CFG" --public-only || warn "public resolvers could not reach the tunnel yet; try 'vortexctl status' in a few minutes"
  fi
  show_link
  echo
  ok "ready in $((SECONDS - t0))s. Manage it with: sudo vortexctl status | link | add-domain | update"
  INSTALL_ROLLBACK_ARMED=0
  trap - EXIT
}

cmd_link() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  show_link
}

cmd_status() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  if systemctl is-active -q vortex-server; then ok "service active"; else
    warn "service not running: journalctl -u vortex-server -n 50"
    return 1
  fi
  "$BIN" version
  "$BIN" status --config "$CFG" || true
  "$BIN" selfcheck --config "$CFG"
}

cmd_check_dns() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  DNS_CHECK=1
  dns_check
}

cmd_add_domain() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  [ ${#DOMAINS[@]} -gt 0 ] || DOMAINS=("${ARGS[@]:1}")
  [ ${#DOMAINS[@]} -gt 0 ] || die "usage: vortexctl add-domain t2.example.net"
  "$BIN" domain add --config "$CFG" "${DOMAINS[@]}"
  fix_perms
  restart_service
  dns_check || true
  show_link
}

cmd_remove_domain() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  [ ${#DOMAINS[@]} -gt 0 ] || DOMAINS=("${ARGS[@]:1}")
  [ ${#DOMAINS[@]} -gt 0 ] || die "usage: vortexctl remove-domain t2.example.net"
  "$BIN" domain remove --config "$CFG" "${DOMAINS[@]}"
  fix_perms
  restart_service
  show_link
}

cmd_update() {
  need_root
  check_platform
  [ -f "$CFG" ] || die "not installed; run the install command first"
  local old
  old=$("$BIN" version 2> /dev/null || echo none)
  [ -n "$WANT_VERSION" ] || PIN=0
  backup_to "$ETC.prev.tar.gz"
  install_binary
  install_ctl refresh
  write_unit
  if ! systemctl restart vortex-server || ! health_ok; then
    warn "health check failed after the update; rolling back to $old"
    cmd_rollback
    die "update failed and was rolled back: journalctl -u vortex-server -n 50"
  fi
  ok "updated: $old -> $("$BIN" version)"
}

health_ok() {
  local _
  for _ in 1 2 3 4 5; do
    systemctl is-active -q vortex-server && "$BIN" selfcheck --config "$CFG" > /dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

backup_to() { # backup_to FILE: config + key archive, mode 0600
  (umask 077 && tar -czf "$1" -C / "${ETC#/}") && chmod 600 "$1"
}

cmd_rollback() {
  need_root
  [ -x "$BIN.prev" ] || die "no previous binary to roll back to"
  cp -f "$BIN.prev" "$BIN.new" && mv -f "$BIN.new" "$BIN"
  [ -f "$ETC.prev.tar.gz" ] && tar -xzf "$ETC.prev.tar.gz" -C / && fix_perms
  systemctl restart vortex-server || true
  if health_ok; then ok "rolled back to $("$BIN" version)"; else warn "rolled back, but the service is still unhealthy: journalctl -u vortex-server -n 50"; fi
}

cmd_doctor() {
  need_root
  local bad=0
  chk() { # chk "what" "fix hint" command...
    local what=$1 hint=$2
    shift 2
    if "$@" > /dev/null 2>&1; then ok "$what"; else warn "$what: FAILED -> $hint"; bad=1; fi
  }
  for c in systemctl ss sha256sum tar; do chk "dependency $c" "install it with your package manager (apt install ...)" command -v "$c"; done
  chk "download tool (curl or wget)" "apt install curl" sh -c 'command -v curl || command -v wget'
  chk "config $CFG" "re-run the install command, or restore with: vortexctl rollback" "$BIN" domain list --config "$CFG"
  chk "service vortex-server active" "systemctl restart vortex-server; journalctl -u vortex-server -n 50" systemctl is-active -q vortex-server
  local p owner
  p=$(sed -nE 's/^UDP_PORT *= *([0-9]+).*/\1/p' "$CFG" 2> /dev/null | head -1)
  PORT=${p:-$PORT}
  owner=$(port_owner)
  if [ "$owner" = vortex-server ]; then ok "UDP/$PORT bound by vortex-server"; else
    warn "UDP/$PORT: owned by '${owner:-nobody}' -> stop the other service (systemctl disable --now <it>) and run: systemctl restart vortex-server"
    bad=1
  fi
  if command -v ufw > /dev/null && ufw status 2> /dev/null | grep -q "Status: active"; then
    chk "ufw allows $PORT/udp" "ufw allow $PORT/udp" sh -c "ufw status | grep -qE '^$PORT/udp'"
  else
    log "no active ufw; make sure UDP $PORT is open in your provider's firewall panel"
  fi
  chk "DNS delegation of every domain" "add the A/NS records shown by: vortexctl check-dns" "$BIN" check-dns --config "$CFG"
  chk "tunnel self test" "journalctl -u vortex-server -n 50" "$BIN" selfcheck --config "$CFG"
  if [ "$bad" = 0 ]; then
    ok "doctor: everything looks fine"
  else
    warn "doctor: problems found (fixes above)"
    return 1
  fi
}

cmd_bench() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  "$BIN" bench --config "$CFG"
}

cmd_rotate_key() {
  need_root
  [ -f "$CFG" ] || die "not installed"
  confirm "Make a new key? Every existing link stops working until people import the new one." || die "cancelled"
  "$BIN" keygen --config "$CFG" --rotate
  fix_perms
  restart_service
  show_link
}

cmd_backup() {
  need_root
  [ -d "$ETC" ] || die "not installed"
  local out
  out="/root/vortex-server-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  backup_to "$out"
  ok "backup written to $out (mode 0600; it contains the server key: keep it private)"
}

cmd_logs() { journalctl -u vortex-server -n "${ARGS[1]:-100}" --no-pager; }

cmd_uninstall() {
  need_root
  confirm "Remove the Vortex server from this machine?" || die "cancelled"
  systemctl disable --now vortex-server > /dev/null 2>&1 || true
  rm -f "$UNIT" "$BIN" "$BIN.prev" "$SYSCTL_FILE" "$(dirname "$CTL")/vortex"
  systemctl daemon-reload
  if [ -f "$RESOLVED_DROPIN" ]; then
    rm -f "$RESOLVED_DROPIN"
    systemctl restart systemd-resolved 2> /dev/null || true
  fi
  if [ "$PURGE" = 1 ]; then
    rm -rf "$ETC"
    userdel "$SVC_USER" 2> /dev/null || true
    ok "removed, including the config and key"
  else
    ok "removed; config and key kept in $ETC (delete with: vortexctl uninstall --purge, or rm -rf $ETC)"
  fi
  rm -f "$CTL"
}

cmd_uninstall_legacy() {
  need_root
  [ -d "$LEGACY" ] || [ -n "$(legacy_units)" ] || die "no old Vortex-53 server found"
  confirm "Delete the old server in $LEGACY (its keys too)?" || die "cancelled"
  legacy_stop
  local u
  for u in $(legacy_units); do rm -f "$UNIT_DIR/$u"; done
  systemctl daemon-reload
  rm -f /etc/systemd/resolved.conf.d/vortex53.conf
  rm -rf "$LEGACY"
  ok "old server removed"
}

main() {
  parse "$@"
  local c=${ARGS[0]:-install}
  case "$c" in
    install) cmd_install ;;
    link | links) cmd_link ;;
    status | health) cmd_status ;;
    check-dns) cmd_check_dns ;;
    add-domain) cmd_add_domain ;;
    remove-domain) cmd_remove_domain ;;
    update | upgrade) cmd_update ;;
    rotate-key) cmd_rotate_key ;;
    backup) cmd_backup ;;
    doctor) cmd_doctor ;;
    bench) cmd_bench ;;
    rollback) cmd_rollback ;;
    logs) cmd_logs ;;
    uninstall) cmd_uninstall ;;
    uninstall-legacy) cmd_uninstall_legacy ;;
    help) usage ;;
    *) die "unknown command '$c' (see --help)" ;;
  esac
}

main "$@"
