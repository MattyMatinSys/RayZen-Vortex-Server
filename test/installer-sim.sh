#!/usr/bin/env bash
# Local simulation of install.sh without systemd (developer machines / containers).
# Runs against a temporary root and a systemd shim; this is not a real systemd test.
#   test/installer-sim.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
work=${SIM_DIR:-$(mktemp -d)}
rel="$work/release" root="$work/root" shims="$work/shims"
rm -rf "$rel" "$root" "$shims"
mkdir -p "$rel" "$root" "$shims"
PORT=${SIM_PORT:-15353}

echo "== build (host arch, named like the release asset)"
(cd "$repo/core" && CGO_ENABLED=0 go build -trimpath -ldflags "-X stormdns-go/vortexsrv.Version=0.0.0-sim" -o "$rel/vortex-server-linux-amd64" ./cmd/vortex-server)
cp "$here/../install.sh" "$rel/install.sh"
(cd "$rel" && sha256sum vortex-server-linux-amd64 > SHA256SUMS)

export VORTEX_BIN="$root/usr/local/bin/vortex-server" VORTEX_CTL="$root/usr/local/sbin/vortexctl"
export VORTEX_ETC="$root/etc/vortex-server" VORTEX_UNIT_DIR="$root/etc/systemd/system"
export VORTEX_SYSCTL_FILE="$root/etc/sysctl.d/90-vortex-server.conf"
export VORTEX_RESOLVED_DROPIN="$root/etc/systemd/resolved.conf.d/vortex-server.conf"
export VORTEX_LEGACY_BASE="$root/opt/vortex53" VORTEX_TEST_ARCH=x86_64
export SIM_STATE="$work/state"
mkdir -p "$SIM_STATE"

# systemctl shim: runs the server in the background like the unit would.
cat > "$shims/systemctl" << 'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$SIM_STATE/calls"
cmd=$1; shift || true
while [[ "${1:-}" == -* ]]; do shift; done
unit=${1:-}
stop() { [ -f "$SIM_STATE/pid" ] && kill "$(cat "$SIM_STATE/pid")" 2>/dev/null; rm -f "$SIM_STATE/pid"; sleep 0.3; }
start() {
  nohup "$VORTEX_BIN" run --config "$VORTEX_ETC/server.toml" >> "$SIM_STATE/server.log" 2>&1 &
  echo $! > "$SIM_STATE/pid"
  for _ in $(seq 50); do [ -f "$VORTEX_ETC/stats.json" ] && return 0; kill -0 "$(cat "$SIM_STATE/pid")" 2>/dev/null || return 1; sleep 0.1; done
  return 1
}
case "$cmd" in
  restart) [ "$unit" = vortex-server ] && { stop; rm -f "$VORTEX_ETC/stats.json"; start; } ;;
  is-active) [ -f "$SIM_STATE/pid" ] && kill -0 "$(cat "$SIM_STATE/pid")" 2>/dev/null ;;
  disable) [[ "$*" == *vortex-server* ]] && stop; exit 0 ;;
  *) exit 0 ;;
esac
EOF
# shellcheck disable=SC2016 # expanded by the shim at run time
printf '#!/bin/sh\necho "sysctl $*" >> "$SIM_STATE/calls"\nexit 0\n' > "$shims/sysctl"
# shellcheck disable=SC2016
printf '#!/bin/sh\ncat "$SIM_STATE/server.log" 2>/dev/null | tail -n 30\n' > "$shims/journalctl"
printf '#!/bin/sh\nexit 0\n' > "$shims/modprobe"
# Keep identity, ownership, and firewall operations inside the simulated root.
printf '#!/bin/sh\nif [ "$1" = "-u" ]; then echo 0; else exec /usr/bin/id "$@"; fi\n' > "$shims/id"
printf '#!/bin/sh\nexit 0\n' > "$shims/chown"
printf '#!/bin/sh\nif [ "$1" = status ]; then echo "Status: inactive"; else exit 1; fi\n' > "$shims/ufw"
printf '#!/bin/sh\nexit 1\n' > "$shims/firewall-cmd"
chmod +x "$shims"/*
export PATH="$shims:$PATH"

pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; tail -n 20 "$SIM_STATE/server.log" 2>/dev/null; exit 1; }
cleanup() { [ -f "$SIM_STATE/pid" ] && kill "$(cat "$SIM_STATE/pid")" 2>/dev/null; true; }
trap cleanup EXIT

echo "== legacy server present (old /opt/vortex53 layout, key kept)"
mkdir -p "$VORTEX_LEGACY_BASE/instances/main" "$VORTEX_UNIT_DIR"
echo "old.example.com" > "$VORTEX_LEGACY_BASE/instances/main/domain"
echo "0123456789abcdef0123456789abcdef" > "$VORTEX_LEGACY_BASE/instances/main/encrypt_key.txt"
touch "$VORTEX_UNIT_DIR/vortex53-main.service"

echo "== fresh install from a local release dir (--from), piped like curl | bash"
t0=$(date +%s)
bash -s -- --from "$rel" --port "$PORT" --yes --no-dns-check < "$rel/install.sh" | tee "$work/install.out"
t1=$(date +%s)
grep -q "^vortex://p/" "$work/install.out" || fail "no link printed"
[ "$(grep -c '^vortex://p/' "$work/install.out")" = 1 ] || fail "more than one link line"
grep -q "kept the key and domain of the old server" "$work/install.out" || fail "legacy key not migrated"
"$VORTEX_BIN" link -q --config "$VORTEX_ETC/server.toml" | python3 -c 'import sys,base64; p=sys.stdin.read().strip()[11:]; print(base64.urlsafe_b64decode(p+"="*(-len(p)%4)).decode())' | grep -q '"name":"Vortex old.example.com"' || fail "profile name"
[ "$(cat "$VORTEX_ETC/key.txt")" = "0123456789abcdef0123456789abcdef" ] || fail "key differs from legacy key"
grep -q '^DOMAIN = \["old.example.com"\]' "$VORTEX_ETC/server.toml" || fail "legacy domain not used"
grep -q "systemctl disable --now vortex53-main.service" "$SIM_STATE/calls" || fail "legacy unit not stopped"
grep -q "Type=notify" "$VORTEX_UNIT_DIR/vortex-server.service" || fail "unit not written"
grep -q "WatchdogSec=30" "$VORTEX_UNIT_DIR/vortex-server.service" || fail "watchdog missing"
[ -x "$VORTEX_CTL" ] || fail "vortexctl not installed"
[ ! -f "$VORTEX_SYSCTL_FILE" ] || fail "kernel tuning applied without --tune (REQ-108)"
pass "install (legacy upgrade) in $((t1 - t0))s"

echo "== vortexctl link / status"
"$VORTEX_CTL" link | grep -q "^vortex://p/" || fail "link"
"$VORTEX_CTL" status | tee "$work/status.out" | grep -q "tunnel handshake on this server works" || fail "status selfcheck"
pass "link + status"

echo "== add-domain / remove-domain"
"$VORTEX_CTL" add-domain t2.example.net --no-dns-check > "$work/add.out" || fail "add-domain"
grep -q '^DOMAIN = \["old.example.com", "t2.example.net"\]' "$VORTEX_ETC/server.toml" || fail "domain not added"
"$VORTEX_BIN" selfcheck --config "$VORTEX_ETC/server.toml" | grep -q "\[ok\] t2.example.net" || fail "new domain not served"
"$VORTEX_CTL" remove-domain t2.example.net > /dev/null || fail "remove-domain"
grep -q '^DOMAIN = \["old.example.com"\]' "$VORTEX_ETC/server.toml" || fail "domain not removed"
pass "domains"

echo "== re-run install = upgrade (config + key kept, new domain merged)"
key=$(cat "$VORTEX_ETC/key.txt")
bash "$rel/install.sh" --from "$rel" --domain t3.example.org --yes --no-dns-check > "$work/upgrade.out" || fail "upgrade run"
[ "$(cat "$VORTEX_ETC/key.txt")" = "$key" ] || fail "upgrade changed the key"
grep -q 't3.example.org' "$VORTEX_ETC/server.toml" || fail "upgrade did not add the domain"
pass "upgrade keeps key"

echo "== upgrade rollback when the replacement cannot start"
cp -r "$rel" "$work/badstart"
cat > "$work/badstart/vortex-server-linux-amd64" <<'EOF'
#!/bin/sh
if [ "$1" = version ]; then echo 'vortex-server test-broken'; exit 0; fi
exit 1
EOF
chmod +x "$work/badstart/vortex-server-linux-amd64"
(cd "$work/badstart" && sha256sum vortex-server-linux-amd64 > SHA256SUMS)
before=$(sha256sum "$VORTEX_BIN" | cut -d' ' -f1)
if bash "$rel/install.sh" --from "$work/badstart" --domain fail.example.net --yes --no-dns-check > "$work/badstart.out" 2>&1; then fail "broken upgrade succeeded"; fi
[ "$(sha256sum "$VORTEX_BIN" | cut -d' ' -f1)" = "$before" ] || fail "previous binary not restored"
! grep -q fail.example.net "$VORTEX_ETC/server.toml" || fail "previous configuration not restored"
"$VORTEX_BIN" selfcheck --config "$VORTEX_ETC/server.toml" > /dev/null || fail "service unhealthy after rollback"
pass "failed upgrade restores binary and configuration"

echo "== port occupied by an unknown process"
cat > "$shims/ss" <<'EOF'
#!/bin/sh
echo 'UNCONN 0 0 0.0.0.0:15353 0.0.0.0:*'
EOF
chmod +x "$shims/ss"
if bash "$rel/install.sh" --from "$rel" --yes --no-dns-check > "$work/port.out" 2>&1; then fail "unknown port owner accepted"; fi
grep -q "unknown process" "$work/port.out" || fail "missing port diagnostic"
[ "$(sha256sum "$VORTEX_BIN" | cut -d' ' -f1)" = "$before" ] || fail "binary changed despite occupied port"
rm "$shims/ss"
pass "unknown port owner detected before upgrade"

echo "== rotate-key"
"$VORTEX_CTL" rotate-key --yes > "$work/rotate.out" || fail "rotate"
[ "$(cat "$VORTEX_ETC/key.txt")" != "$key" ] || fail "key not rotated"
"$VORTEX_BIN" selfcheck --config "$VORTEX_ETC/server.toml" > /dev/null || fail "server not serving the new key"
pass "rotate-key"

echo "== update (same local release) + tampered binary refused"
"$VORTEX_CTL" update --from "$rel" > /dev/null || fail "update"
cp -r "$rel" "$work/bad" && printf 'x' >> "$work/bad/vortex-server-linux-amd64"
if "$VORTEX_CTL" update --from "$work/bad" > "$work/bad.out" 2>&1; then fail "tampered binary accepted"; fi
grep -q "checksum mismatch" "$work/bad.out" || fail "no checksum error"
"$VORTEX_BIN" version > /dev/null || fail "binary broken after refused update"
pass "update + checksum"

echo "== unsupported architecture refused"
if VORTEX_TEST_ARCH=riscv64 bash "$rel/install.sh" --from "$rel" --domain x.example.com --yes > "$work/arm.out" 2>&1; then fail "riscv64 accepted"; fi
grep -q "x86_64" "$work/arm.out" || fail "no arch message"
pass "arch gate"

echo "== uninstall (key kept unless --purge)"
"$VORTEX_CTL" uninstall --yes > /dev/null || fail "uninstall"
if [ -e "$VORTEX_BIN" ] || [ -e "$VORTEX_UNIT_DIR/vortex-server.service" ] || [ ! -f "$VORTEX_ETC/key.txt" ]; then fail "uninstall state"; fi
pass "uninstall"
echo "all installer simulations passed (work dir $work)"
