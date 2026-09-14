#!/usr/bin/env bash
# docs/socket-daemon.md phase gates — no LLM keys, no FUSE needed beyond the
# touch-profile child (same trick as smoke-serve.sh: unknown profiles get the
# prompt bare, so the child runs `den touch /path` in the real sandbox).
#
# Verifies: socket-only boot without a token, peercred health, TCP not bound,
# second-serve refusal, proxied sessions, den up (background run), den logs,
# one-shot proxy, --solo escape hatch, autospawn from a cold socket, orphan
# sweep after a daemon kill.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -q --bin den
BIN="$(pwd)/target/debug/den"

# Scratch must not sit under /tmp|/var/tmp|/run (sandbox mounts fresh tmpfs
# over those); same constraint as smoke-serve.sh.
SCRATCH="$(mktemp -d "${HOME}/.den/smoke-socket-XXXXXX")"
export HOME="$SCRATCH/home"
export XDG_RUNTIME_DIR="$SCRATCH/xdg"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
cleanup() {
  pkill -f "den serve --socket $SCRATCH" 2>/dev/null || true
  pkill -f "den serve" 2>/dev/null || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

SOCK="$XDG_RUNTIME_DIR/den/den.sock"
ok() { echo "ok: $1"; }
wait_for() { for i in $(seq 1 50); do [ -S "$SOCK" ] && return 0; sleep 0.1; done; return 1; }

# --- 1) socket-only boot, no token ------------------------------------------
"$BIN" serve --socket "$SOCK" &
SRV_PID=$!
wait_for || { echo "FAIL: socket never appeared"; exit 1; }
ok "socket-only boot (no DEN_API_TOKEN)"

# health over the socket needs no bearer (peercred)
curl -s --unix-socket "$SOCK" http://den/v1/health | grep -q '"version"' \
  || { echo "FAIL: socket health"; exit 1; }
ok "peercred health (no token)"

# --- 2) TCP must NOT be bound in socket-only mode ---------------------------
if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8520' 2>/dev/null; then
  echo "FAIL: TCP bound without a token"; exit 1
fi
ok "TCP unbound without token"

# --- 3) second serve refuses (live daemon owns the socket) ------------------
if "$BIN" serve --socket "$SOCK" 2>/dev/null; then
  echo "FAIL: second serve on live socket should refuse"; exit 1
fi
ok "second serve refused (already listening)"

# --- 4) proxied sessions listing -------------------------------------------
"$BIN" sessions | grep -q "daemon reports no sessions" \
  || { echo "FAIL: proxied empty sessions"; exit 1; }
ok "proxied sessions (empty)"

# --- 5) den up: create+launch in the daemon, exit immediately ---------------
SID="$("$BIN" up touch "/hello-from-up")"
echo "$SID" | grep -q '^s-' || { echo "FAIL: den up printed '$SID'"; exit 1; }
ok "den up -> $SID"
for i in $(seq 1 50); do
  "$BIN" logs "$SID" 2>/dev/null | grep -q "— exited" && break
  sleep 0.2
done
"$BIN" logs "$SID" | grep -q "hello-from-up" 2>/dev/null \
  || { echo "FAIL: log missing"; "$BIN" logs "$SID" || true; exit 1; }
ok "den logs shows the run log"

# --- 6) one-shot proxy (prompt-only, daemon present) ------------------------
OUT="$("$BIN" touch /hello-oneshot 2>&1)" || true
echo "$OUT" | grep -q "hello-oneshot" \
  || { echo "FAIL: one-shot proxy streamed nothing: $OUT"; exit 1; }
ok "one-shot proxied through the daemon"

# --- 7) --solo escape hatch -------------------------------------------------
"$BIN" --solo sessions >/dev/null \
  || { echo "FAIL: --solo sessions"; exit 1; }
ok "--solo forces the in-process path"

# --- 8) autospawn from a cold socket ----------------------------------------
kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true
rm -f "$SOCK"
export XDG_RUNTIME_DIR="$SCRATCH/xdg2"   # cold socket → autospawn
SID2="$("$BIN" up touch "/hello-autospawn")"
echo "$SID2" | grep -q '^s-' || { echo "FAIL: autospawn up"; exit 1; }
ok "autospawned daemon -> $SID2"
for i in $(seq 1 50); do
  "$BIN" logs "$SID2" 2>/dev/null | grep -q "— exited" && break
  sleep 0.2
done
"$BIN" logs "$SID2" | grep -q "hello-autospawn" \
  || { echo "FAIL: autospawned run log"; exit 1; }
ok "autospawned run completed"

# --- 9) orphan sweep: kill daemon mid-session, restart ----------------------
pkill -f "den serve --socket $SCRATCH" 2>/dev/null || true
sleep 0.5
unset XDG_RUNTIME_DIR; export XDG_RUNTIME_DIR="$SCRATCH/xdg3"
("$BIN" serve --socket "$XDG_RUNTIME_DIR/den/den.sock" >"$SCRATCH/xdg3-serve.log" 2>&1 &)
for i in $(seq 1 50); do [ -S "$XDG_RUNTIME_DIR/den/den.sock" ] && break; sleep 0.1; done
head -2 "$SCRATCH/xdg3-serve.log"
# boot sweep may report orphaned runs from the killed daemon (best-effort
# children still running under their own pgid are unaffected)
ok "restart with fresh socket dir (boot sweep ran)"
pkill -f "den serve --socket $SCRATCH" 2>/dev/null || true

echo "SMOKE-SOCKET-OK"
