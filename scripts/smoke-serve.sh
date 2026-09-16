#!/usr/bin/env bash
# Phase 1 acceptance for den serve (platform-api.md §13, slice 1) — no LLM
# keys needed: agent ["touch"]/["sleep"] runs the prompt bare, so the child
# runs `den exec --session <sid> -- touch ./hello.txt` / `... sleep 30`
# inside the real sandbox. The profile= payloads below exercise the legacy
# v1 compat path (profile -> agent=[profile]); new clients send agent=[...].
#
# Verifies: auth refusal, session create, run launch, sandboxed VFS write
# captured as delta_json, process-group kill, serve-restart orphan sweep,
# session delete. Runs entirely under a scratch HOME.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8520}"
TOKEN="smoke-$RANDOM"
# The daemon-attach test needs the PATCHED dex (--fd adoption). Point
# Set DEX_WORKTREE to a dex checkout to also exercise the daemon-attach
# path; the smoke builds that dex and puts it first on PATH. Unset by
# default so the smoke runs on any machine.
DEX_WORKTREE="${DEX_WORKTREE:-}"
# Scratch must NOT sit under /tmp|/var/tmp|/run: the sandbox mounts fresh
# tmpfs over those (sandbox.rs step 4) and would swallow the scratch HOME
# and its FUSE mountpoint. Real HOME survives (it lives on the host fs).
SCRATCH="$(mktemp -d "${HOME}/.den/smoke-XXXXXX")"
trap 'kill "$SRV_PID" 2>/dev/null || true; pkill -f "$BIN dex serve --fd" 2>/dev/null || true; for m in "$SCRATCH"/home/.den/sessions/*/mnt; do fusermount3 -uz "$m" 2>/dev/null || true; done; rm -rf "$SCRATCH"' EXIT

cargo build -q --bin den
BIN="$(pwd)/target/debug/den"

# patched dex: build + PATH-first so the sandboxed daemon adopts the fd
if [ -d "$DEX_WORKTREE" ]; then
  (cd "$DEX_WORKTREE" && cargo build -q --bin dex)
  export PATH="$DEX_WORKTREE/target/debug:$PATH"
fi

export HOME="$SCRATCH/home"
mkdir -p "$HOME"
# Serve from a tmpfs work dir: sessions are cwd-scoped, and some hosts
# refuse the FUSE bind-mount onto non-tmpfs dirs (see README platform
# notes) — /tmp keeps the smoke host-agnostic.
WORK="$SCRATCH/work"
mkdir -p "$WORK"
cd "$WORK"
export DEN_API_TOKEN="$TOKEN"
export DEN_BIND="127.0.0.1:$PORT"
BASE="http://127.0.0.1:$PORT/v1"
AUTH=(-H "Authorization: Bearer $TOKEN")
jqget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

"$BIN" serve >"$SCRATCH/serve.log" 2>&1 &
SRV_PID=$!

# 1. health + bad-token refusal
for i in $(seq 1 50); do curl -sf "$BASE/health" -H "Authorization: Bearer $TOKEN" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$BASE/health" "${AUTH[@]}" | jqget "['version']" >/dev/null
echo "ok: health"
if curl -sf "$BASE/sessions" -H "Authorization: Bearer wrong" >/dev/null 2>&1; then
  echo "FAIL: bad token accepted"; exit 1
fi
echo "ok: auth refused"

# 2. create a turn session, run `touch ./hello.txt` in the sandbox. The VFS
# overlay covers the session cwd; `/` stays read-only (sandbox.rs step 11),
# so the prompt must be cwd-relative — the delta still reports the VFS path
# /hello.txt.
SID=$(curl -sf -X POST "$BASE/sessions" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"profile":"touch"}' | jqget "['sid']")
echo "ok: session $SID"

RID=$(curl -sf -X POST "$BASE/sessions/$SID/runs" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"prompt":"./hello.txt"}' | jqget "['run_id']")
echo "ok: run $RID"

STATE="running"
ROW=""
for i in $(seq 1 100); do
  ROW=$(curl -sf "$BASE/runs/$RID" "${AUTH[@]}")
  STATE=$(echo "$ROW" | jqget "['status']")
  [ "$STATE" != "queued" ] && [ "$STATE" != "running" ] && break
  sleep 0.3
done
[ "$STATE" = "exited" ] || { echo "FAIL: run ended '$STATE'"; cat "$SCRATCH/serve.log"; exit 1; }
DELTA=$(echo "$ROW" | jqget "['delta_json']")
echo "$DELTA" | grep -q '"/hello.txt"' || { echo "FAIL: delta missing /hello.txt: $DELTA"; exit 1; }
echo "ok: delta captured /hello.txt"

# 3. kill a live run (process group)
SID2=$(curl -sf -X POST "$BASE/sessions" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"profile":"sleep"}' | jqget "['sid']")
RID2=$(curl -sf -X POST "$BASE/sessions/$SID2/runs" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"prompt":"30"}' | jqget "['run_id']")
sleep 1
curl -sf -X POST "$BASE/runs/$RID2/kill" "${AUTH[@]}" >/dev/null
for i in $(seq 1 60); do
  STATE=$(curl -sf "$BASE/runs/$RID2" "${AUTH[@]}" | jqget "['status']")
  [ "$STATE" != "running" ] && [ "$STATE" != "queued" ] && break
  sleep 0.3
done
[ "$STATE" = "killed" ] || { echo "FAIL: kill ended '$STATE'"; exit 1; }
echo "ok: kill -> killed"

# 4. serve death mid-run -> orphan sweep on restart
SID3=$(curl -sf -X POST "$BASE/sessions" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"profile":"sleep"}' | jqget "['sid']")
RID3=$(curl -sf -X POST "$BASE/sessions/$SID3/runs" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"prompt":"60"}' | jqget "['run_id']")
sleep 1
kill -9 "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true
"$BIN" serve >>"$SCRATCH/serve.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 50); do curl -sf "$BASE/health" "${AUTH[@]}" >/dev/null 2>&1 && break; sleep 0.2; done
STATE=$(curl -sf "$BASE/runs/$RID3" "${AUTH[@]}" | jqget "['status']")
[ "$STATE" = "orphaned" ] || { echo "FAIL: restart state '$STATE'"; exit 1; }
echo "ok: restart -> orphaned"
# The orphan child still runs (its own process group survived serve) and
# holds the session flock until it exits — kill it to leave a clean slate.
pkill -f "sleep 60" 2>/dev/null || true

# 5. delete a session
curl -sf -X DELETE "$BASE/sessions/$SID2" "${AUTH[@]}" | jqget "['removed']" >/dev/null
echo "ok: delete"

# 6. concurrent-run conflict on a LIVE session (session_busy -> 409)
SID4=$(curl -sf -X POST "$BASE/sessions" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"profile":"sleep"}' | jqget "['sid']")
RID4=$(curl -sf -X POST "$BASE/sessions/$SID4/runs" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"prompt":"30"}' | jqget "['run_id']")
sleep 0.7
if curl -sf -X POST "$BASE/sessions/$SID4/runs" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"prompt":"30"}' >/dev/null 2>&1; then
  echo "FAIL: second run on busy session accepted"; exit 1
fi
echo "ok: busy session refused"
curl -sf -X POST "$BASE/runs/$RID4/kill" "${AUTH[@]}" >/dev/null

# 7. daemon session: /attach passes a host listener fd into the sandboxed
#    dex daemon (platform-api.md §3) — /health answers through it
SID5=$(curl -sf -X POST "$BASE/sessions" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"profile":"dex","kind":"daemon"}' | jqget "['sid']")
echo "ok: daemon session $SID5"
ATT=$(curl -sf -X POST "$BASE/sessions/$SID5/attach" "${AUTH[@]}")
URL=$(echo "$ATT" | jqget "['attach_url']")
DTOKEN=$(echo "$ATT" | jqget "['attach_token']")
DAEMON_OK=0
for i in $(seq 1 60); do
  if curl -sf --max-time 5 "$URL/health" -H "Authorization: Bearer $DTOKEN" >/dev/null 2>&1; then DAEMON_OK=1; break; fi
  sleep 0.3
done
[ "$DAEMON_OK" = "1" ] || {
  echo "FAIL: dex daemon not reachable at $URL"
  tail -20 "$SCRATCH/home/.den/runs/$SID5/daemon.log" 2>/dev/null
  exit 1
}
echo "ok: daemon attach ($URL)"
# reconnect is idempotent: same port + token while the child is live
ATT2=$(curl -sf -X POST "$BASE/sessions/$SID5/attach" "${AUTH[@]}")
[ "$(echo "$ATT2" | jqget "['attach_url']")" = "$URL" ] || { echo "FAIL: reconnect drifted"; exit 1; }
echo "ok: reconnect idempotent"
# stop the daemon, wait for the reap, then delete
curl -sf -X POST "$BASE/sessions/$SID5/stop" "${AUTH[@]}" >/dev/null
for i in $(seq 1 40); do
  curl -sf -X DELETE "$BASE/sessions/$SID5" "${AUTH[@]}" | jqget "['removed']" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -sf "$BASE/sessions/$SID5" "${AUTH[@]}" >/dev/null 2>&1 && { echo "FAIL: delete"; exit 1; }
echo "ok: daemon stop+delete"

echo "SMOKE-OK"
