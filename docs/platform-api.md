# Platform over den — HTTP API for durable agent sessions (plan)

Goal: a platform where users launch durable, sandboxed coding-agent sessions
over HTTP, and connect to them from a TUI or a web UI.

Two projects compose into the platform:

- **den** (this repo) — the runtime: OS-sandboxed execution (FUSE + user/mount/
  net namespaces), durable per-session state (`~/.den/sessions/<sid>/fs.db`),
  replication/restore (`den replicate`/`pull`), and git landing (`den push`).
- **dex** (`~/Work/dex`) — the flagship agent: its own turn loop + tools, and a
  client–daemon architecture that already solves "connect from anywhere":
  `dex serve` (axum HTTP+SSE daemon, src/daemon/mod.rs:710), pure-HTTP TUI
  (`dex connect <url> --reattach <id>`, journal replay, remote tool approval),
  bearer-token auth (`DEX_DAEMON_TOKEN`, generated token file for non-loopback
  binds), one-shot mode (`dex -p "..."`) for headless turns.

den is the sandbox + durable state + orchestration; dex's existing HTTP+SSE
protocol is the attach layer — the web UI speaks the same wire the TUI
already speaks. den's "wrap any CLI" story stays supported as turn-based
headless runs; dex is the interactive/attachable first-party session kind.

## 0. Boundary

- **den core (unchanged at first)**: sandbox exec chain (src/sandbox.rs), FUSE
  VFS, sessions, seed/push/backup/replicate/pull, egress proxy + policy.
- **New**: `den serve` (HTTP API, auth, registry, job lifecycle), headless
  argv map, per-session locking, socket plumbing for attachable sessions.
- **dex (small additions, separate repo)**: fd-socket activation so the
  daemon can adopt a pre-bound host listener (§3); everything else exists.

### Entry points

**den is the door; dex is the room.**

- **Control plane = den.** Every platform request — create, launch, attach
  credential minting, push, delete — starts at den (`den serve` + its API,
  or the `den` CLI). den owns auth, the registry, session lifecycle,
  isolation, and durability; it also supports profiles that never involve
  dex (claude, codex, gemini turn runs).
- **Data plane = dex.** Once a session is live, clients speak dex's existing
  HTTP+SSE protocol at the `attach_url` den minted (journal replay,
  steering, tool approval), holding a session-scoped token den issued.
- CLI surface: `den serve` (daemon), session create/launch, `den attach
  <sid>` (opens the dex TUI pointed at the attach_url), `den push`,
  `den rm`. Platform users never type `dex connect` — `den attach` does.
  Bare `dex` stays valid as the no-platform, no-sandbox local dev loop.
  Front-door parity with `amp -ox`: `den up "<prompt>"` = create session +
  launch + print the session/attach URL and return immediately; local
  execute parity with `amp -x`: `den -x "<prompt>"` (current one-shot
  behaviour, renamed surface).
- Rule of thumb: **anything that outlives a session is den's** (registry,
  fs.db, replica, git branch); **anything that lives inside a session is
  dex's** (LLM loop, transcript, approvals). dex is simply the first-class
  profile of each session kind.

## 1. Process model — the one architectural rule

`src/sandbox.rs:436` forks from a single-threaded context; a multithreaded
HTTP server cannot host runs in-process. So:

- `den serve` is a **supervisor, not a sandbox host**. Each session is a
  direct child process (`tokio::process::Command` → `den <profile> …`),
  with its own process group (`CommandExt::process_group`) so a kill hits the
  whole chain.
- serve reaps children directly — no pidfile polling. The existing detached
  machinery (spawn_detached, src/main.rs) is used only for backup/replicate
  watchers, exactly as `--autostart` does today.
- serve restart while sessions are children: orphans reparent to init. On
  boot, serve scans registry rows in `running`/`attached` state and marks them
  `orphaned` unless the recorded pid is still alive (`kill(pid, 0)`).

## 2. Session kinds

| kind | child process | lifetime | connect |
|---|---|---|---|
| `turn` | any CLI, headless (`claude -p`, `codex exec`, `dex -p "..."`) | one process per turn; conversation resumed across turns | results via API (delta, log, files, push) |
| `daemon` | `dex serve` inside the sandbox | one process for many turns | dex TUI / web UI over dex HTTP+SSE |

**Both kinds are multi-turn** — a den session is a conversation, and fs.db
accumulates across every turn either way. The kinds differ only in process
model, not turn count:

- **turn**: each `POST /runs` is another process on the same session. The
  agent's own conversation state must survive process boundaries, so den
  records the agent's session id in `<sid>/agent-session` at first run and
  the headless argv map gains per-profile resume args (`dex --session <id>`,
  `claude --resume <id>`, `codex exec resume <id>`, …). Context is reloaded
  from the agent's journal each turn; observation is between-turns (poll
  delta/log after each run).
- **daemon**: one live agent process owns the loop in memory; turns are
  messages to it. Observation is mid-turn (SSE attach, steering, approvals).
  Requires an agent with an attach protocol (dex) — that's the only
  prerequisite difference.

Both write the same durable fs.db and can be pushed/replicated/inspected
identically. `turn` covers every agent; `daemon` is the interactive flagship.

## 3. The attach problem: host → daemon inside the netns

The sandboxed dex daemon binds loopback **inside its own netns** — the host
cannot dial it, and slirp4netns gives guest→host, not host→guest. Solution:
**listener adoption via fd passing** (the same pattern den already uses for
its egress proxy listener on fd 3):

1. `den serve` binds `127.0.0.1:<port>` per daemon session on the **host**
   (port tracked in the registry).
2. The fd is inherited down den's fork chain (N→U→A) with CLOEXEC cleared;
   sandbox.rs's child fd cleanup must exempt it (the chain already special-
   cases fds — the proxy listener follows the same route to its child).
3. dex adopts it: `LISTEN_FDS=1` (systemd socket-activation convention, fd 3
   with `LISTEN_FDNAMES`) or an explicit `dex serve --fd <n>`. dex's
   `run_daemon(listener)` already takes a pre-bound `TcpListener`, so the dex
   change is: build the listener from the raw fd instead of `bind()`.
4. The daemon now serves on a **host loopback port** while its process runs
   sandboxed; the socket belongs to the host netns (bound at creation time),
   so inbound attach connections arrive directly.

Auth per session: den serve generates the session's `DEX_DAEMON_TOKEN` at
launch, injects it into the sandbox env, and returns `{attach_url,
attach_token}` from the session/runs response. Clients hold only the
platform token until they attach; the attach token is session-scoped.

MVP attach is localhost (`127.0.0.1`). Multi-host platforms add a
platform-side reverse proxy (`/v1/sessions/:sid/attach/*` → the session's
local port, SSE-aware) in slice 3, so remote clients never touch per-session
ports directly.

### Any agent daemon, not just dex

Daemon-kind is an adapter surface. A profile's daemon spec needs only: an
argv for its daemon mode, a way to accept the listener, an optional auth
env, and an optional health probe. Two integration levels:

1. **Native (dex)**: the agent adopts the pre-bound host listener fd
   (`LISTEN_FDS`/`--fd`). Zero extra hops, best latency.
2. **Bridge (generic)**: the agent binds its own port *inside* the netns
   (`opencode serve --port …`, any daemon that takes a port) and den spawns
   its own tiny in-sandbox forwarder: it adopts fd 4, dials the agent's
   loopback port in the same netns, and pumps bytes both ways. Works for any
   daemon with zero agent changes. When the agent has no daemon auth, the
   bridge enforces the session token itself (den already builds HTTP
   proxies — src/proxy.rs).

What den guarantees to every daemon guest, regardless of wire protocol:
isolation, durable fs.db (the agent's own state files live in the VFS, so
they survive restarts and replicate), seed, push, registry/API lifecycle,
token minting, log capture, reap/kill/orphan semantics. What den does NOT
do: normalize agent protocols — journal replay/steering/approval remain the
agent's own; den brokers the socket, the credential, and the lifecycle.
(Transcript-protocol adapters per agent, if ever wanted, belong in the web
UI client, not in den.)

## 4. Architecture

```
 platform clients
   │ (den token)
   ▼
den serve ── platform API: sessions, launches, status, push, quotas
   │ spawns per session (own process group, reaped)
   ▼
den sandbox (FUSE VFS + userns/mountns + egress proxy)
   │
   ├── turn kind:     claude -p / codex exec / dex -p …  → exit → delta_json
   └── daemon kind:   dex serve (adopts host listener fd)
                         ▲
        dex TUI / web UI ┘ (dex HTTP+SSE: stream, steer, approve, journal replay)
   │
   ▼ fs.db (durable) ──▶ litestream ──▶ S3   (any host can den pull + resume)
```

Scale model that falls out: N concurrent sessions per host (each an isolated
namespace chain), horizontal scale = more hosts + shared S3 replica; a
session's fs.db is portable by design (README "Sessions are born portable").

## 5. On-disk layout

```
~/.den/
  sessions/<sid>/        unchanged: fs.db, mnt/, seed.sha, seed.snapshot
                         + runs/<rid>.log (turn runs), daemon.token (daemon kind)
  platform.db            new: registry (SQLite, WAL; rusqlite is already a dep)
```

`DEN_SESSION_ROOT` env may relocate sessions (platform hosts often run
headless with a service user). Session ids reuse `valid_sid` (src/main.rs) —
no `.`/`..`/slashes, so an API request can never escape the sessions tree.

## 6. Registry schema (platform.db)

```sql
sessions(
  sid TEXT PRIMARY KEY,
  kind TEXT NOT NULL,             -- turn | daemon
  profile TEXT NOT NULL,          -- claude | codex | dex | …
  seed_json TEXT,                 -- seed spec (dir or git url, dirty mode)
  status TEXT NOT NULL,           -- idle | running | attached | exited | failed | orphaned
  owner TEXT,                     -- v1: single-tenant token; reserved for keys
  attach_port INTEGER,            -- daemon kind: host listener port
  created_at INTEGER, updated_at INTEGER
);
runs(                             -- turn kind only; dex tracks its own turns
  id TEXT PRIMARY KEY,            -- "r-<suffix>" (random_suffix, src/main.rs)
  sid TEXT NOT NULL REFERENCES sessions(sid),
  profile TEXT NOT NULL,
  prompt TEXT, argv_json TEXT,
  status TEXT NOT NULL,           -- queued | running | exited | failed | killed | orphaned
  exit_code INTEGER, pid INTEGER,
  started_at INTEGER, finished_at INTEGER,
  delta_json TEXT,                -- {added:[], modified:[], removed:[]}
  log_path TEXT
);
CREATE INDEX idx_runs_sid ON runs(sid);
```

The registry is bookkeeping only — fs.db stays the durable truth; rows can
be rebuilt by scanning `~/.den/sessions`.

## 7. Run lifecycle

```
turn:    queued → running → exited (0) | failed (!=0) | killed
daemon:  queued → attached (client connected) → idle → … → exited
either:  → orphaned (serve died mid-session; detected on boot)
```

- **Launch**: flock `<sid>.lock` (pattern: backup.rs:309-317); held → 409
  "session busy" (one live process per session).
- **Execute**: spawn child, stream child stdout+stderr to the log file, store
  pid + status. Turn kind: child exit → compute delta (§8) → update registry.
  Daemon kind: den waits; dex owns turns; registry tracks session status only.
- **Kill**: SIGTERM to the process group, SIGKILL after 10s; `DEN_RUN_TIMEOUT`
  optional per launch.

## 8. API v1

JSON bodies; auth = `Authorization: Bearer $DEN_API_TOKEN`. serve **refuses
to start without a token**: it executes agent CLIs on the host — an open
listener is an RCE primitive. Bind 127.0.0.1 by default (`DEN_BIND`);
TLS is a reverse-proxy concern, out of scope.

| Method | Path | Purpose |
|---|---|---|
| GET | /v1/health | version, fusermount3/slirp4netns presence, limits, uptime |
| POST | /v1/sessions | create/reserve: `{sid?, kind, agent, seed_dir?, seed_git?, seed_dirty?}` → `{sid}` (`agent` = full argv, e.g. `["codex","exec"]`; legacy `profile` still accepted as `agent=[profile]`) |
| GET | /v1/sessions | list (registry ∪ dir scan) |
| GET | /v1/sessions/:sid | row + fs summary (entry count, seed.sha, base key, attach info) |
| GET | /v1/sessions/:sid/files?path=… | read file / list dir via AgentFS SDK (read-only) |
| DELETE | /v1/sessions/:sid | `cmd_rm` semantics; 409 if the flock is held |
| POST | /v1/sessions/:sid/runs | turn kind: launch `{prompt?, args?, net?, timeout?}` → 202 `{run_id}` |
| POST | /v1/sessions/:sid/attach | daemon kind: `{reconnect?}` → `{attach_url, attach_token}` (ensures the child is up) |
| GET | /v1/runs/:id | `{state, exit_code, delta, log_tail, started/finished}` |
| GET | /v1/runs/:id/log | full log, text/plain |
| POST | /v1/runs/:id/kill | 202, async process-group kill |
| POST | /v1/sessions/:sid/push | land the delta as a git branch/PR (`push::push_session`) |

Error shape: `{"error": {"code", "message"}}` — 400 invalid (bad sid/seed),
401/403 auth, 404 unknown, 409 busy, 429 over `DEN_MAX_RUNS`.

Seed spec (MVP): stored at create, applied at first run via `--seed`; the
sandboxed run path is unchanged. `--seed-git` (slice 2) clones the URL to a
temp dir and feeds resolve_seed_source (which already scrubs `.git`
credentials).

## 9. Delta capture — one small refactor

`print_run_summary` (src/main.rs:895-996) computes added/modified/removed
in-line. Extract into `diff_run_snap(sid, before) -> RunDelta`:
print_run_summary calls it (CLI output byte-identical), serve serializes it
into `runs.delta_json`. The only change touching existing run code.

## 10. Agent argv (turn kind; no per-agent map)

The session stores full agent argv at create (e.g. `["codex", "exec"]`,
`["claude", "-p"]`, `["touch"]`); serve never passes a TTY (child stdio =
pipes + log) and never injects per-agent flags. A run appends the prompt
bare: `agent + [prompt]`. The caller owns headless flags — they are part of
the agent at create. Daemon kind appends `serve --fd <n>` to the stored
agent the same way.

## 11. Clients

- **dex TUI (exists)**: `dex connect <attach_url> --reattach <sid>` — journal
  replay, steering queue, remote tool approval. den's attach response gives
  it the URL + token.
- **Web UI (new, separate client)**: speaks dex's HTTP+SSE protocol for the
  transcript/steering/approval, plus den's platform API for session list /
  launch / push. MVP client = single-page app reading the two APIs.
- **TUI launcher (small)**: `den attach <sid>` opens the dex TUI pointed at
  the session's attach_url (parity with `den inspect` ergonomics).

## 12. Dependencies (Cargo.toml)

- `axum` + tokio features `net`, `time`, `sync`, `process`, `signal`.
- `serde_json` already present. litestream/slirp4netns stay optional
  (health endpoint surfaces them).

## 13. Milestones

### Slice 1 — MVP platform (single tenant, one token, turn sessions)
- `den serve`: axum listener, bearer auth, registry (platform.db), orphan
  sweep, per-session flock, DEN_MAX_RUNS.
- Endpoints: health, sessions CRUD, runs launch/status/log/kill (§8 minus
  attach/push/files).
- `diff_run_snap` refactor (§9); headless argv map (§10).
- **Acceptance**: clean host; curl create → run `codex exec` "touch
  /hello.txt" → poll → delta_json lists /hello.txt; kill a sleeping run;
  restart serve mid-run → orphaned; `den sessions`/`inspect` unchanged;
  `cargo test` green.

### Slice 2 — attachable sessions (dex daemon in the sandbox)
- dex: socket-activation / `--fd` listener adoption (small patch, dex repo).
- den sandbox: fd 4 listener passthrough into the chain (Linux-only code).
- serve: `/attach` endpoint (bind host port, spawn `dex serve --fd 3`,
  return url+token), daemon-kind lifecycle in registry.
- `den attach <sid>` TUI launcher.
- **Acceptance**: launch a daemon session over the API; `dex connect
  <attach_url> --reattach <sid>` attaches from a second terminal; steering +
  tool approval work across the sandbox boundary; fs.db captures the work;
  `den push` lands it.

### Slice 3 — platform-ness
- Web UI (reads platform API + dex protocol), files endpoint, `/push`
  endpoint, `--seed-git`, autostart replication default, run timeout,
  platform-side attach reverse proxy (SSE-aware) for multi-host.
- Multi-tenant API keys (owner column + key table), quotas, webhooks/SSE on
  completion, agent stdout JSON capture (claude `--output-format json`),
  TOML config.

## 14. Risks & mitigations

| Risk | Mitigation |
|---|---|
| fork() unsafe from multithreaded server | subprocess-per-session (§1); sandbox untouched in slice 1 |
| fd adoption across the fork chain | same pattern as the proxy listener (fd 3); exempt-fd plumbing is small and Linux-only |
| dex daemon port squatting / races | serve binds the port before spawn; registry records it; flock serializes session lifecycles |
| attach token leakage | token generated per session, injected via env, returned only to platform-authed clients; 127.0.0.1 bind |
| Agents expecting a TTY | headless map (§10); no TTY passed; per-profile "headless-proven" docs |
| FUSE mount leak from killed sessions | unmount_stale pre-run (drop_stale_session); process-group kill; `den rm` unmounts first |
| Registry drift | fs.db is truth; dir scan reconciles on boot |
| Egress prompts block headless | proxy fails closed non-TTY (proxy.rs:366); policy-file param replaces interactive approval (slice 3) |
| Linux-only (FUSE, namespaces) | health endpoint checks fusermount3/slirp4netns; documented prereq |

## 15. Explicit non-goals

- No in-process sandbox hosting (§1) and no custom agent loop in den — dex
  IS the first-party loop; other CLIs stay wrapped, not adopted.
- No new attach protocol — dex's HTTP+SSE is the wire; the web UI is a
  client of it, not a fork of it.
- No web UI shipped from this repo in slice 1 — clients are separate.
- No multi-user auth before slice 3; `owner` column reserved now.
- No Windows/macOS support (sandbox is Linux-only, unchanged).
