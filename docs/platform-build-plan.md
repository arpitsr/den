# Build plan — den platform

Task-level sequel to `docs/platform-api.md` (architecture lives there; this
file is the sequenced work plan with verification gates). Checkboxes track
progress; CI gates for every phase: `cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test` (matches .github/workflows/ci.yml).

## Phase 0 — prereqs (gate before any code)

- [x] Linux host with FUSE: `fusermount3` present, `/dev/fuse` available
- [ ] Egress deps for default networking: `slirp4netns`, `nft` (or accept
      `DEN_NET=none` for MVP smoke tests)
- [x] Agents on PATH: `dex` built (`cargo build --release` in ~/Work/dex),
      plus `codex`/`claude` for cross-agent checks
- [ ] Service-account layout: `DEN_SESSION_ROOT` (e.g. /var/lib/den/sessions)
      decided; run den under it once manually
- **Gate**: `den raw sh -c 'echo ok'` works; `den dex -p "say hi"` completes
  inside the sandbox and the delta prints.

## Phase 1 — den serve MVP: turn sessions (den-only)

Order matters: registry → diff refactor → argv map → serve module → dispatch.

1. [x] **Cargo.toml**: add `axum` (json, http1); extend tokio features to
   `["rt-multi-thread", "macros", "net", "time", "sync", "process", "signal"]`.
2. [x] **src/registry.rs** — platform.db (schema: platform-api.md §6):
   open/create with WAL, `sessions` + `runs` tables, CRUD: upsert_session,
   get/list_sessions, insert_run, update_run, mark_orphans (status
   transition on boot). Sync rusqlite behind a small API; serve calls it
   from `spawn_blocking` with a `Mutex<Connection>`. Unit tests against a
   tempdir DB (schema, transitions, orphan sweep).
3. [x] **diff refactor (src/main.rs)**: extract the added/modified/removed
   computation from `print_run_summary` (main.rs:895-996) into
   `pub(crate) async fn diff_run_snap(sid, before) -> RunDelta` with
   `RunDelta { added, modified, removed }` (serde). print path keeps
   byte-identical output. Unit tests on synthetic RunSnap values (legacy +
   layered, incl. no-op copy-up exclusion).
4. [x] **Headless argv map (src/main.rs)**: extend `Profile` with a
   headless builder per §10 of platform-api.md (dex → `-p <prompt>`,
   claude → `-p`, codex → `exec`, gemini → `-p`, opencode → `run`; unknown →
   bare prompt arg). `build_argv` gains a `headless(prompt: Option<&str>)`
   mode. Tests: argv assembly per profile with/without prompt.
5. [x] **src/serve.rs**:
   - bearer auth: `DEN_API_TOKEN` required — refuse to boot without it;
     constant-time compare middleware.
   - routes (turn subset of §8): health, POST/GET/GET-id/DELETE sessions,
     POST runs, GET run, GET run log, POST run kill.
   - supervisor: `tokio::process::Command` → `den <profile> …` with
     `process_group(0)`; stdout+stderr both → `<sessions>/<sid>/runs/<rid>.log`;
     store pid + status=running; on exit compute `diff_run_snap` →
     `runs.delta_json` → session status exited/failed.
   - per-session flock `<sid>.lock` (copy the LOCK_EX|LOCK_NB pattern,
     backup.rs:309-317): acquire pre-spawn, hold until reap; held → 409.
   - kill: SIGTERM to process group, SIGKILL after 10s (`tokio::time`).
   - `DEN_MAX_RUNS` gate → 429 (default 8).
   - orphan sweep at boot: every row still `running` → `orphaned` (a
     restarted serve observes no children; a surviving orphan keeps the
     session flock until it exits).
6. [x] **Dispatch (src/main.rs)**: `den serve` arm; env config: DEN_API_TOKEN
   (required), DEN_BIND (default `127.0.0.1:8520` — dex owns 8420,
   don't collide), DEN_MAX_RUNS, DEN_SESSION_ROOT.
7. [x] **Tests + smoke**: registry/argv/diff unit tests wired into
   `cmd_selftest`; `scripts/smoke-serve.sh` — the §13 acceptance flow in
   curl: create session → launch `codex exec` "touch /hello.txt" → poll run →
   delta_json lists /hello.txt → kill a sleeping run → restart serve mid-run
   → orphaned.
- **Gate**: smoke script green; `den sessions`/`den inspect` outputs
  unchanged; full CI clean.

## Phase 2 — attachable sessions (dex daemon inside the sandbox)

Can start in parallel with Phase 1: the dex patch is a separate repo.

8. [x] **dex patch (~/Work/dex)**: listener adoption — `dex serve --fd <n>`
   and/or `LISTEN_FDS`/`LISTEN_FDNAMES`: build `std::net::TcpListener` from
   the raw fd (`FromRawFd`, CLOEXEC already cleared by den) and hand it to
   the existing `run_daemon(listener)` (src/daemon/mod.rs:710). Token path
   unchanged (`DEX_DAEMON_TOKEN` env). dex-repo test: bind a listener in the
   test, pass its fd via env, assert the daemon serves on it.
9. [x] **fd passthrough (src/sandbox.rs, Linux-only)**: den serve binds the
   host listener, passes it down N→U→A (CLOEXEC cleared; exempt the fd from
   the chain's child fd-cleanup, mirroring how the proxy listener reaches
   its child). IMPLEMENTED WITH ZERO sandbox.rs CHANGES: the chain only
   closes its own named pipes (no fd sweep), so a CLOEXEC-cleared listener
   fd survives the whole M→N→U→A→exec chain by plain inheritance. The smoke
   script (daemon-attach flow) is the live gate.
10. [x] **/attach endpoint (src/serve.rs)**: daemon-kind session with no live
   child → bind `127.0.0.1:<port>` (ephemeral, recorded in registry),
   generate `DEX_DAEMON_TOKEN`, spawn `den dex serve --fd 4`, status=attached;
   response `{attach_url, attach_token}`. Reap → status idle/exited;
   relaunch on next /attach (dex journal + fs.db keep continuity).
11. [x] **`den attach <sid>`**: host TUI launcher — runs `dex connect
   <attach_url> --reattach <sid>` with the token wired through.
- [x] **Multi-turn turn-kind sessions (den side)**: turn sessions are
  conversations, not one-shots. dex path: den pre-assigns the agent session
  id (`--session <sid>` on the *first* run too — no capture needed). Generic
  CLIs: after each run, den reads the agent's own session id out of the VFS
  and records it in `<sid>/agent-session`; the next `POST /runs` passes the
  per-profile resume args (`claude --resume <id>`, `codex exec resume <id>`,
  …). API unchanged — a second `POST /runs` on the same sid is simply the
  next turn of the same conversation.
- **Gate** (platform-api.md §13 slice 2): launch a daemon session via curl;
  attach from a second terminal with `dex connect`; steering + remote tool
  approval work across the sandbox boundary; fs.db captures the work; `den
  push` lands it as a branch.

## Phase 3 — platform-ness (chunked, after attach is real)

12. [ ] `GET /sessions/:sid/files` — AgentFS SDK read (file content / dir
   listing), read-only connection like `den inspect`.
13. [ ] `POST /sessions/:sid/push` — call `push::push_session` directly;
   JSON-ify the PushOpts result (changed/deleted/status already structured).
14. [ ] `--seed-git <url>` — clone to temp, feed `resolve_seed_source`;
   seed spec stored at create, replayed on relaunch.
15. [ ] Durability default: `--autostart` on every launch when a replica is
   configured; `DEN_RUN_TIMEOUT` support in the supervisor.
16. [ ] Web UI client (separate dir/repo): session list + launch (platform
   API) + transcript/steering/approval (dex HTTP+SSE) + push button.
17. [ ] Multi-tenant: API-key table + `owner` column use, per-key quotas
   (429), platform-side SSE-aware attach reverse proxy for multi-host.
18. [ ] Agent stdout JSON capture (claude `--output-format json`,
   `DEX_JSON` if dex gains one) into runs; webhook/SSE on run completion.
19. [ ] TOML config for profiles/limits (README "when to grow it" trigger:
   several custom agents).
- [ ] **Generic daemon bridge (Phase 2 follow-up)**: in-sandbox forwarder
   that adopts fd 4 and proxies to any agent daemon's in-netns port
   (platform-api.md §3 "Any agent daemon"); enforces the session token when
   the agent has no daemon auth. Unlocks `opencode serve` and any port-based
   daemon without agent-side patches; dex stays native-adoption.

## Sequencing & parallelism

```
Phase 1 (den serve) ──────────────┐
Phase 2.8 (dex patch, parallel) ──┴─▶ Phase 2.9-11 (attach) ─▶ Phase 3 chunks
```

- 1–7 are den-only and unblock everything.
- 8 is independent (other repo) — start it whenever.
- 9–11 need both 1 and 8.
- 3 is the only change to existing run code; do it before serve consumes
  deltas.
- 12–15 are independent of 16–19; ship in any order after Phase 2.

## Definition of done (per phase)

- CI clean (fmt, clippy -D warnings, test) on every commit.
- Smoke script for the phase's acceptance flow, runnable on a clean host.
- README gains a "Platform" section once Phase 1 lands (env table +
  endpoint list); platform-api.md updated where implementation diverged.
- No sandbox behaviour change: `den <profile>`, `den inspect`, `den push`
  behave byte-identically for interactive users.

## Risk watchlist (details: platform-api.md §14)

fork-from-single-thread (subprocess model), fd adoption across the chain,
port/token lifecycle for daemon sessions, TTY-less agents (headless map),
mount leaks on kill (unmount_stale + process-group kill), registry vs fs.db
drift (dir scan reconciles), Linux-only deps surfaced by /health.
