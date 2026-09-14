# Socket daemon — single process, CLI combo (design)

Status: plan. Builds on platform-api.md §1 (process model) and the oss-launch
scope (docs/oss-launch.md). The daemon is `den serve` with a second listener;
the CLI becomes an opportunistic client. The sandbox stays inside the child.

## 0. Decision and non-goals

**Decision**: one long-lived `den serve` process owns all session children;
the CLI detects it over a unix socket and proxies lifecycle commands. No
socket and no autospawn? Today's in-process solo mode runs unchanged.

Non-goals:

- No sandboxing in the daemon (multithreaded process cannot host the fork
  chain — platform-api.md §1 is unchanged; children remain `den exec`).
- No mandatory daemon: solo mode is permanent, zero-config, CI-friendly.
- No daemon manager: no pid files, no init zoo. Socket presence + `/v1/health`
  is the liveness story; the existing boot orphan-sweep handles daemon death.
- The TCP surface does not change — the SaaS layer keeps sitting on it.

## 1. Component model

```
                       ┌──────────────────────────────────────────┐
                       │              den serve (1 proc)          │
                       │                                          │
   remote/HTTP ───────▶│  TCP :8520 ── bearer auth ─┐             │
   (platform, SaaS)    │                            ├─ axum       │
                       │  local/unix ── peercred ───┘   Router    │
                       │   $XDG_RUNTIME_DIR/den.sock  (same one)  │
                       └──────────────┬───────────────────────────┘
                                      │ spawn `den exec --session <sid>`
                                      ▼
                        ┌──────────────────────────────┐
                        │ session children (own pgid)  │
                        │ sandbox: FUSE + namespaces   │
                        └──────────────────────────────┘

   den CLI (thin client)                                  solo mode
   ─────────────────────                                  ──────────
   socket exists → proxy lifecycle over socket        no socket →
   (sessions, up, attach, push, logs, runs)           in-process exec
   socket missing → autospawn serve, retry            (today's path,
   DEN_AUTOSPAWN=0 / --solo → always solo             unchanged)
```

| Component | File | Change |
|---|---|---|
| **Serve transports** | `src/serve.rs` | + `--socket PATH`: second `axum::serve` on `UnixListener`, same `Router`. Boot accepts TCP-only, socket-only, or both |
| **Local auth** | `src/serve.rs` | + peer-cred middleware on the socket listener only: `SO_PEERCRED` uid == euid ⇒ root `AuthContext`; a bearer key still honored if presented. TCP keeps bearer-only |
| **CLI client** | `src/client.rs` (new) | Socket detection, typed calls for the proxyable commands, version handshake, error mapping (daemon down → clear message, not a Rust backtrace) |
| **CLI dispatch** | `src/main.rs` | Lifecycle subcommands route: `--solo` or no daemon ⇒ in-process (today); else proxy. `--solo` forces in-process; an empty prompt (interactive TUI) always stays in-process — it has nothing to POST and no TTY to stream |
| **Autospawn** | `src/client.rs` | Double-fork detached `den serve --socket`, spawn-lock file so parallel first calls don't race, 3s socket-wait timeout. Autospawned daemons are socket-only: the child env drops `DEN_API_TOKEN`/`DEN_BIND`, so a local convenience daemon never silently opens a TCP port (explicit `den serve restart` preserves the env, so a deliberately-run TCP daemon restarts as one) |
| **Version pin** | `serve.rs` health | `/v1/health` already returns `version`; on mismatch the client refuses the proxy with a `den serve restart` hint (`den sessions`/`den up` bail — their daemon-side data is invisible to a stale CLI; the one-shot run warns and falls back in-process so the user's command still completes) |

Runner, registry, sandbox, durability: untouched.

## 2. Auth model per transport

| Transport | Auth | Root context | Keys |
|---|---|---|---|
| TCP (as today) | bearer required, no token ⇒ no listen | `DEN_API_TOKEN` | hashed `dk_…` |
| Unix socket | none required | same-uid via `SO_PEERCRED` | accepted if presented; an unknown/empty bearer falls through to the peercred check rather than 401 (the uid is the ground truth — TCP keeps bearer-strict) |

Refusal rules stay: `den serve --socket` with neither `DEN_API_TOKEN` nor
`--socket` fails; socket path gets 0600 perms and lives under
`XDG_RUNTIME_DIR` (per-user, tmpfs, gone on logout/reboot — no stale-socket
hygiene problem in practice; serve removes its socket at startup and exit).

## 3. CLI behavior matrix

| Command | daemon present | no daemon |
|---|---|---|
| `den <profile> "prompt"` | proxy: launch + stream + print delta | in-process (today) |
| `den sessions / inspect` | proxy | read fs.db/platform.db directly (today) |
| `den up` (launch-and-detach) | **new: returns immediately, run lives in daemon** | autospawn then same |
| `den attach <sid>` | proxy to attach_url (socket-bound URL for local) | error: session only exists under daemon |
| `den push/backup/replicate` | local always (fs.db is on-disk; no daemon needed) | local |
| `den serve stop [--socket PATH]` | **new: SIGTERM the daemon** (10 s grace → SIGKILL); it removes its socket + `<socket>.pid` | reports `not running` (exit 1), tidies a dead socket/pid pair |

Launch-and-detach is the headline capability: `den up "fix the tests"` =
create + launch + print sid/log path, exit. Come back with `den logs <sid>`.
Solo mode keeps waiting synchronously — no behavior change for scripts.

## 4. Failure matrix

| Failure | Effect | Recovery |
|---|---|---|
| Daemon not running, autospawn on | transparent autospawn (<1s) | nothing to do |
| Daemon dies mid-child | children keep running (own processes); boot sweep marks orphans | restart; sweep does the rest |
| Stale socket file | connect() fails ⇒ treated as missing ⇒ autospawn; serve unlinks stale path at boot | automatic |
| Version mismatch | client refuses proxy, prints hint | `den serve restart` (new: stop+start via spawn-lock) |
| `--solo` while daemon runs | two lifecycle owners on one host — flock files keep sessions exclusive per-sid, as today | accepted, documented |
| Socket dir missing (no XDG_RUNTIME_DIR, e.g. cron) | serve falls back to `XDG_STATE_HOME/den/den.sock` with a warning | automatic |
| Stale pid file (daemon killed -9, pid reused) | stop verifies `/proc/<pid>/cmdline` is a `den serve` before signalling; a foreign pid is refused and the file removed | automatic |

## 5. Phases (each shippable, gates per phase)

1. **Socket transport + peercred auth** (~150 LOC): `--socket`, UnixListener
   serve, auth split, stale-socket unlink, 0600. Gate: smoke shows socket
   health + TCP health both live, bearer not required over socket.
2. **CLI client + version handshake** (~300 LOC): `client.rs`, lifecycle
   proxying, error mapping. Gate: identical output for proxy vs solo
   `den sessions`.
3. **Autospawn + `--solo` + `den up`** (~200 LOC): spawn-lock, wait loop,
   background runs. Gate: `scripts/smoke-socket.sh` — solo run, autospawn,
   proxy run, `den up` + close-term + `den logs`, daemon kill → orphan sweep,
   version-mismatch refusal.
4. **Streaming + stop** (~250 LOC): `/v1/runs/:id/stream` — the daemon
   tails the run log server-side and pushes length-prefixed frames
   (`log`/`ping`/`done`); the CLI holds one connection instead of
   re-downloading the whole file every 500 ms (O(log bytes) vs O(n²)).
   Old daemons without the route fall back to polling. Plus
   `den serve stop`: pid file at `<socket>.pid`, SIGTERM → 10 s → SIGKILL,
   socket + pid file removed on the way down. Gate: smoke-socket.sh steps
   9–11. *Still open:* TUI attach over socket — moot for the local daemon
   (the CLI reaches the dex TUI on its own localhost port today); it only
   matters for remote daemons, which the socket daemon doesn't serve.

Total ~650 lines, no new dependencies (unix sockets via tokio net, peercred
via nix/libc getsockopt — std `std::os::unix` + libc, both already in tree).

## 6. Why this shape is right

- One process owns children and mounts ⇒ kill semantics, orphan sweeps, and
  logging have a single owner; flock coordination becomes the exception, not
  the design.
- Zero-config local + the same auth surface for remote: the SaaS layer never
  learns the socket exists.
- Solo mode keeps the OSS quickstart at one binary, no background process —
  the daemon is an upgrade, not a requirement.
