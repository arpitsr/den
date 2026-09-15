# den (Rust) — local coding agents, sandboxed, with typed SDK state

A Rust binary that launches any local coding-agent CLI (`claude`, `codex`,
`gemini`, `opencode`, `pi`, …) inside an OS-level sandbox (FUSE virtual
filesystem + user/mount namespaces), and binds the `agentfs-sdk` crate for
typed, in-process access to what the sandboxed agent did.

A session's filesystem is a SQLite **base + delta** pair (see
`docs/layered-sessions.md`): the seed is copied once into a shared read-only
base DB (`~/.den/bases/<content-key>/base.db`), and the session's own
`~/.den/sessions/<sid>/fs.db` holds only what the agent created, modified
(copy-up), or deleted (tombstones). A merge layer serves base ∪ delta as one
tree, so N subagents on one repo share N−1 copies of it and session start on
a base hit is O(changes), not O(repo). Sessions without a `--seed` (and
`DEN_LAYER=0`) keep the old single-DB behavior: fs.db *is* the whole tree.
Every session is still self-contained — backup/replicate/pull ship the delta
(and its tombstones); a base is content-addressed and immutable, seeded once
per repo state.

## Platform support

|                  | Linux | macOS |
| ---------------- | ----- | ----- |
| `den serve` API, sessions, seed/push/backup | ✅ | ✅ |
| Strong sandbox (FUSE virtual FS, namespaces, egress proxy) | ✅ | ❌ |
| `process` runner (same API, no isolation) | ✅ | ✅ (default) |

`DEN_RUNNER=process` (default) supervises the agent as a plain child process:
same session lifecycle, no containment — the agent runs with your full access.
`DEN_RUNNER=sandbox` (Linux only) adds the FUSE + namespace isolation above.
`den run`, `den proxy`, and `selftest --sandbox` are Linux-only and bail
elsewhere. Need containment on a Mac? Run the Linux build inside
Docker/Lima — the sandbox works unmodified in a Linux guest.

## Install

Grab a tarball from
[releases](https://github.com/arpitsr/den/releases) (Linux x86_64, macOS
arm64/x86_64), or build from source: `cargo build --release` → `den --version`.

### Seeding

`--seed <dir>` copies the dir into the session's virtual FS before the agent
starts. When the dir is inside a git repo, seeding is git-aware:

- The repo's `.git` is seeded too, as `/.git`: the agent can `git diff`,
  `git log`, and branch/commit inside the session — all private; the host
  repo is never touched, and the copy ships with `den backup` like
  everything else in the session DB. (Only when the seed dir *is* the repo
  root — a subdir seed gets no `/.git`, since a root-level history would
  mis-describe the partial tree; linked worktrees and submodules, where
  `.git` is a file, get no history either.) Remote URLs in `/.git/config`
  have credentials (`user:pass@host`) stripped before seeding, so host
  secrets don't ride along in the session DB.
- If the worktree has uncommitted changes, `den` asks:
  `N uncommitted change(s) — seed them too? [y/N]`. The default is **N**:
  the session is then seeded from HEAD via `git archive`, so it holds
  exactly the committed state — dirty edits and untracked files stay on the
  host. Non-interactive runs default to N without prompting.
- `--seed-dirty ask|all|head` overrides: `all` always seeds the dirty
  worktree, `head` never asks. Note `git archive` honors `export-ignore`
  attributes, so a repo that export-ignores (say) its tests seeds without
  them.

## Design

The sandbox layer is **in this binary** — no `agentfs` CLI dependency:

- `src/sandbox.rs` — `fork`/`unshare` user+mount namespaces, uid/gid mapping,
  `MS_REC|MS_PRIVATE`, bind-mount of the virtual FS onto the cwd, read-only
  remount of everything else (small allowlist), exec, signal forwarding.
- `src/proxy.rs` — egress allowlist proxy: the sandbox's only network path
  (via slirp4netns), CONNECT + absolute-form HTTP, chains to the host's own
  proxy (`HTTPS_PROXY` etc.) when set, 403 on blocked hosts.

The sandbox chain is M→N→U→A: M (CLI) forks N (user-ns holder), which forks
U (mount/pid/ipc/uts ns), which forks A — a tiny init (pid 1 of the sandbox
pidns) that catches INT/TERM/USR1 and forwards them to the agent (pid 2).
pidns init only receives signals it catches (`SIGNAL_UNKILLABLE`), so a
bare-agent-as-init would silently drop Ctrl-C; the init wrapper is what makes
signal escalation work (first signal forwards as-is, second → SIGKILL).
Secret dirs (`~/.ssh`, `~/.aws`, …) are hidden by mounting empty tmpfs over
them — including alias paths that expose the same inode through other
mountpoints. The network is a fresh netns (slirp4netns → tap), nft policy
(allowlist via the proxy, DNS to 10.0.2.3, everything else dropped), and a
fresh `/dev`, `/tmp`, `/run`, `/var/tmp`.
- `src/fuse.rs` + `src/mount.rs` — the FUSE filesystem (published `fuser`
  crate) that serves the session's virtual filesystem. There is no host base
  and no copy-on-write overlay: the SQLite DB *is* the filesystem, mounted
  over the cwd. The agent sees a normal POSIX tree; the host directory
  underneath is hidden and untouched.
- The storage layer is `agentfs-sdk` (`AgentFS { kv, fs, tools }`): a
  POSIX-like filesystem, a key-value store, and a tool-call audit trail in
  one SQLite file at `~/.den/sessions/<sid>/fs.db`.

den snapshots the virtual FS before and after each run and reports what the
run touched (added/modified/removed), plus the tool-call timeline
(`tools.recent`) in `den inspect`.

If you want the SDK to *be* the sandbox (drop FUSE/namespaces, build an agent
loop whose tools call `agent.fs.*` / `agent.kv.*` directly), that's a
different project — see "When to grow it" below.

## Prereqs

Linux with FUSE available (`fusermount3` or `fusermount` on `PATH` — the same
runtime requirement agentfs has) for the sandboxed runner. macOS is supported
in *process-runner* mode only (see `den serve` below): the sandbox paths bail
with a clear message, headless serve runs agents as plain children.

Any agent CLI you wrap must already be installed and authed on your `PATH`.

## den serve — durable sessions over HTTP

`den serve` runs sessions as supervised children behind an authenticated HTTP
API — the same lifecycle the CLI uses, reachable from scripts, CI, or a UI.

```bash
export DEN_API_TOKEN=$(openssl rand -hex 24)   # TCP mode: required; refuses to listen without it
den serve                                      # binds 127.0.0.1:8520
# or, local daemon mode (no token; SO_PEERCRED, same-uid only):
den serve --socket $XDG_RUNTIME_DIR/den/den.sock
```

```bash
curl -s -H "Authorization: Bearer $DEN_API_TOKEN" localhost:8520/v1/health
SID=$(curl -s -XPOST -H "Authorization: Bearer $DEN_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"profile":"claude","seed_git":"https://github.com/you/repo"}' \
  localhost:8520/v1/sessions | jq -r .sid)
curl -s -XPOST -H "Authorization: Bearer $DEN_API_TOKEN" \
  -d '{"prompt":"refactor auth"}' localhost:8520/v1/sessions/$SID/runs   # launch a turn
```

Routes (`/v1`): `POST/GET /sessions`, `GET/DELETE /sessions/{sid}`,
`POST /sessions/{sid}/attach|stop|push`, `GET /sessions/{sid}/files`,
`POST/GET /sessions/{sid}/runs`, `GET /runs/{rid}`, `GET /runs/{rid}/log`,
`GET /runs/{rid}/stream` (live run log, pushed), `POST /runs/{rid}/kill`,
`POST/GET /keys`, `POST /keys/{key_id}/revoke`. Minted `dk_…` keys are scoped to
their owner and stored hashed; foreign sessions 404.

| Env | Meaning | Default |
|---|---|---|
| `DEN_API_TOKEN` | root bearer token (TCP mode) | — |
| `DEN_SOCKET` | unix-socket path (local daemon mode; `--socket` flag also works) | `$XDG_RUNTIME_DIR/den/den.sock` |
| `DEN_BIND` | listen address | `127.0.0.1:8520` |
| `DEN_MAX_RUNS` | concurrent child runs | 8 |
| `DEN_RUNNER` | isolation backend: `process` or `sandbox` | `process` |
| `DEN_REGISTRY_URL` | registry backend (`sqlite://path`) | local platform.db |

Isolation is pluggable: `DEN_RUNNER=process` (the default, portable — plain
children with their own process group, works on macOS/CI/Docker) or
`sandbox` (the Linux FUSE + namespace backend this repo is built around).
The registry is a `Store` trait; SQLite ships here.

## Build & install

```bash
cd den
cargo build --release           # heavy first build: pulls turso + sync (~315 crates)
# then either:
cargo run --release -- <cmd> [args...]          # from the project dir
cargo install --path .                         # installs a binary named `den`
```

## Use

```bash
cd /path/to/your/project
den claude --seed . "refactor auth"   # new session preloaded with the cwd; runs `claude` inside
den claude --seed . --seed-dirty all "finish the wip"  # seed uncommitted changes too (default: ask [y/N], N seeds HEAD)
den claude "continue the refactor"    # resumes: the DB is the whole FS, host tree ignored
den codex  "fix the flaky test"       # separate session per profile+dir
den pi     "..."                      # no --seed: starts in an empty virtual FS
den opencode
den dex "triage inbox"          # XDG-based agent: config/state/cache persist with zero flags
den list                      # known profiles (any other CLI works: den <cmd> args...)
den selftest                  # sanity-check argv assembly
den selftest --sandbox        # full round-trip: seed, mount, vfs writes, ro-enforcement
den dump codex exec --json    # print the exact run argv (no exec)
den sessions                  # list persisted sessions with entry counts
den sessions --select         # show numbered sessions, choose one, print its id
den inspect [session-id]      # open a session's fs.db; omit id to choose interactively
den up [flags] <profile> <prompt...>   # launch a session run in the background daemon and exit
den logs <sid>                # show the latest run log for a session
den attach <sid>              # open the dex TUI against a daemon-attached session (needs POST /attach first)
den push [sid] [--branch b] [--to dir] [--remote r] [-m msg] [--dry-run] [--keep] [--pr]
                              # land a session's changes as a git branch on the host
den backup [sid] [--from prev.ltx] [--out path] [-c] [--watch]  # LTX backup of a session's fs.db
den restore <file.ltx> [--to db]                      # apply an LTX backup (and chain) back
den ltx <file.ltx>            # inspect/verify a backup file
den exec --session <sid> -- <cmd>...  # run a command inside a new session sandbox (also --seed/--seed-git/--autostart)
den serve [--socket PATH]     # durable sessions over HTTP (see above); `den serve stop|restart` too
--solo                        # first arg: force the in-process path, never proxy to a daemon
den replicate [sid] [url]     # litestream daemon: stream the session's fs.db to S3
den pull [sid] [url] [--force] [--to db]              # restore the session from its S3 replica
```

The wrapped agent runs normally and sees the session's virtual tree; nothing
touches the host disk. After the agent exits, `den` diffs the virtual FS
against the pre-run snapshot and prints what this run touched:

```
den: session codex-myproject — 2 added, 1 modified, 1 removed this run
  + /src/auth_test.rs
  M /src/auth.rs
  - README.md
```

Sessions are born portable: legacy sessions' `fs.db` contains the complete
tree; layered sessions ship the delta (with tombstones) plus the
content-addressed base (`~/.den/bases/<key>/base.db`, 0644, never rewritten
after seeding) — copy both and the environment reproduces on another machine
or VM without a host checkout.

Note: because resumed sessions see only the DB, host-side changes (`git pull`,
IDE edits) are invisible to an existing session. Start a fresh one
(`DEN_NEW=1`) when the world outside changes.

### Landing changes as a branch (`den push`)

The agent's writes live only in the session DB — and that's where they should
land from. `den push` (the host process, which never shows the sandbox its git
credentials — the seeded `/.git/config` is scrubbed at seed time) diffs the
session VFS against its seed baseline, applies the delta to a throwaway
worktree of the host repo, commits, and pushes a branch:

```bash
den claude --seed . "fix the flaky test"     # agent works in its private sandbox
den push                                     # -> branch den/claude-myproject, pushed to origin
den push mysession --branch den/agent-2 -m "flaky: retry on timeout" --pr
den push --dry-run --keep                    # apply to a kept worktree, commit nothing
```

The result is a reviewable PR: fan out N sessions on N tasks, push each to its
own branch, review, merge. The sandbox itself never gains push power — no
credentials inside the VFS, no egress needed; the push runs at the trust
boundary, on the host. Changes under system dirs (`/etc`, `/tmp`, `/.git`, …)
are never pushed; the session's `.git` is its own private history.

### Resume / fresh / quiet

By default the session id is `<profile>-<dirname>`, so re-running `den claude` in the
same dir **resumes** the same sandbox (changes persist across calls).

| env            | effect                                                          |
|----------------|----------------------------------------------------------------|
| `DEN_SESSION`   | pin/resume this session id instead of the `<profile>-<dir>` default |
| `DEN_NEW=1`     | start a fresh unique session, nothing carried over             |
| `DEN_QUIET=1`   | don't print the post-run delta summary                          |
| `DEN_LITESTREAM`| path to the `litestream` binary (default: from `PATH`)          |
| `DEN_REPLICA`   | replica URL for `den replicate`/`den pull` (default: `LITESTREAM_REPLICA_URL`, then `LITESTREAM_BUCKET`) |

### Sandbox env

| env            | effect                                                          |
|----------------|----------------------------------------------------------------|
| `DEN_NET`      | `proxy` (default: slirp4netns + allowlist proxy), `none` (no netns), `full` (host netns, no proxy) |
| `DEN_PROXY_ALLOW` | comma-separated extra egress hosts for the proxy (default list is minimal — agent API endpoints only, see `src/default-egress.yaml`) |
| `DEN_PROXY_POLICY` | YAML egress policy file (else `./den-egress.yaml` in the project dir if present). `allow:`/`deny:` host lists, exact or subdomain, deny wins; merged over the defaults, re-read live. Schema example: `src/default-egress.yaml` |
| — user egress config | `$XDG_CONFIG_HOME/den/egress.yaml` (default `~/.config/den/egress.yaml`), always merged between the defaults and any explicit/project file; interactive approvals persist here, so "allow and remember" applies to all projects |
| `DEN_HIDE` / `DEN_NO_HIDE` | colon-separated extra secret paths to hide / paths to un-hide (`~/.ssh` etc. are hidden by default) |
| `DEN_SECCOMP=0` | disable the seccomp filter (unshare/mount/ptrace/bpf/… get EPERM by default) |
| `DEN_PROXY_LISTEN_PORT` | debug: run `den proxy` standalone on a TCP port instead of the in-band fd 3 |
| `DEN_LIMIT_*`   | rlimits applied to the agent (see `apply_rlimits` in `src/sandbox.rs`) |

### Inspecting sessions

```bash
den sessions                  # list ~/.den/sessions/* with virtual-FS entry counts (via SDK)
den sessions --select         # number the list, prompt for a choice, print the selected id
den inspect [session-id]      # list the session's virtual FS + tool-call timeline; omit id to select
den rm [session-id]           # delete a session dir (unmounts stale FUSE mounts first; --select to pick)
```

The tool-call timeline is only populated if the agent *itself* records tool calls
through the `agentfs-sdk` (an agent you wrote). Wrapped CLIs like `claude`/`codex`
leave it empty — for those, the useful SDK surface is the touched-this-run diff
and the virtual FS listing, which is typed and in-process.

### LTX backups

Sessions persist in `~/.den/sessions/<sid>/fs.db` — a SQLite file. `den backup`
writes it in the [LTX format](https://github.com/superfly/ltx-rs) (via the
`litetx` crate): a header (page size, page count, txid range, pre-apply
checksum), the DB pages, and a trailer with post-apply + file checksums
(CRC-64/GO-ISO).

```bash
den backup codex-myproj                # snapshot -> ./codex-myproj.ltx (txid 1)
den backup codex-myproj -c             # same, LZ4-compressed
den backup codex-myproj --from codex-myproj.ltx   # delta: only changed pages (txid 2)
den backup codex-myproj --watch        # stream: snapshot + chained deltas while it runs (Ctrl-C to stop)
den ltx codex-myproj.ltx               # inspect + verify checksums
den restore codex-myproj.ltx           # -> ~/.den/sessions/codex-myproj/fs.db (replays the whole chain)
den restore codex-myproj.ltx --to /tmp/other.db
```

* A **snapshot** (no `--from`) contains every page; a **delta** (`--from
  prev.ltx`, the previous file in the chain) contains only pages whose checksum
  changed since it, with its post-apply checksum as `pre_apply` — so a delta
  only applies on top of exactly the preceding stream state.
* `--watch` streams, Litestream-style: it writes the snapshot, then appends a
  chained delta (`codex-myproj.0001.ltx`, `codex-myproj.0002.ltx`, ...)
  whenever the session DB changes, until Ctrl-C. Like Litestream it polls the
  DB + WAL (SQLite has no cross-process write hook); deltas are page-level
  LTX files rather than WAL frames. Every file is written complete, so a
  crash mid-session still leaves the chain restorable up to the last tick,
  and restarting `--watch` resumes from the newest file.
* `den <profile> --autostart` starts the watch automatically when the agent
  runs: a detached `den backup <sid> --watch` streams the session to
  `<sid>.ltx` (or `--out <base.ltx>`) while the sandbox works. It survives
  Ctrl-C on the run (log: `~/.den/sessions/<sid>/backup-watch.log`), stops on
  its own when the session is deleted, and refuses to double-run on the same
  session — stop it with `kill $(pgrep -f "den backup <sid> --watch")`.
* Restore verifies the file checksum, then the post-apply checksum, then
  `PRAGMA integrity_check`; delta restores additionally verify the pre-apply
  checksum of the target before writing. A snapshot restore replaces the
  target wholesale; a delta restore applies onto an existing DB.
* The agentfs SDK leaves its DBs in WAL mode, so `den` folds any `-wal` frames
  into the main file (`PRAGMA wal_checkpoint(TRUNCATE)`) before reading pages.
  A `-journal` sibling (mid-commit) is refused — back up after the agent exits.
  A DB large enough to contain SQLite's lock-byte page (≥1 GiB at 4 KiB pages)
  is refused — LTX cannot store that page.

### Litestream replication (continuous, off-host)

If a replica is configured and the [litestream](https://litestream.io) binary
is installed, `den` wraps it in command-line mode — no config file, credentials
come from the standard `AWS_*` / `LITESTREAM_*` env vars:

```bash
# one-time:
curl -s https://litestream.io/install.sh | sh

# per shell (or your agent's env):
export DEN_REPLICA=s3://my-bucket/coding-agents   # bucket is fixed; path is per-session
# or: LITESTREAM_REPLICA_URL=s3://...  /  LITESTREAM_BUCKET=my-bucket
# plus AWS creds (S3, or any S3-compatible endpoint via AWS_ENDPOINT_URL):
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

den codex "fix the flaky test" --autostart   # litestream streams the session to S3 while the agent works
den replicate codex-myproject                  # same, as a foreground daemon (Ctrl-C stops it)
den pull codex-myproject                       # restore newest state back into the session dir
den pull codex-myproject --force --to /tmp/db  # overwrite / restore elsewhere
```

* `den <profile> --autostart` prefers litestream when a replica is configured
  **and** the binary is installed; otherwise it falls back to the local LTX
  watch above. A detached `den replicate <sid>` streams
  `~/.den/sessions/<sid>/fs.db` to `s3://<bucket>/<sid>/db` continuously
  (litestream's ~1s sync), survives Ctrl-C on the run (log:
  `~/.den/sessions/<sid>/replicate.log`), exits on its own when the session is
  deleted, and refuses a second daemon on the same session (flock). Stop it
  with `kill $(pgrep -f "den replicate <sid>")`.
* Replica URL resolution: explicit arg `den replicate <sid> s3://...` >
  `DEN_REPLICA` > `LITESTREAM_REPLICA_URL` > `LITESTREAM_BUCKET` (synthesized
  to `s3://<bucket>/<sid>/db`, so sessions never collide in one bucket).
  `DEN_LITESTREAM` overrides the binary path.
* The daemon runs with `-restore-if-db-not-exists`, so a fresh machine that
  starts a session with an existing replica pulls it back automatically.
  `den pull` runs `litestream restore` with `-if-replica-exists` (a
  never-backed-up session is a no-op) and `-integrity-check quick`; it
  refuses to overwrite an existing DB unless `--force`. Don't pull into a
  session while its agent is still running — same hazard as LTX restore.

## Commands (profiles)

Any first argument is the command to run: `den anything args...` execs
`anything args...` inside the sandbox. A few known agents get extra host dirs
kept writable beyond the sandbox defaults (the four XDG base dirs —
`~/.config`, `~/.local/share`, `~/.local/state`, `~/.cache` — plus legacy
agent dotdirs like `~/.claude`, `~/.codex`, `~/.npm`): `ak` (`.ak`),
`pi` (`.pi`), `opencode` (`.opencode`) — see `fn profile` in `src/main.rs`
and `build_allowed_paths` in `src/sandbox.rs`. XDG-following agents (e.g.
`dex`, which keeps config, state, logs and caches under `<base>/dex/`)
persist with zero flags: `den dex ...` just works.
Unknown commands just get the defaults.

## Project layout

```
den/
  Cargo.toml            agentfs-sdk 0.6.4, fuser (FUSE), tokio, anyhow, litetx, rusqlite
  src/main.rs           profiles, argv assembly, seed/base/snapshot, run/inspect/sessions/dump/selftest
  src/sandbox.rs        fork/unshare namespaces, read-only remount, exec, signals
  src/proxy.rs          egress allowlist proxy (CONNECT + absolute-form HTTP)
  src/policy.rs         egress policy sources (YAML FilePolicy, re-read live; cloud later)
  src/layer.rs          base+delta merge layer (copy-up, tombstones, merged listings)
  src/fuse.rs           FUSE filesystem serving the session's SQLite virtual FS (fuser)
  src/mount.rs          mount lifecycle (fusermount), MountHandle, helpers
  src/backup.rs         LTX backup/restore/inspect of session fs.db files (litetx + rusqlite)
  src/serve.rs          den serve: axum HTTP API, supervision, registry, auth (bearer + dk_ keys)
  src/registry.rs       platform.db — run/session bookkeeping (rebuildable from ~/.den/sessions)
  src/runner.rs         Runner trait: process (default) vs sandbox isolation backends
  src/client.rs         CLI↔daemon client: opportunistic unix-socket proxy (--solo disables)
  src/push.rs           den push: session VFS diff → throwaway worktree → git branch on the host
  examples/mkdelta.rs   throwaway: builds a fake session fs.db via the SDK (used to test
                        inspect/sessions + backups without the real agentfs CLI)
```

## When to grow it

- **Own the tool layer** → build a tiny Rust agent loop whose tools call
  `agent.fs.*` / `agent.kv.*` / `agent.tools.*` directly. Now the SDK *is* the
  sandbox (the agent has no other FS access), no FUSE/namespaces needed. This is
  what `agentfs-sdk` is designed for and is the cleanest next step if you want
  programmatic control of the agent instead of wrapping a CLI.
- **macOS support** → the port covers Linux only. The original agentfs CLI has an
  NFS-based macOS path; bring that in if macOS matters.
- **Off-host backup** → already wired: `den replicate`/`den pull` wrap
  litestream (continuous S3 replication of the fs.db; see above). If you
  want retention tuning, snapshots on a schedule, or a control socket, point
  litestream at a config file instead of env vars (`den replicate` uses
  command-line mode; a hand-written `litestream.yml` still works — it's just
  a binary litestream is exec'd with either way).
- **TOML config + a TUI** → partially here: `den attach` opens the dex TUI
  against a running daemon session. A richer session browser over the fs.db
  files is still future work.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build checks and PR conventions.
Report security issues privately per [SECURITY.md](SECURITY.md) — do not open
public issues for vulnerabilities. The OSS scope and release plan live in
[docs/oss-charter.md](docs/oss-charter.md) and [docs/oss-launch.md](docs/oss-launch.md).

## License

Dual-licensed under MIT and Apache-2.0 — see [LICENSE](LICENSE) and
[LICENSE-APACHE](LICENSE-APACHE).
