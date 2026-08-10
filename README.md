# pit (Rust) — local coding agents, sandboxed, with typed SDK state

A Rust binary that launches any local coding-agent CLI (`claude`, `codex`,
`gemini`, `opencode`, `pi`, …) inside an OS-level sandbox (FUSE copy-on-write
overlay + user/mount namespaces), and binds the `agentfs-sdk` crate for typed,
in-process access to what the sandboxed agent did.

## Design

The sandbox layer is **in this binary** — no `agentfs` CLI dependency:

- `src/sandbox.rs` — `fork`/`unshare` user+mount namespaces, uid/gid mapping,
  `MS_REC|MS_PRIVATE`, bind-mount of the overlay onto the cwd, read-only
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
  crate) that serves the copy-on-write overlay. The current working directory
  is the sandbox base: host files are read-only, every write is captured to a
  SQLite delta DB, deletes become whiteouts.
- The storage layer is `agentfs-sdk` (`AgentFS { kv, fs, tools }`): a
  POSIX-like filesystem, a key-value store, and a tool-call audit trail in
  one SQLite file at `~/.agentfs/run/<sid>/delta.db`.

pit opens that DB in-process and surfaces a typed diff (`get_delta_paths` /
`get_whiteouts` / `is_overlay_enabled`) and tool-call timeline
(`tools.recent`). The session layout is identical to agentfs's, so existing
agentfs sessions interoperate.

If you want the SDK to *be* the sandbox (drop FUSE/namespaces, build an agent
loop whose tools call `agent.fs.*` / `agent.kv.*` directly), that's a
different project — see "When to grow it" below.

## Prereqs

Linux with FUSE available (`fusermount3` or `fusermount` on `PATH` — the same
runtime requirement agentfs has). macOS is not supported (no sandbox path; the
binary bails with a clear message).

Any agent CLI you wrap (`claude`/`codex`/`gemini`/`opencode`/`pi`) must already
be installed and authed on your `PATH`.

## Build & install

```bash
cd pit
cargo build --release           # heavy first build: pulls turso + sync (~280 crates)
# then either:
cargo run --release -- <profile> [args...]     # from the project dir
cargo install --path .                         # installs a binary named `pit`
```

## Use

```bash
cd /path/to/your/project     # this dir becomes the copy-on-write sandbox base
pit claude "refactor auth"    # runs `claude` inside the sandbox; prints delta diff after
pit codex  "fix the flaky test"
pit pi     "..."
pit opencode
pit list                      # configured profiles
pit selftest                  # sanity-check argv assembly
pit selftest --sandbox        # full round-trip: mount, delta, whiteouts, ro-enforcement
pit dump codex exec --json    # print the exact run argv (no exec)
pit sessions                  # list persisted sessions with changed/deleted counts
pit sessions --select         # show numbered sessions, choose one, print its id
pit inspect [session-id]      # open a session's delta DB; omit id to choose interactively
pit backup [sid] [--from prev.ltx] [--out path] [-c] [--watch]  # LTX backup of a session's delta DB
pit restore <file.ltx> [--to db]                      # apply an LTX backup (and chain) back
pit ltx <file.ltx>            # inspect/verify a backup file
pit replicate [sid] [url]     # litestream daemon: stream the session's delta DB to S3
pit pull [sid] [url] [--force] [--to db]              # restore the session from its S3 replica
```

The wrapped agent runs normally and sees its own working tree; writes land in
the delta layer, not on disk. After the agent exits, `pit` opens the persisted
delta DB via the SDK and prints a compact diff:

```
pit: session codex-myproject — 3 changed, 1 deleted
  + /src/auth.rs
  + /src/auth_test.rs
  - README.md
```

### Resume / fresh / quiet

By default the session id is `<profile>-<dirname>`, so re-running `pit claude` in the
same dir **resumes** the same sandbox (changes persist across calls).

| env            | effect                                                          |
|----------------|----------------------------------------------------------------|
| `PIT_SESSION`   | pin/resume this session id instead of the `<profile>-<dir>` default |
| `PIT_NEW=1`     | start a fresh unique session, nothing carried over             |
| `PIT_QUIET=1`   | don't print the post-run delta summary                          |
| `PIT_LITESTREAM`| path to the `litestream` binary (default: from `PATH`)          |
| `PIT_REPLICA`   | replica URL for `pit replicate`/`pit pull` (default: `LITESTREAM_REPLICA_URL`, then `LITESTREAM_BUCKET`) |

### Sandbox env

| env            | effect                                                          |
|----------------|----------------------------------------------------------------|
| `PIT_NET`      | `proxy` (default: slirp4netns + allowlist proxy), `none` (no netns), `full` (host netns, no proxy) |
| `PIT_PROXY_ALLOW` | comma-separated extra egress hosts for the proxy (default list: anthropic/openai/google/opencode/archlinux.org + more in `src/proxy.rs`) |
| `PIT_HIDE` / `PIT_NO_HIDE` | colon-separated extra secret paths to hide / paths to un-hide (`~/.ssh` etc. are hidden by default) |
| `PIT_SECCOMP=0` | disable the seccomp filter (unshare/mount/ptrace/bpf/… get EPERM by default) |
| `PIT_PROXY_LISTEN_PORT` | debug: run `pit proxy` standalone on a TCP port instead of the in-band fd 3 |
| `PIT_LIMIT_*`   | rlimits applied to the agent (see `apply_rlimits` in `src/sandbox.rs`) |

### Inspecting sessions

```bash
pit sessions                  # list ~/.agentfs/run/* with changed/deleted counts (via SDK)
pit sessions --select         # number the list, prompt for a choice, print the selected id
pit inspect [session-id]      # full diff +, deletions -, and tool-call timeline; omit id to select
pit rm [session-id]           # delete a session dir (unmounts stale FUSE mounts first; --select to pick)
```

The tool-call timeline is only populated if the agent *itself* records tool calls
through the `agentfs-sdk` (an agent you wrote). Wrapped CLIs like `claude`/`codex`
leave it empty — for those, the useful SDK surface is the delta diff (what files
the agent created/modified/deleted), which is typed and in-process.

### LTX backups

Sessions persist in `~/.agentfs/run/<sid>/delta.db` — a SQLite file. `pit backup`
writes it in the [LTX format](https://github.com/superfly/ltx-rs) (via the
`litetx` crate): a header (page size, page count, txid range, pre-apply
checksum), the DB pages, and a trailer with post-apply + file checksums
(CRC-64/GO-ISO).

```bash
pit backup codex-myproj                # snapshot -> ./codex-myproj.ltx (txid 1)
pit backup codex-myproj -c             # same, LZ4-compressed
pit backup codex-myproj --from codex-myproj.ltx   # delta: only changed pages (txid 2)
pit backup codex-myproj --watch        # stream: snapshot + chained deltas while it runs (Ctrl-C to stop)
pit ltx codex-myproj.ltx               # inspect + verify checksums
pit restore codex-myproj.ltx           # -> ~/.agentfs/run/codex-myproj/delta.db (replays the whole chain)
pit restore codex-myproj.ltx --to /tmp/other.db
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
* `pit <profile> --autostart` starts the watch automatically when the agent
  runs: a detached `pit backup <sid> --watch` streams the session to
  `<sid>.ltx` (or `--out <base.ltx>`) while the sandbox works. It survives
  Ctrl-C on the run (log: `~/.agentfs/run/<sid>/backup-watch.log`), stops on
  its own when the session is deleted, and refuses to double-run on the same
  session — stop it with `kill $(pgrep -f "pit backup <sid> --watch")`.
* Restore verifies the file checksum, then the post-apply checksum, then
  `PRAGMA integrity_check`; delta restores additionally verify the pre-apply
  checksum of the target before writing. A snapshot restore replaces the
  target wholesale; a delta restore applies onto an existing DB.
* The agentfs SDK leaves its DBs in WAL mode, so `pit` folds any `-wal` frames
  into the main file (`PRAGMA wal_checkpoint(TRUNCATE)`) before reading pages.
  A `-journal` sibling (mid-commit) is refused — back up after the agent exits.
  A DB large enough to contain SQLite's lock-byte page (≥1 GiB at 4 KiB pages)
  is refused — LTX cannot store that page.

### Litestream replication (continuous, off-host)

If a replica is configured and the [litestream](https://litestream.io) binary
is installed, `pit` wraps it in command-line mode — no config file, credentials
come from the standard `AWS_*` / `LITESTREAM_*` env vars:

```bash
# one-time:
curl -s https://litestream.io/install.sh | sh

# per shell (or your agent's env):
export PIT_REPLICA=s3://my-bucket/coding-agents   # bucket is fixed; path is per-session
# or: LITESTREAM_REPLICA_URL=s3://...  /  LITESTREAM_BUCKET=my-bucket
# plus AWS creds (S3, or any S3-compatible endpoint via AWS_ENDPOINT_URL):
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

pit codex "fix the flaky test" --autostart   # litestream streams the session to S3 while the agent works
pit replicate codex-myproject                  # same, as a foreground daemon (Ctrl-C stops it)
pit pull codex-myproject                       # restore newest state back into the session dir
pit pull codex-myproject --force --to /tmp/db  # overwrite / restore elsewhere
```

* `pit <profile> --autostart` prefers litestream when a replica is configured
  **and** the binary is installed; otherwise it falls back to the local LTX
  watch above. A detached `pit replicate <sid>` streams
  `~/.agentfs/run/<sid>/delta.db` to `s3://<bucket>/<sid>/db` continuously
  (litestream's ~1s sync), survives Ctrl-C on the run (log:
  `~/.agentfs/run/<sid>/replicate.log`), exits on its own when the session is
  deleted, and refuses a second daemon on the same session (flock). Stop it
  with `kill $(pgrep -f "pit replicate <sid>")`.
* Replica URL resolution: explicit arg `pit replicate <sid> s3://...` >
  `PIT_REPLICA` > `LITESTREAM_REPLICA_URL` > `LITESTREAM_BUCKET` (synthesized
  to `s3://<bucket>/<sid>/db`, so sessions never collide in one bucket).
  `PIT_LITESTREAM` overrides the binary path.
* The daemon runs with `-restore-if-db-not-exists`, so a fresh machine that
  starts a session with an existing replica pulls it back automatically.
  `pit pull` runs `litestream restore` with `-if-replica-exists` (a
  never-backed-up session is a no-op) and `-integrity-check quick`; it
  refuses to overwrite an existing DB unless `--force`. Don't pull into a
  session while its agent is still running — same hazard as LTX restore.

## Profiles

Built into `src/main.rs` (`fn profile`): `claude`, `codex`, `gemini`, `opencode`,
`pi`. Each maps to a command plus extra `--allow` host dirs (beyond the sandbox
defaults: `~/.config`, `~/.cache`, `~/.local`, `~/.npm`, `~/.claude`, `~/.codex`,
`~/.gemini`, `~/.amp`). To add a custom agent, add a match arm. When you have more
than a couple of custom agents, bring in a TOML config (`~/.config/pit/agents.toml`)
— YAGNI until then.

## Project layout

```
pit/
  Cargo.toml            agentfs-sdk 0.6.4, fuser (FUSE), tokio, anyhow, litetx, rusqlite
  src/main.rs           profiles, argv assembly, run/inspect/sessions/dump/selftest
  src/sandbox.rs        fork/unshare namespaces, read-only remount, exec, signals
  src/proxy.rs          egress allowlist proxy (CONNECT + absolute-form HTTP)
  src/fuse.rs           FUSE filesystem serving the COW overlay (fuser)
  src/mount.rs          mount lifecycle (fusermount), MountHandle, helpers
  src/backup.rs         LTX backup/restore/inspect of session delta DBs (litetx + rusqlite)
  examples/mkdelta.rs   throwaway: builds a fake session delta DB via the SDK (used to test
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
- **Off-host backup** → already wired: `pit replicate`/`pit pull` wrap
  litestream (continuous S3 replication of the delta DB; see above). If you
  want retention tuning, snapshots on a schedule, or a control socket, point
  litestream at a config file instead of env vars (`pit replicate` uses
  command-line mode; a hand-written `litestream.yml` still works — it's just
  a binary litestream is exec'd with either way).
- **TOML config + a TUI** → once there are several custom agents or you want a
  session browser over the delta DBs.

The bash `./pit` at the repo root (the original prototype) can be deleted once this
Rust binary is installed; it's kept only as a reference for the same behaviour.
