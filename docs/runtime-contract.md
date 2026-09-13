# den runtime contract

The interface any control plane drives den through. Versioned by
`den --version`; the control plane checks it at boot. Everything here is
process-and-filesystem shaped on purpose — no in-process API, so the
control plane can live in another process, another binary, or another
language without den changing.

## Launching runs: `den exec`

```
den exec --session <sid> [--seed <dir>] [--seed-dirty ask|all|head]
         [--autostart [--out <base.ltx>]] -- <cmd> [args…]
```

- `--session <sid>` is required; ids must pass den's sid rules
  (non-empty, no `.`/`..`/slashes — see `valid_sid`).
- Everything **before** ` -- ` is den's and is parsed strictly: unknown
  flags are errors, never eaten silently. Everything **after** ` -- ` is
  the command argv, taken verbatim (the caller owns argv assembly — e.g.
  headless agent flags like `claude -p` / `codex exec` are the caller's).
- Den resolves `<cmd>` on the **host PATH** before entering the sandbox —
  a file planted in the session overlay cannot shadow the real binary.
- Exits with the child's exit code. Run logs go to the **platform** dir
  (`~/.den/runs/`), never the session dir (sessions can be recreated
  wholesale; platform artifacts must survive).
- Behaviours identical to `den <profile>`: fresh sessions seed from
  `--seed`, resumable otherwise; `drop_stale_session` recreates a session
  whose config stamp changed (cwd/allow list/pinned base) — callers must
  treat the session dir as den-owned (see below).
- Session allow-policy is keyed by `<cmd>`'s name: known profiles get
  their extra host dirs kept writable, unknown names run bare.

## Session directory layout (den-owned; do not write into it)

```
<root>/<sid>/
  fs.db            the session's durable virtual filesystem (the truth)
  mnt/             FUSE mountpoint — only exists while a run is live
  base             pinned shared-base DB pointer (layered sessions)
  seed.sha         seed-time host HEAD, for push-drift detection
  seed.snapshot    legacy-session seed baseline
.stamps/<sid>      config stamp: cwd + allow list + base key
<root>/<sid>.lock  flock: one live process per session (cross-binary)
```

`<root>` = `~/.den/sessions` by default, `DEN_SESSION_ROOT` may relocate.
Anything the **platform** owns lives outside the session dir, under the
platform state dir (`~/.den/`): `platform.db`, `runs/<sid>/<rid>.log`,
`attach/<sid>/attach.json`.

## Environment the runtime honours

| Var | Meaning |
|---|---|
| `DEN_SESSION` | resume this session id (interactive runs; exec takes `--session`) |
| `DEN_NEW` | fresh unique session id |
| `DEN_QUIET` | suppress the post-run delta summary |
| `DEN_BASE_DB` | nested-run base pin (set by den, not callers) |
| `DEN_NET`, `DEN_PROXY_ALLOW`, `DEN_HIDE`, `DEN_LIMIT_*`, `DEN_SECCOMP` | sandbox policy (unchanged) |

## Attachable sessions

The control plane binds a host-loopback listener, clears CLOEXEC, and
passes the fd into `den exec --session <sid> -- <daemon> serve --fd <n>`.
The fd survives the whole exec chain (den closes only its own pipe fds);
the adopted daemon re-arms CLOEXEC on first use so agent-spawned children
never see it. Tokens for the daemon socket are minted per session by the
control plane and injected as env (`DEX_DAEMON_TOKEN` for dex).

## Versioning

`den --version` → `den <semver>`. The control plane refuses to start
against a runtime older than the version it was built against (checked at
serve boot).
