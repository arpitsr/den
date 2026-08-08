# pit (Rust) — local coding agents, sandboxed with AgentFS, with typed SDK state

A Rust binary that launches any local coding-agent CLI (`claude`, `codex`,
`gemini`, `opencode`, `pi`, …) inside an [AgentFS](https://github.com/tursodatabase/agentfs)
sandbox, and binds the `agentfs-sdk` crate to give you typed, in-process access
to what the sandboxed agent did.

## Design — why it splits the way it does

AgentFS is two things:

1. **The OS sandbox** — FUSE + user/mount namespaces on Linux (NFS + `sandbox-exec`
   on macOS). It makes the current working directory a copy-on-write overlay:
   host files become read-only, every write is captured to a SQLite delta DB,
   and the rest of the filesystem is locked read-only except a small allowlist.
   This lives in the **`agentfs` CLI** (`cli/src/sandbox/linux.rs`, ~400 lines of
   unsafe libc), *not* in the published `agentfs-sdk` crate.

2. **The storage layer** — `AgentFS { kv, fs, tools }`: a POSIX-like filesystem,
   a key-value store, and a tool-call audit trail, all backed by one SQLite
   file. This **is** in the `agentfs-sdk` crate.

So this binary deliberately does **not** reimplement the sandbox. It:

- **execs `agentfs run`** for the OS sandbox (the one component that already does
  the dangerous job correctly — porting ~400 lines of unsafe, platform-specific
  `fork`/`unshare`/`mount` into your binary is the non-lazy path and a second
  macOS path on top), and
- **binds `agentfs-sdk`** for everything around it: resolving a session id to its
  persisted delta DB (`~/.agentfs/run/<sid>/delta.db`), opening it in-process, and
  surfacing a typed diff (`get_delta_paths` / `get_whiteouts` / `is_overlay_enabled`)
  and tool-call timeline (`tools.recent`).

If you want the SDK to *be* the sandbox (drop FUSE/namespaces, build an agent loop
whose tools call `agent.fs.*` / `agent.kv.*` directly), that's a different project —
see "When to grow it" below.

## Prereqs

Install the `agentfs` CLI once (the Rust binary shells out to it for the sandbox):

```bash
curl -fsSL https://github.com/tursodatabase/agentfs/releases/latest/download/agentfs-installer.sh | sh
```

Any agent CLI you wrap (`claude`/`codex`/`gemini`/`opencode`/`pi`) must already be
installed and authed on your `PATH`.

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
pit selftest                  # sanity-check argv assembly (no agentfs needed)
pit dump codex exec --json    # print the exact `agentfs run` argv (no exec)
pit sessions                  # list persisted sessions with changed/deleted counts
pit sessions --select         # show numbered sessions, choose one, print its id
pit inspect [session-id]      # open a session's delta DB; omit id to choose interactively
```

The wrapped agent runs normally and sees its own working tree; writes land in the
delta layer, not on disk. After the agent exits, `pit` opens the persisted delta DB
via the SDK and prints a compact diff:

```
agentfs: session codex-myproject — 3 changed, 1 deleted
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
| `PIT_AGENTFS`   | path to the `agentfs` binary (default: from `PATH`)            |
| `PIT_QUIET=1`   | don't print the post-run delta summary                          |

### Inspecting sessions

```bash
pit sessions                 # list ~/.agentfs/run/* with changed/deleted counts (via SDK)
pit sessions --select        # number the list, prompt for a choice, print the selected id
pit inspect [session-id]     # full diff +, deletions -, and tool-call timeline; omit id to select
```

The tool-call timeline is only populated if the agent *itself* records tool calls
through the `agentfs-sdk` (an agent you wrote). Wrapped CLIs like `claude`/`codex`
leave it empty — for those, the useful SDK surface is the delta diff (what files
the agent created/modified/deleted), which is exactly `agentfs diff` but typed and
in-process.

## Profiles

Built into `src/main.rs` (`fn profile`): `claude`, `codex`, `gemini`, `opencode`,
`pi`. Each maps to a command plus extra `--allow` host dirs (beyond AgentFS's
defaults: `~/.config`, `~/.cache`, `~/.local`, `~/.npm`, `~/.claude`, `~/.codex`,
`~/.gemini`, `~/.amp`). To add a custom agent, add a match arm. When you have more
than a couple of custom agents, bring in a TOML config (`~/.config/pit/agents.toml`)
— YAGNI until then.

## Project layout

```
pit/
  Cargo.toml            agentfs-sdk 0.6.4, tokio, anyhow
  src/main.rs           the binary: profiles, argv assembly, run/inspect/sessions/dump/selftest
  examples/mkdelta.rs   throwaway: builds a fake session delta DB via the SDK (used to test
                        inspect/sessions + the post-run summary without the real agentfs CLI)
```

## When to grow it

- **Own the tool layer** → build a tiny Rust agent loop whose tools call
  `agent.fs.*` / `agent.kv.*` / `agent.tools.*` directly. Now the SDK *is* the
  sandbox (the agent has no other FS access), no FUSE/namespaces needed. This is
  what `agentfs-sdk` is designed for and is the cleanest next step if you want
  programmatic control of the agent instead of wrapping a CLI.
- **Reimplement the OS sandbox in Rust** → only if you can't tolerate the
  `agentfs` CLI dependency. You'd port `cli/src/sandbox/linux.rs` (and the NFS
  path for macOS). ~400 lines of unsafe libc with a second platform branch.
- **TOML config + a TUI** → once there are several custom agents or you want a
  session browser over the delta DBs.

The bash `./pit` at the repo root (the original prototype) can be deleted once this
Rust binary is installed; it's kept only as a reference for the same behaviour.