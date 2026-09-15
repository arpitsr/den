# Contributing to den

Thanks for helping improve `den` — bug reports, docs fixes, and small focused
code changes are all welcome. This file has the fast facts;
[`AGENTS.md`](AGENTS.md) documents the architecture and working conventions.

There is no formal roadmap; the issue list is the backlog. If you have a
larger change in mind, please open a feature request first so we can agree on
scope before you write code.

## Build and check

```sh
cargo fmt -- --check                          # must pass
cargo clippy --all-targets -- -D warnings     # must pass
cargo test                                    # must pass (unit tests only, repo root)
scripts/smoke-serve.sh                        # must print SMOKE-OK (serve/registry/auth/seed paths)
```

Requires a stable Rust toolchain (edition 2021). Feature work happens in
worktrees outside the repo (`git worktree add ~/Work/den-<branch> -b <branch>`),
never inside `.worktrees/`.

## Pull requests

- Target `develop`.
- Keep diffs minimal; reuse existing helpers; no scaffolding "for later".
- CI runs `fmt`, `clippy -D warnings`, `test`, a macOS `process`-runner job,
  `gitleaks`, and `cargo audit`.
- Conventional-commit subjects (`fix:`, `feat:`, `chore:`, ...) preferred.
- New dependencies need a clear reason — prefer stdlib.

## Code conventions

- Rust, edition 2021, sync rusqlite behind small public APIs; async is tokio
  (`rt-multi-thread`, `macros`, `net`, `time`, `sync`, `process`).
- Registry schemas get a `schema_version` and forward-compatible columns.
- HTTP surface (`src/serve.rs`): bearer auth on every route (root token +
  scoped `dk_…` keys), ownership checks return 404 for foreign sessions,
  constant-time token compare, refuse to listen without auth configured.
- Secrets: host-side only — never seed host git credentials into a sandbox.

## Reporting bugs / features / security

- Bugs / features: open a GitHub issue with the template.
- Security: see [SECURITY.md](SECURITY.md) — private vulnerability reporting only.

## License

By contributing, you agree that your contributions are dual-licensed under
the MIT and Apache-2.0 licenses, the same as the project (see
[LICENSE](LICENSE) and [LICENSE-APACHE](LICENSE-APACHE)).
