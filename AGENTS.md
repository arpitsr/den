# AGENTS.md — den

Agent instructions for the den repo (sandboxed coding-agent runtime).

## Repo layout

- Main checkout: `~/Work/den` (branch `develop`)
- Feature worktrees live **outside** the repo, at `~/Work/den-<branch>` —
  never inside `~/Work/den/.worktrees/` (keeps the main checkout's worktree
  scan and den's own `worktree_digest` clean). Create with:
  `git worktree add ~/Work/den-<branch> -b <branch>`
- Docs: `docs/layered-sessions.md` (runtime internals),
  `docs/platform-api.md` (serve architecture), `docs/platform-build-plan.md`
  (sequenced plan + verification gates).

## Build & test gates

CI (`ci.yml`) runs `cargo fmt --check`, `cargo clippy --all-targets
-- -D warnings`, and `cargo test`. All three must pass before pushing.
Tests are unit tests only (`cargo test` in the repo root).

## Conventions

- Rust, edition 2021, sync rusqlite behind small public APIs; async code is
  tokio (`rt-multi-thread`, `macros`, `net`, `time`, `sync`, `process`).
- Registry schemas get a `schema_version` and forward-compatible columns.
- HTTP surface (serve.rs): bearer auth on every route (root token +
  scoped `dk_…` keys), ownership checks return 404 for foreign sessions,
  constant-time token compare, refuse to listen without auth configured.
- Secrets: host-side only — never seed host git credentials into a sandbox
  (`--seed-git` clones in den, then scrubs; temp clones under /tmp must be
  removed in `prepare_base`).

## Verification before opening a PR

1. `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
2. `scripts/smoke-serve.sh` (expect SMOKE-OK) for anything touching serve,
   registry, auth, or seed paths.
3. Push branch from the worktree; PR against `develop`.
