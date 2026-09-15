# den OSS Charter (draft — uncommitted)

Status: draft for review. Decides nothing until merged.
Companion to `docs/oss-launch.md` (launch scoping) and `SECURITY.md`
(security boundary). When this charter conflicts with older docs,
this charter wins once approved.

## 1. Mission

`den` OSS is single-host **durable, attachable coding-agent sessions**:
`den serve` + CLI + SQLite registry + `Runner`/`Store` traits.
One binary, 60-second quickstart, same API as the fleet.

The multi-host/SaaS layer (Postgres registry, leases, gateway, rescue)
is a separate private product. It does not live here and does not gate
the OSS release.

## 2. Public / private boundary

Public (this repo, fresh history — see §6):

- `den serve` + `den` CLI — session/run lifecycle, seed/push/replicate
- SQLite registry (`Store` trait + adapter), `Runner` trait + `process` backend
- Docs, examples, `scripts/smoke-serve.sh`

Private (separate repo, never in this tree):

- Postgres adapter, host leases, `den gateway`, multi-host routing/rescue
- Hardened sandbox backend (FUSE VFS + namespace chain, egress proxy
  policy, `--seed-git` credential scrubbing) until explicitly relicensed

The `Store` and `Runner` traits are the plugin surfaces. Private
backends plug back in without public changes.

## 3. License

- Code: **MIT OR Apache-2.0** (dual, matching sibling `dex`; Rust
  convention, crates.io compatible, patent grant via Apache leg).
- Files: `LICENSE` (MIT) + `LICENSE-APACHE`, `Cargo.toml` gains
  `license = "MIT OR Apache-2.0"`, `repository`, `readme`, `authors`.
- `README.md` gains a `## License` footer linking both;
  `CONTRIBUTING.md` notes contributions under the same dual terms.
- No private deps (crates.io only).

## 4. Security principles (non-negotiable)

From `SECURITY.md` + `AGENTS.md` conventions:

- `den serve` refuses to listen without `DEN_API_TOKEN`.
- Bearer auth on every route; foreign-owned sessions return 404, never 403.
- `dk_…` keys stored as SHA-256 hashes only; raw key shown once.
- Constant-time token compare.
- Secrets are host-side only: `--seed-git` clones in den, then scrubs;
  temp clones under `/tmp` removed in `prepare_base`. Never seed host
  git credentials into a sandbox.
- `den serve` runs agent CLIs as the invoking user by design — a
  malicious agent with your uid is out of scope. Tokens go only to
  trusted principals.

## 5. Quality gates

Every PR, enforced by `ci.yml`:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test` (unit only, repo root)
4. `scripts/smoke-serve.sh` → `SMOKE-OK` for serve/registry/auth/seed paths

Plus: macOS job for the `process` runner (the honest test that OSS
works off-Linux).

## 6. OSS hygiene before public

1. Fresh history: public repo starts from one squashed commit.
2. Secret audit: grep for hosts/tokens/URLs/account names; `gitleaks`
   in CI (already present — keep it); add `cargo audit` job (dex has it).
3. Missing files: `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`,
   `ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md`,
   `release.yml` (tag==version check, checksums) — copy from dex, adapt.
4. `.gitignore`: add `.worktrees/` at minimum; resolve untracked `bin/`.
5. Docs pass: quickstart tested from scratch in a clean container by a
   non-author.

## 7. Governance (minimal)

- Maintainer: Arpit Kumar. `develop` is default; PRs target `develop`.
- Semver, tagged releases; latest tag + `develop` HEAD get security fixes.
- Contributions dual-licensed MIT + Apache-2.0 (no CLA). Security reports private only.

## 8. Release plan (this charter)

1. Review this charter (this file) — amend, then approve in PR.
2. Land metadata: `Cargo.toml` license fields, `README` footer,
   COC/CONTRIBUTING/templates/`release.yml`, `.gitignore` fix.
3. Secret audit + `cargo audit` CI + clean-container quickstart test.
4. Squash-export to fresh public repo, tag `v0.1.0`, verify CI green.
5. Announce only after `SECURITY.md` + versioned release exist.
