# Open-source launch — the platform is the product

Status: launch scoping. Decision: the open-source product is **single-host
den** — `den serve` + CLI + SQLite registry + the `Runner`/`Store` traits.
The multi-host/SaaS layer (Postgres registry, leases, gateway, rescue) is
the paid product, built separately in its own private repo — its design
does not live in this repository.

## 1. What is public, what is not

**Public repo (new, fresh history — see §5):**

- `den serve` + `den` CLI — session/run lifecycle, headless profiles,
  seed/push/replicate (fs.db, durability)
- SQLite registry (`Store` trait + adapter) — bookkeeping, single host
- The **`Runner` trait** (§2) and the `process` backend (default)
- Docs, examples, `scripts/smoke-serve.sh`
- License: Apache-2.0 (patent grant; the permissive default for
  infrastructure other companies are expected to run)

**Stays private — our custom solution, built separately (decided):**

- Everything SaaS-shaped: the Postgres registry adapter (pg), host leases,
  `den gateway`, multi-host routing/rescue — designed in an internal doc
  that lives in the private SaaS repo, not here. The `Store` trait remains
  public as the extension point; the fleet implementation is private.
- The hardened sandbox backend (FUSE VFS + user/mount/net namespace chain,
  egress proxy policy, `--seed-git` credential scrubbing). It plugs back
  in as a Runner backend without public changes.

## 2. The one new abstraction: `Runner`

serve currently assumes the child is a sandboxed `den <profile>` chain
(sandbox.rs fork chain, FUSE mount, netns). For an OSS launch that must run
on a MacBook, in CI, and in plain Docker, isolation becomes pluggable:

```rust
pub trait Runner: Send + Sync {
    /// Spawn one headless turn (or daemon child) for a session.
    fn launch(&self, req: LaunchReq) -> Result<Child>;
    /// Files/snapshot access for /files, seed, push (local dir vs VFS).
    fn session_root(&self, sid: &str) -> PathBuf;
}
```

- `runner = "process"` (default): plain `std::process::Command` with a
  process group. Works on macOS/Linux/CI. Less isolation, same API.
- `runner = "sandbox"` (Linux): the existing namespace chain. Same trait,
  private until we decide otherwise.

Everything above the trait — registry, leases, gateway, fs.db durability,
seed/push — is runner-agnostic already, because serve is a supervisor, not
a sandbox host (platform-api.md §1). This is a small refactor with a big
consequence: **the OSS quickstart works on day one on any machine.**

## 3. Positioning

- **Name**: the OSS project keeps the `den` name if we can get it
  (crate/npm/gh org check before announcing); otherwise rename now, not
  after launch.
- **Pitch**: "self-hosted platform for durable, attachable coding-agent
  sessions" — one binary locally, a fleet with Postgres when you grow.
  dex/claude/codex profiles are the first-class agents; the agent loop
  itself is *not* the product being launched.
- **Docs order** (README): 60-second single-binary quickstart first, fleet
  demo second. Even though the fleet is the headline, nobody adopts a
  platform they can't run in a minute.

## 4. Repo layout (public)

```
den/
  crates/
    den/          CLI + serve (supervisor, Runner trait, lifecycle)
    den-gateway/  the front door (auth, lookup, proxy)
    den-registry/ Store trait, sqlite + postgres adapters
    den-core/     sessions, fs.db, seed/push/replicate (shared)
  docs/           platform-api.md, runtime-contract.md, layered-sessions.md
  examples/       docker-compose.yml (fleet demo), quickstart
  scripts/        smoke-serve.sh, smoke-fleet.sh
```

A workspace of small crates, not one bin — it's what makes "embed just the
registry" and "write your own gateway" legitimate extension points, which
is the actual open-source strategy: the Store and Runner traits are the
plugin surfaces.

## 5. Pre-launch checklist (hard requirements)

1. **Fresh history**: public repo starts from a single squashed commit —
   no archaeology of internal hostnames, tokens, or TODOs.
2. **Secret audit**: grep the public tree for real hosts, tokens, git
   URLs, account names; CI adds a secret scanner (gitleaks) so it stays
   clean.
3. **No private dependencies**: everything in the public tree builds from
   crates.io only.
4. **CI = the three gates** (fmt, clippy -D warnings, test) + both smoke
   scripts on Linux; test matrix includes a macOS job for the `process`
   runner (this is the honest test of §2).
5. **Docs pass**: quickstart tested from scratch in a clean container by
   someone who didn't write it.
6. **Security policy** (SECURITY.md) + a versioned release (v0.1.0) before
   any announcement.

## 6. The private SaaS layer

The fleet design is our private SaaS layer, built separately in its own
repo — it is not in the OSS repo and does not gate the launch. What the
OSS release takes from it is only the *shape*: the `Store` trait as a
public registry extension point (SQLite adapter public, Postgres adapter
private) and the `Runner` trait as the isolation extension point. Both are
documented as "bring your own backend" surfaces; our hosted deployment is
the reference consumer of the private extensions.
