# Layered sessions: shared base + per-session delta

Status: **built** (v1) — `src/layer.rs` (LayeredFS), base creation in
`src/main.rs`, delta/diff/inspect/push switched over, nesting (§7 steps 1–4),
selftest block, kill switch. Everything below stands as designed except the
build findings:

- **R1 resolved — no SDK read-only mode exists**, and a chmod-0444 base.db
  cannot be opened at all (turso needs O_RDWR for WAL). Bases stay **0644**;
  immutability is "only the seeding write ever opens it", not a chmod.
- **Tombstones live in the delta's `fs_whiteout` table** (the SDK's own
  whiteout schema, created by LayeredFS at mount), **not** a separate
  `meta.db`: the mount is fs.db's only writer (turso), so a rusqlite sidecar
  would be a second rw opener; and storing them in fs.db makes
  `den backup`/`den pull`/litestream carry deletions for free (verified:
  restore preserves `fs_whiteout`). No `meta.db` on disk.
- **The base key cannot come from the seed walk** (§3.2): the key is needed
  *before* deciding to create vs reuse the base, and the seed walk only runs
  on a miss. The digest is a separate host walk (`worktree_digest`: rel path,
  size, mtime ns, kind per entry; SEED_EXCLUDES at every level, top `.git`
  skipped — history is pinned by head_sha). Once per base, not per session.
- **No content re-verification on base hits** (§3.2 TODO): any worktree
  touch changes mtime → fresh key → fresh base, so a stale-identity hit
  would require a content-equal-but-mtime-identical tree; re-verifying on
  every start would cost the O(repo) walk the design removes.
- **The merged node keeps BOTH layer inos** (`base_ino` + `delta_ino`) plus
  a `(parent, name) → merged ino` reverse index. A shadowed dir retains its
  `base_ino` so base children keep merging; a recreation over a tombstone
  clears `base_ino` so the new entry never leaks the deleted base subtree.
  Copy-up of the PARENT dir (shadow) is what creation under a base-resident
  parent needs — `mkdir`/`create_file`/`mknod`/`symlink` on an existing
  path are EEXIST (POSIX), shadowing only happens via copy-up.
- **No-op setattr does not copy-up** (the kernel re-flushes cached attrs on
  inode eviction/unlink with unchanged values — a plain `rm` would
  otherwise materialize every file it deletes). chmod/chown/utimens compare
  against the current attrs and skip when nothing changes; a real change
  invalidates the parent's cached listing (its embedded attrs went stale).
- **Bookkeeping reviewed for the recreated-path race**: `drop_child` removes
  a `(parent, name)` reverse-index entry only when it still points at the
  node being retired, so a delete+recreate before the old node's `forget`
  can't orphan the new node's index. `unlink(dir)` is EISDIR, `rename` moves
  descendant tombstones to the new prefix (a renamed dir must not resurrect
  base children it had hidden), and `forget` invalidates the parent listing
  (a retired ino must not survive in cached readdir output).
- **`den rename` of a base-resident dir** renames the shadow and leaves the
  base subtree shared (per-entry copy-up); the old path gets a tombstone,
  and a dir renamed back onto its old name clears that tombstone (the base
  content is visible there again).

Author notes for the implementer were marked **TODO(build)**; all are
resolved here or in code comments.

---

## TL;DR

Today every den session owns a SQLite DB that *is* its whole filesystem
(`~/.den/sessions/<sid>/fs.db`), seeded by copying the target tree in. For N
subagents on one big repo that is N copies of the repo and N full-seed costs,
and every file read pays FUSE + SQLite even for files the agent never touches.

Change to two layers:

- **base**: one read-only seeded DB per repo state, shared by all sessions
  seeded from that state (`~/.den/bases/<key>/base.db`).
- **delta**: the session's own tiny DB, same filename `fs.db` as today,
  containing only entries the session created, modified, or deleted.

A new merge layer (`src/layer.rs`, implements the same `FileSystem` trait the
SDK defines) mounts base+delta as one tree. Writes copy the entry up into the
delta ("copy-up"), deletes leave tombstones. Seeding happens once per base;
sessions are O(their changes).

Everything else — userns chain, seccomp, nft egress, proxy, hides, RO sweep —
is unchanged. This doc does not touch `sandbox.rs` security logic beyond the
object it receives.

---

## 1. Background: the current storage model

Facts, with anchors:

- `src/sandbox.rs:280` — the mount serves the session's `fs.db`; no host base,
  no overlay. Comment: "no copy-on-write overlay" — the previous agentfs
  architecture *was* an overlay and was removed.
- `src/main.rs` `seed_session`/`seed_tree` — walks the seed dir and copies
  every entry into the virtual FS through the agentfs SDK (mkdir / create_file
  / pwrite / symlink). Excludes `node_modules`, `target` (`SEED_EXCLUDES`),
  keeps `.git` for repo seeds, scrubs credential-bearing git config.
- `src/mount.rs` — `FileSystem` trait (async, ino-based: `lookup(parent,
  name)`, `getattr(ino)`, `readdir(ino)`, `readdir_plus(ino)`, `open(ino,
  flags)`, `mkdir(parent, name, ...)`, `create_file(parent, name, ...)`,
  `link`, `forget`, `statfs`, …). `fuse.rs` bridges `fuser` to this trait and
  passes SDK inos straight through (it does **not** keep its own ino map —
  `getattr(_req, ino)` → `fs.getattr(ino)`).
- Cost model today, per session: full tree import at seed; every read crosses
  FUSE → tokio → SQLite for the entire tree for the life of the mount; the
  pre/post `snapshot_fs` diff walks the whole tree twice per run.

## 2. Why change it

1. **Seed is O(repo), paid per session.** 5 subagents × 1 GB repo = 5 imports,
   5 full DB copies under `~/.den/sessions`.
2. **The read path is the slow path.** Builds read 10⁵+ files; each is a FUSE
   round trip into SQLite. The 99% of files nobody modifies pay the tax.
3. **No cross-session dedupe.** Two sessions that `npm install` store two
   copies of identical content.
4. **Join cost grows with repo size.** Each joining `M` opens the full fs.db
   rw; busy/lock contention scales with DB size.
5. **No nestable sessions.** "Agent launches subagent" fails today: the inner
   den can't write `~/.den/sessions/...` (not on the writable allowlist) and
   the design assumes one sandbox per host invocation (§7).

## 3. Design

### 3.1 Layers and invariants

Two layers only. No arbitrary stacks (YAGNI).

```
merged view (what FUSE serves)
   delta  : ~/.den/sessions/<sid>/fs.db   — per session, read-write, sparse
   base   : ~/.den/bases/<key>/base.db    — read-only, shared, seeded once
```

Invariants:

- **I1** The base DB never changes after creation (0644 — R1 resolved: no
  SDK read-only mode, and 0444 breaks WAL; only the seeding write opens it).
- **I2** The delta DB is the only writable filesystem storage of the session.
  It starts empty.
- **I3** A session pins exactly one base, recorded in its session dir
  (`base` file). Base is immutable for the session's life; staleness is a
  warning, not a re-seed (`den push` already warns on `seed.sha` drift —
  keep that behavior, now reading the same value from the base key).
- **I4** Security posture is unchanged: the FUSE daemon (M-side) is the only
  writer; the sandbox still cannot reach `~/.den`; the RO sweep / hides /
  allowlist run exactly as today.

### 3.2 On-disk layout

```
~/.den/bases/<key>/base.db        # seeded once per <key>, shared, chmod 0444
~/.den/bases/<key>/key.json       # {kind: git|dir, toplevel, head_sha, digest, created, refs}
~/.den/sessions/<sid>/
    fs.db                         # delta (SAME name as today — see §5);
                                  #   tombstones live in its fs_whiteout table
    base                          # absolute path to the pinned base.db
    seed.sha                      # as today (echoed from the base key)
    base_path                     # recorded cwd (push target), unchanged
    seed.snapshot                 # legacy sessions only (pre-layer)
    mnt/                          # mount point, unchanged
~/.den/sessions/.stamps/<sid>     # drop_stale_session stamp + base key, unchanged
```

`<key>` content-identity, computed during the existing seed walk
(`seed_tree` already visits every entry — hashing `name|size|mtime_nanos` per
entry is nearly free):

- git repo seed: `git-<slug(toplevel)>-<head_sha>-<worktree_digest>`
  where the worktree digest covers non-`.git` files only.
- plain dir seed: `dir-<slug(path)>-<digest>`.
- Keys are restricted to `[a-z0-9-]` and stay well under 120 chars
  (`key_slug` truncates the path part at 48). Built as designed, minus the
  content re-verification (see build report): identical sources reuse the
  base on the strength of the digest alone.

### 3.3 `src/layer.rs` — the merge layer

One new file, ~700–900 lines. A struct implementing the same
`agentfs_sdk::filesystem::FileSystem` trait `mount_fs` already consumes, so
`fuse.rs` and `sandbox.rs` don't change shape:

```rust
pub struct LayeredFS {
    base:  Option<AgentFS>,            // None => legacy single-DB mode (§6)
    delta: AgentFS,
    meta:  MetaSidecar,                // tombstones, §3.5
    inos:  Mutex<HashMap<i64, Node>>,  // merged ino -> layer entry
    next_ino: AtomicI64,               // starts at 2; ino 1 = root (merged)
}
struct Node { layer: Layer, ino: i64, parent: i64, name: String } // parent+name ⇒ path
enum Layer { Base, Delta }
```

**Inode table and the stability rule (the subtle part).** Merged inos are
allocated on first lookup and cached for the mount's lifetime. The merged ino
is *sticky across copy-up*: a node starts `Layer::Base`; when it is copied up,
flip the node's `layer`/`ino` fields to the delta entry **but keep the merged
ino**. The kernel never sees a changed inode number. Never delete entries from
the map before `forget` (bounded by entries the run actually touched; for
readdir of big dirs, see risk R2).

Operations:

| Op | Merged behavior |
|---|---|
| `lookup(parent, name)` | tombstoned? → `ENOENT`. `delta.lookup` hit → allocate/return (Layer::Delta). else `base.lookup` hit → allocate (Layer::Base). else `ENOENT`. |
| `getattr/readlink/open(O_RDONLY)` | delegate to the node's layer. No copy-up. |
| `open(O_WRONLY\|O_RDWR\|O_TRUNC)` | copy-up (§3.4) first, flip node to Delta, delegate. |
| `chmod/chown/utimens` | copy-up target (dirs too), then apply in delta. |
| `create_file/mkdir/symlink` in a base-resident parent | **do not copy the parent's subtree**. Create a shadow dir/entry in delta: for dirs, copy base dir's mode/uid/gid/times into the delta entry (entry-level copy-up, not subtree). Child reads still merge from base (§3.4). |
| `readdir/readdir_plus(dir)` | union: delta children (win) ∪ base children; drop tombstoned names; allocate merged inos for new names; stable sorted order (see R4). |
| `unlink` | tombstone the path; delete in delta if present; merged ino retired at `forget`. |
| `rmdir` | merged children must be empty (else `ENOTEMPTY`). Tombstone the dir path. |
| `rename` | copy-up source (with content), delta `rename`, tombstone the old path if source was base-resident, tombstone the target if it existed in base. |
| `link` | copy-up source first (hardlinks live only within the delta thereafter), then delta `link`. |
| `read/write` on an open handle | handle belongs to one layer; delegate. Copy-up happens at `open`, not at `write`. |
| `forget` | retire the map entry when the kernel's forget count reaches zero (mirror SDK behavior). |
| `statfs` | report delta's numbers (its footprint is what fills up). |

**Built + verified**: `fuse.rs` re-derives the full listing per call and
indexes by position (`skip(offset)`), and `readdirplus` replies use
`entry.stats.ino` — so the merged layer returns a stable sorted listing with
merged inos in `DirEntry.stats.ino`, cached per dir ino and invalidated on
delta mutation of that dir (R4).

### 3.4 Copy-up

`copy_up(node)`:

1. If `node.layer == Delta`, nothing to do.
2. Resolve the full path by walking `parent`/`name` to the root.
3. Recreate the entry in delta with base's attrs (dir: shadow dir with copied
   mode/uid/gid/times; file: `create_file` + read base content + `pwrite`;
   symlink: `symlink(target)`), preserving mode.
4. Flip the node to `{layer: Delta, ino: <delta ino>}`, keep merged ino.

Copy-up is per *entry*; the base subtree is never bulk-copied. A session that
`touch`es one file in a 100k-file tree stores one file.

### 3.5 Tombstones

Tombstones live in the **delta's own `fs_whiteout` table** (SDK schema;
LayeredFS creates it if missing at mount time) — absolute VFS paths with a
leading slash (`/src/lib.rs`). Build report: this replaces the planned
`meta.db` sidecar — the mount already owns fs.db via turso, and in-delta
tombstones ship with `den backup`/`den pull`/litestream for free.

- Tombstone semantics: exact path only, no prefix tombstones in v1.
  `lookup` consults tombstones (deleted ⇒ `ENOENT`); `readdir` filters
  tombstoned child names; **and** a tombstoned ancestor hides descendants
  (a tombstoned dir's children never surface — enforce with the
  ancestor-check, see R5).
- `rmdir` after tombstoning the dir: one row covers the whole subtree.
- Deleting an entry that already lives in delta: delete from delta *and*
  tombstone (the base copy must stay hidden).
- Built as pure functions with unit tests: `tombstone_hidden` (exact +
  ancestor check), `filter_base_children` (readdir filter), shared by the
  layer and the merged-view walk.

### 3.6 Base creation and lifecycle

Reuse the existing seed machinery verbatim:

1. `resolve_seed_source` / `git_seed_ctx` / `extract_head_archive` — unchanged.
2. Compute the key from the resolved source (§3.2).
3. Base exists → open read-only. Else: create
   `~/.den/bases/<key>/base.db` via `AgentFSOptions::with_path`, run
   `seed_session` + `scrub_git_config` (the credential scrub now runs once
   per base instead of per session — strictly better), chmod 0444, write
   `key.json`.
4. Session records `bases/<key>/base.db` + `seed.sha`; delta starts empty.

GC: none in v1. `key.json` has `refs: n`, incremented on pin, decremented on
`den rm` of a session and by the `drop_stale_session` archive path; bases
with `refs = 0` older than N days are removable by hand (`den bases --prune`
is a stretch goal, not v1).

### 3.7 Feature mapping (what each existing command now means)

- **seed**: creates/opens the base; session delta empty.
- **join/resume** (`DEN_SESSION`): open pinned base RO + delta rw. Same
  stamp/drop_stale_session logic; add the base key to the stamp so a config
  change that changes the base archives the session (one line: stamp =
  `cwd\nallows\nbase_key`).
- **touched-this-run diff**: pre-run snapshot = dump delta + tombstones
  (small); post-run same; diff. Deletes `snapshot_fs`'s whole-tree walks.
  The delta *is* the change set — this gets strictly simpler.
- **inspect**: merged view = base ∪ delta − tombstones (walk via LayeredFS
  without FUSE, same shape as today's snapshot).
- **push** (`push.rs`): changed = delta file entries; deleted = tombstones;
  contents read from delta (merged reads via LayeredFS). Baseline-drift
  warning: base `head_sha` vs host HEAD — same logic, new source. The
  seeded `/.git` lives in the base, so worktree materialization keeps
  working unchanged.
- **backup / replicate / pull / ltx**: unchanged — they target
  `sessions/<sid>/fs.db`, still a plain SQLite DB (the delta). Base DBs are
  content-addressed and immutable; back one up at base creation (stretch:
  `den backup --base`).
- **`DEN_NEW=1` + same seed ⇒ same base, empty delta.** This is the
  subagent case working.

### 3.8 Performance expectations (acceptance numbers)

On a ~100k-file / ~1 GB repo:

- Seed: once per base. Session start on a base hit ≈ open 2 SQLite files +
  mount (< 0.5 s) vs today's full walk+import.
- Read path: unchanged mechanism (still FUSE→SQLite) — this design removes
  the *storage* cost, not FUSE syscall overhead (R6 lists the faster read
  path as a follow-up).
- Delta size: O(agent's writes) — typically < 1% of the base.

## 4. What does not change

Everything in `sandbox.rs` that is security: the M→P→N→U→A chain, nft egress
policy, `policy.rs` live reload, proxy, seccomp deny-list, rlimits, hides,
RO sweep, allowlists, `/proc` masking. `sandbox.rs` changes are limited to
receiving a `LayeredFS` instead of an SDK-served mount at the `mount_fs` call
site. `proxy.rs` / `policy.rs` untouched.

## 5. Why the delta keeps the name `fs.db`

`backup.rs`, `push.rs`, litestream paths, `session_db_path()` all target
`fs.db`. Keeping the delta at that exact path means the whole
backup/replicate/restore surface is untouched and old muscle memory works.
The only new artifact next to it is the `base` pointer (tombstones live inside fs.db itself).

## 6. Compatibility

- Legacy sessions (pre-layer: `fs.db` holds everything, no `base` file):
  `LayeredFS` with `base: None` and no tombstones is a passthrough to the
  delta — exactly today's behavior. No migration.
- Kill switch: `DEN_LAYER=0` forces today's per-session seed path. Keep it
  one release as an escape hatch, then delete.
- `den sessions` / `inspect` / `rm` need no schema changes.

## 7. Nesting: agent spawns a subagent inside a sandbox

**Built** (steps 1–4): the sandbox already exports `AGENTFS=1` +
`AGENTFS_SESSION=<sid>`; den detects that, keeps all session state under
`<cwd>/.den` inside the outer VFS (`sessions_root`/`bases_root` are
nested-aware), inherits the outer session's pinned base via `DEN_BASE_DB`
(exported by the sandbox), defaults to `DEN_NET=none` inside, and gives each
nested run a unique session id. `/dev/fuse` is bound into the sandbox so the
inner den can mount. Steps 5 (nested-aware inspect/push) remain v2 — the
paths already resolve (session root is `<cwd>/.den`), so `den inspect` from
inside works against nested sessions.

The inner den runs with `AGENTFS=1` + `AGENTFS_SESSION=<sid>` in its env.
Behavior (v1, small):

1. Detect `AGENTFS=1` at startup. The inner den does **not** create
   `~/.den/sessions/...` (unreachable anyway — not on the allowlist).
2. The inner session's delta lives *inside the outer session's VFS*:
   `/.den/<inner-sid>/fs.db` (+ its tombstones inside that DB) — the outer
   VFS is writable by construction. Base: inherited from the outer session
   via `DEN_BASE_DB` (exported by the sandbox) — the subagent works on the
   same tree by definition.
3. `DEN_SESSION` semantics: explicitly exported `DEN_SESSION` → inner run
   joins that outer session (appends to its delta). No `DEN_SESSION` →
   create the nested session under `/.den/` so the parent can diff the
   subagent's work separately by reading `/.den/<inner-sid>/fs.db`.
4. Network for subagents: default `DEN_NET=none` when `AGENTFS=1` is
   detected unless explicitly overridden — most subagents need no egress,
   and `none` skips slirp + proxy entirely (already supported).
5. `den inspect`/`push` understanding `/.den/...` nested sessions: v2; v1
   documents the path convention.

## 8. Out of scope (recorded, not built)

- **Shared proxy / `den serve` daemon** (one proxy + mount broker, thin
  client runs): only worth it for large fleets; the per-session proxy cost
  is seconds. Revisit when there's a fleet benchmark.
- **overlayfs scratch mode** (no DB at all, per-session upperdir as the
  diff): the fallback if base/delta doesn't move the needle. Decide by
  measuring §3.8, not by building both.
- Content-addressed blob store inside the delta (cross-session dedupe of
  identical *written* content, e.g. two sessions' node_modules). Bases give
  the big win; this is a marginal add.
- Faster base reads via a RO bind mount of the host tree under the FUSE
  mount (kills the SQLite read path for unmodified files) — bigger change to
  `fuse.rs`, defer.

## 9. Test plan

Unit (in `layer.rs`, no FUSE — drive the trait directly with two `AgentFS`
DBs):

1. lookup resolution order (delta wins, base fallback, tombstone → ENOENT).
2. readdir union + dedupe + tombstone filter + stable ordering.
3. copy-up file: content/mode/times equal to base; merged ino unchanged
   after copy-up (the §3.3 stability rule).
4. dir shadow: after shadowing a base-resident parent, its base children
   still appear in the merged listing.
5. rename/unlink/rmdir tombstone bookkeeping; `ENOTEMPTY` from merged view.
6. legacy mode (`base: None`) passthrough.

Selftest (`cmd_selftest` extension — mirror the existing sandbox block):
seed a dir with a few files → `sh -c "echo hi >> /README.md; touch
/new.txt; rm /a.txt"` → assert base untouched (hash), delta holds exactly
{README.md, new.txt} + tombstone {a.txt}, merged inspect shows all three
effects, a second `run_cmd` joins (delta survives), `/etc` write still
EROFS. Seed twice with the identical source and assert the second session
reused the same base (no second `base.db`).

Manual perf harness: run against a big repo (e.g. rustc or linux tree):
record seed wall-clock and delta.db size, before/after.

## 10. Implementation order

| Step | File(s) | Rough size |
|---|---|---|
| 1. tombstone store (delta's `fs_whiteout`) + unit tests | `src/layer.rs` (new) | ~150 |
| 2. `LayeredFS` core: ino table, lookup, getattr, readdir(+), copy-up, create/mkdir/symlink | `src/layer.rs` | ~400 |
| 3. delete/rename/link/forget/statfs | `src/layer.rs` | ~150 |
| 4. base creation + key computation (reuses seed path) | `src/main.rs` | ~150 |
| 5. wire into run: session layout, stamps, `DEN_LAYER` kill switch, legacy passthrough | `src/main.rs`, `src/sandbox.rs` (call site only) | ~100 |
| 6. diff/inspect/push switched to delta + tombstones | `src/main.rs`, `src/push.rs` | ~100 |
| 7. nesting detect (§7 steps 1–4) | `src/main.rs` | ~80 |
| 8. selftest + perf harness | `src/main.rs` | ~120 |

All eight steps are built (step 8's perf harness is the manual measurement
from §3.8 — run `den` against a big tree and record seed wall-clock and
delta.db size before/after; nothing to code). Steps 1–3 ship with unit tests
(`cargo test layer::`); step 5+ is exercised end-to-end by
`den selftest --sandbox`, which now runs the legacy sandbox block followed by
the layered block (base untouched by hash, delta contents, tombstone,
merged view, join, base reuse, `DEN_LAYER=0`).

## 11. Risks / open questions

- **R1 SDK read-only open — RESOLVED: no.** `AgentFSOptions` has no RO mode
  and a 0444 file cannot be opened at all (WAL needs O_RDWR). Bases are
  0644, opened rw-but-never-written; the "guard" is that only the seeding
  write touches a base.
- **R2 Inode table memory**: readdir of a 100k-entry dir allocates 100k map
  nodes (~tens of MB, transient). Acceptable for v1; revisit with a compact
  table only if measured.
- **R3 SDK schema tolerance — MOOT**: the only addition to fs.db is the
  SDK's own `fs_whiteout` table (created by LayeredFS; schema detection
  introspects `fs_inode` only). Verified by backup/restore round-trips.
- **R4 `readdir_plus` merge cost** — RESOLVED: the merged listing is cached
  per dir ino and invalidated (marked dirty) on delta mutations of that
  dir, so repeated `ls` of a hot dir pay one union, not one per call.
- **R5 Tombstone-heavy sessions**: deleting a big seeded subtree is one
  tombstone row, but merge must then hide the whole subtree — enforce via
  ancestor tombstone checks during lookup/readdir, not by materializing.
- **R6 FUSE read overhead stays**: layering fixes storage, not syscall
  overhead. If a build still reads 10⁵ files per run, the RO-bind fast path
  (§8, last bullet) is the next lever.
- **R7 Two processes joining one session**: delta is rw shared SQLite —
  same contention profile as today's full DB, strictly smaller. Confirm no
  join-path regressions.
