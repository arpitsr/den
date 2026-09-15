//! Layered sessions: one shared read-only base DB + the session's writable
//! delta DB, merged into a single tree (docs/layered-sessions.md §3.3–3.5).
//!
//! The delta keeps today's layout (`sessions/<sid>/fs.db`), starts EMPTY and
//! holds only what the session created, modified (copy-up) or deleted
//! (tombstone). The base is seeded once per repo state and shared; a session
//! is O(its changes).
//!
//! Build-time deviations from the doc, resolved:
//! - **Tombstones live in the delta's `fs_whiteout` table** (the SDK's own
//!   whiteout schema), not a separate `meta.db`: the FUSE daemon is the only
//!   writer of fs.db via turso, so a rusqlite sidecar would be a second rw
//!   opener of the same file; storing tombstones in fs.db makes `den backup`
//!   / `den pull` / litestream carry deletions for free (R3 moot — no new
//!   tables outside fs.db).
//! - **Base DBs stay 0644, not 0444** (R1 resolved): `AgentFSOptions` has no
//!   read-only mode and turso needs O_RDWR (WAL). Immutability is discipline
//!   (only the seeding write ever opens a base), not a chmod.
//! - **No content re-verification on base hits** (§3.2 TODO relaxed): the
//!   digest covers name|size|mtime_ns per entry, so any worktree touch
//!   yields a fresh key rather than a false hit; re-verifying content on
//!   every session start would cost the O(repo) walk we're removing.
//! - **SDK `OverlayFS` not reused**: it keeps whiteouts in memory only, so a
//!   resumed session would resurrect deleted files. `LayeredFS` replaces it
//!   with persisted tombstones + the same sticky-inode rule.
//!
//! The merged inode table (§3.3, the subtle part): merged inos are allocated
//! on first lookup and survive copy-up — the node flips its layer inos but
//! keeps the merged ino, so the kernel never sees a changed inode number.
//! `base_ino` is retained on shadowed dirs so their base children keep
//! merging; recreating over a tombstone clears it, so a fresh dir never
//! leaks the deleted base subtree.
//!
//! Tombstone semantics (v1, §3.5): exact paths only. A tombstoned path hides
//! the BASE copy (and, via the ancestor check, its whole base subtree); the
//! delta namespace always wins, so a delete-then-recreate is just the new
//! entry. `rmdir` leaves one row covering the (then-empty) subtree.

use agentfs_sdk::error::Result as SdkResult;
use agentfs_sdk::filesystem::FileSystem;
use agentfs_sdk::filesystem::{
    self, BoxedFile, DirEntry, FilesystemStats, FsError, Stats, TimeChange, S_IFDIR, S_IFLNK,
    S_IFMT,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

const ROOT_INO: i64 = 1;

/// layer debugging (DEN_LAYER_DEBUG=1): name + ino of each interesting op.
fn layer_dbg(op: &str, ino: i64) {
    if std::env::var("DEN_LAYER_DEBUG").as_deref() == Ok("1") {
        eprintln!("layer: {op} ino {ino}");
    }
}
/// Copy-up read/write chunk: 1 MiB.
const COPY_CHUNK: u64 = 1 << 20;

// ── pure path/tombstone helpers (unit-tested, no FS) ────────────────────────

/// VFS path of a child entry: parent "/" (or "") + name.
pub(crate) fn child_path(parent: &str, name: &str) -> String {
    let parent = parent.trim_end_matches('/');
    if parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// True when a base-resident path is hidden by a tombstone: the path itself
/// or any ancestor is exactly tombstoned. Only ever applied to BASE results
/// — delta entries always win, recreations included.
pub(crate) fn tombstone_hidden(path: &str, tombstones: &HashSet<String>) -> bool {
    let mut rest = path;
    loop {
        if tombstones.contains(rest) {
            return true;
        }
        match rest.rfind('/') {
            Some(0) => return tombstones.contains("/"),
            Some(i) => rest = &rest[..i],
            None => return false,
        }
    }
}

/// Names of a base directory listing that survive tombstone filtering.
pub(crate) fn filter_base_children<'a>(
    parent_path: &str,
    names: impl IntoIterator<Item = &'a String>,
    tombstones: &HashSet<String>,
) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| !tombstone_hidden(&child_path(parent_path, n), tombstones))
        .cloned()
        .collect()
}

// ── base identity: digest, key, key.json (§3.2, §3.6) ───────────────────────

/// Content identity of a host tree: one line per entry (relative path, size,
/// mtime ns, kind), sorted, folded into 64-bit FNV-1a. Mirrors what seeding
/// copies (SEED_EXCLUDES at every level, top-level `.git` skipped — for git
/// seeds history is pinned by head_sha instead). Any touch changes mtime →
/// new key → fresh base; identical sources collide on the same key.
pub(crate) fn worktree_digest(dir: &Path) -> Result<String> {
    const EXCLUDES: &[&str] = &[".git", "node_modules", "target"];
    let mut lines: Vec<String> = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((host, rel)) = stack.pop() {
        let Ok(md) = std::fs::symlink_metadata(&host) else {
            continue;
        };
        if !rel.is_empty() {
            let kind = if md.is_dir() {
                "d"
            } else if md.file_type().is_symlink() {
                "l"
            } else {
                "f"
            };
            let mtime_ns = if md.mtime() < 0 {
                0
            } else {
                md.mtime() as u64 * 1_000_000_000 + md.mtime_nsec() as u64
            };
            lines.push(format!("{rel}\u{0}{}\u{0}{mtime_ns}\u{0}{kind}", md.len()));
        }
        if !md.is_dir() {
            continue;
        }
        for entry in
            std::fs::read_dir(&host).with_context(|| format!("digest: {}", host.display()))?
        {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if EXCLUDES.contains(&name.as_str()) {
                continue;
            }
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            stack.push((entry.path(), child_rel));
        }
    }
    lines.sort();
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    };
    feed(&(lines.len() as u64).to_le_bytes());
    for l in &lines {
        feed(l.as_bytes());
        feed(&[0u8]);
    }
    Ok(format!("{hash:016x}"))
}

/// Key slug: lowercase [a-z0-9-], truncated.
fn key_slug(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= max {
            break;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "x".into()
    } else {
        out
    }
}

/// Content-identity base key (§3.2): `git-<toplevel>-<head>-<digest>` or
/// `dir-<path>-<digest>`; [a-z0-9-] only, well under the 120-char cap.
pub(crate) fn base_key(git: bool, toplevel: &Path, head_sha: Option<&str>, digest: &str) -> String {
    let head = head_sha
        .map(|h| {
            let h: String = h
                .chars()
                .take(12)
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            if h.is_empty() {
                "nohead".into()
            } else {
                h
            }
        })
        .unwrap_or_else(|| "nohead".into());
    format!(
        "{}-{}-{}-{}",
        if git { "git" } else { "dir" },
        key_slug(&toplevel.display().to_string(), 48),
        head,
        digest
    )
}

/// `bases/<key>/key.json` — identity + pin count. `refs` is advisory in v1
/// (GC is manual); lost updates under concurrent pins are acceptable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BaseKey {
    /// "git" | "dir"
    pub kind: String,
    /// Absolute host path the base was seeded from.
    pub toplevel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    pub digest: String,
    pub created: u64,
    #[serde(default)]
    pub refs: u64,
}

pub(crate) fn read_key_json(path: &Path) -> Result<BaseKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

pub(crate) fn write_key_json(path: &Path, k: &BaseKey) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(k)?)
        .with_context(|| format!("write {}", path.display()))
}

// ── the merge layer ─────────────────────────────────────────────────────────

/// One merged path's layer membership. `parent`+`name` locate the entry in
/// the merged tree (path strings: tombstone keys, path_of); `base_ino` /
/// `delta_ino` locate it in the layer DBs. Delta-resident ⟺ `delta_ino` set.
#[derive(Debug, Clone)]
struct MergedNode {
    parent: i64, // merged ino of parent (0 = root)
    name: String,
    base_ino: Option<i64>,
    delta_ino: Option<i64>,
}

pub(crate) struct LayeredFS {
    /// The shared read-only seeded DB. None ⇒ passthrough to delta (§6).
    /// Trait object on purpose: the SDK's concrete type also has PATH-based
    /// inherent methods that would shadow the ino-based trait API here.
    base: Option<Arc<dyn FileSystem>>,
    /// The session's own (initially empty) DB, through the trait.
    delta: Arc<dyn FileSystem>,
    /// The concrete delta handle, only for its connection (tombstone SQL).
    delta_meta: filesystem::AgentFS,
    /// merged ino -> node. Entries survive until `forget`.
    inos: Mutex<HashMap<i64, MergedNode>>,
    /// (parent merged ino, name) -> merged ino — sticky across copy-up.
    by_child: Mutex<HashMap<(i64, String), i64>>,
    next_ino: AtomicI64,
    /// Merged listing cache per dir ino (R4); rebuilt when marked dirty.
    listings: Mutex<HashMap<i64, Vec<DirEntry>>>,
    dirty_dirs: Mutex<HashSet<i64>>,
    /// Tombstone set, loaded from the delta's fs_whiteout at open, kept in
    /// sync on every delete. Exact absolute paths ("/a/b").
    tombstones: Mutex<HashSet<String>>,
}

impl LayeredFS {
    /// Open the merge layer over `base` (optional) + `delta`. Ensures the
    /// delta's tombstone table exists and loads it into memory.
    pub(crate) async fn open(
        base: Option<filesystem::AgentFS>,
        delta: filesystem::AgentFS,
    ) -> Result<Self> {
        let delta_meta = delta.clone();
        let conn = delta_meta.get_connection().await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS fs_whiteout (
                path TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            (),
        )
        .await?;
        let mut tombstones = HashSet::new();
        let mut rows = conn.query("SELECT path FROM fs_whiteout", ()).await?;
        while let Some(row) = rows.next().await? {
            let v = row.get_value(0)?;
            if let Some(p) = v.as_text() {
                tombstones.insert(p.to_string());
            }
        }
        let mut inos = HashMap::new();
        inos.insert(
            ROOT_INO,
            MergedNode {
                parent: 0,
                name: String::new(),
                base_ino: base.as_ref().map(|_| ROOT_INO),
                delta_ino: Some(ROOT_INO),
            },
        );
        Ok(Self {
            base: base.map(|b| Arc::new(b) as Arc<dyn FileSystem>),
            delta: Arc::new(delta) as Arc<dyn FileSystem>,
            delta_meta,
            inos: Mutex::new(inos),
            by_child: Mutex::new(HashMap::new()),
            next_ino: AtomicI64::new(2),
            listings: Mutex::new(HashMap::new()),
            dirty_dirs: Mutex::new(HashSet::new()),
            tombstones: Mutex::new(tombstones),
        })
    }

    // -- state helpers (no awaits while holding a lock) --

    fn node(&self, ino: i64) -> Option<MergedNode> {
        self.inos.lock().unwrap().get(&ino).cloned()
    }

    /// Allocate (or reuse) the merged ino of (parent, name). Sticky: a
    /// repeat lookup returns the same merged ino.
    fn alloc_node(&self, parent: i64, name: &str) -> i64 {
        let key = (parent, name.to_string());
        let mut by = self.by_child.lock().unwrap();
        if let Some(&ino) = by.get(&key) {
            if self.inos.lock().unwrap().contains_key(&ino) {
                return ino;
            }
            by.remove(&key);
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        self.inos.lock().unwrap().insert(
            ino,
            MergedNode {
                parent,
                name: name.to_string(),
                base_ino: None,
                delta_ino: None,
            },
        );
        by.insert(key, ino);
        ino
    }

    /// Attach layer inos to a node (never clears — a shadowed dir keeps its
    /// base ino so base children keep merging).
    fn attach(&self, merged: i64, base_ino: Option<i64>, delta_ino: Option<i64>) {
        let mut map = self.inos.lock().unwrap();
        let Some(n) = map.get_mut(&merged) else {
            return;
        };
        if base_ino.is_some() {
            n.base_ino = base_ino;
        }
        if delta_ino.is_some() {
            n.delta_ino = delta_ino;
        }
    }

    /// Detach a node's delta ino (its delta entry was deleted or replaced;
    /// it falls back to base-side or goes inert until `forget`).
    fn detach_delta(&self, merged: i64) {
        if let Some(n) = self.inos.lock().unwrap().get_mut(&merged) {
            n.delta_ino = None;
        }
    }

    /// Remove the (parent, name) -> ino mapping only when it still points
    /// at `ino`: a path can be deleted and re-created (fresh merged ino)
    /// while a retired node is still around, and an unconditional remove
    /// would orphan the new node's reverse index.
    fn drop_child(&self, parent: i64, name: &str, ino: i64) {
        let mut by = self.by_child.lock().unwrap();
        if by.get(&(parent, name.to_string())).copied() == Some(ino) {
            by.remove(&(parent, name.to_string()));
        }
    }

    fn invalidate_listing(&self, dir_merged: i64) {
        self.dirty_dirs.lock().unwrap().insert(dir_merged);
        self.listings.lock().unwrap().remove(&dir_merged);
    }

    /// Absolute merged path of an ino (walking parent/name to the root).
    fn path_of(&self, ino: i64) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = ino;
        while let Some(node) = self.node(cur) {
            if node.parent == 0 {
                break;
            }
            parts.push(node.name);
            cur = node.parent;
        }
        if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.into_iter().rev().collect::<Vec<_>>().join("/"))
        }
    }

    fn tombstone_hit(&self, path: &str) -> bool {
        tombstone_hidden(path, &self.tombstones.lock().unwrap())
    }

    /// Record a tombstone (in memory + the delta's fs_whiteout table).
    async fn tombstone_add(&self, path: &str) -> SdkResult<()> {
        self.tombstones.lock().unwrap().insert(path.to_string());
        let conn = self.delta_meta.get_connection().await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        conn.execute(
            "INSERT OR IGNORE INTO fs_whiteout (path, created_at) VALUES (?, ?)",
            (path, now),
        )
        .await?;
        Ok(())
    }

    /// Move every tombstone under `old_prefix/` to `new_prefix/`, in memory
    /// and in the delta's fs_whiteout table. Renaming a dir must not
    /// resurrect base children it had hidden at the old location.
    async fn tombstone_rename(&self, old_prefix: &str, new_prefix: &str) {
        let moved: Vec<(String, String)> = {
            let ts = self.tombstones.lock().unwrap();
            ts.iter()
                .filter(|t| {
                    t.len() > old_prefix.len()
                        && t.starts_with(old_prefix)
                        && t.as_bytes().get(old_prefix.len()) == Some(&b'/')
                })
                .map(|t| {
                    (
                        t.clone(),
                        format!("{new_prefix}/{}", &t[old_prefix.len() + 1..]),
                    )
                })
                .collect()
        };
        if moved.is_empty() {
            return;
        }
        {
            let mut ts = self.tombstones.lock().unwrap();
            for (o, n) in &moved {
                ts.remove(o);
                ts.insert(n.clone());
            }
        }
        if let Ok(conn) = self.delta_meta.get_connection().await {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            for (o, n) in &moved {
                let _ = conn
                    .execute("DELETE FROM fs_whiteout WHERE path = ?", (o.as_str(),))
                    .await;
                let _ = conn
                    .execute(
                        "INSERT OR IGNORE INTO fs_whiteout (path, created_at) VALUES (?, ?)",
                        (n.as_str(), now),
                    )
                    .await;
            }
        }
    }

    /// Drop a tombstone row: base content at `path` is visible again through
    /// a delta-resident node (a renamed dir moved back onto its old name).
    async fn tombstone_del(&self, path: &str) {
        self.tombstones.lock().unwrap().remove(path);
        if let Ok(conn) = self.delta_meta.get_connection().await {
            let _ = conn
                .execute("DELETE FROM fs_whiteout WHERE path = ?", (path,))
                .await;
        }
    }

    // -- copy-up (§3.4) --

    /// Ensure every ANCESTOR of `merged` is delta-resident, shadowing
    /// base-resident dirs top-down (entry-level: empty dirs in delta).
    async fn shadow_ancestors(&self, merged: i64) -> SdkResult<()> {
        let mut chain: Vec<(i64, MergedNode)> = Vec::new();
        let mut cur = merged;
        loop {
            match self.node(cur) {
                Some(node) => {
                    let is_root = node.parent == 0;
                    chain.push((cur, node));
                    if is_root {
                        break;
                    }
                    cur = chain.last().unwrap().1.parent;
                }
                None => return Err(FsError::InvalidPath.into()),
            }
        }
        chain.reverse(); // root first, `merged` last
                         // shadow everything except `merged` itself. Re-read each parent
                         // FRESH: the previous iteration just shadowed it, and the snapshot
                         // taken above predates that (its delta_ino was still None).
        for w in chain[..chain.len() - 1].windows(2) {
            let (p_merged, (c_merged, c_node)) = (&w[0].0, &w[1]);
            if c_node.delta_ino.is_some() {
                continue; // root is always delta-resident; shadows idempotent
            }
            let p_node = self.node(*p_merged).ok_or(FsError::NotFound)?;
            self.copy_up_entry(*p_merged, &p_node, *c_merged, c_node)
                .await?;
        }
        Ok(())
    }

    /// Copy ONE base entry up into the delta and flip its node, keeping the
    /// merged ino. Dirs shadow as empty dirs; files copy content; symlinks
    /// copy the target. Attrs (mode/uid/gid/times) come from base.
    async fn copy_up_entry(
        &self,
        parent_merged: i64,
        parent: &MergedNode,
        merged: i64,
        node: &MergedNode,
    ) -> SdkResult<()> {
        let (Some(base), Some(base_ino)) = (self.base.as_ref(), node.base_ino) else {
            return Err(FsError::InvalidPath.into());
        };
        let st = base.getattr(base_ino).await?.ok_or(FsError::NotFound)?;
        layer_dbg("copy-up", merged);
        // the caller guarantees a delta-resident parent; refuse to corrupt
        // the tree by falling back to the delta root
        let parent_delta = parent.delta_ino.ok_or(FsError::NotFound)?;
        let kind = st.mode & S_IFMT;
        let new_delta_ino = if kind == S_IFDIR {
            self.delta
                .mkdir(parent_delta, &node.name, st.mode, st.uid, st.gid)
                .await?
                .ino
        } else if kind == S_IFLNK {
            let target = base.readlink(base_ino).await?.ok_or(FsError::NotFound)?;
            self.delta
                .symlink(parent_delta, &node.name, &target, st.uid, st.gid)
                .await?
                .ino
        } else {
            let data = read_all(&**base, base_ino).await?;
            let (st_new, file) = self
                .delta
                .create_file(parent_delta, &node.name, st.mode, st.uid, st.gid)
                .await?;
            for (off, chunk) in data
                .chunks(COPY_CHUNK as usize)
                .zip(0u64..)
                .map(|(c, i)| (i * COPY_CHUNK, c))
            {
                file.pwrite(off, chunk).await?;
            }
            // preserve base times; a later write updates mtime from here
            let _ = self
                .delta
                .utimens(
                    st_new.ino,
                    TimeChange::Set(st.atime, st.atime_nsec),
                    TimeChange::Set(st.mtime, st.mtime_nsec),
                )
                .await;
            st_new.ino
        };
        self.attach(merged, None, Some(new_delta_ino));
        self.invalidate_listing(parent_merged);
        Ok(())
    }

    /// Copy up `merged` itself (after its ancestors): returns its delta ino.
    async fn copy_up(&self, merged: i64) -> SdkResult<i64> {
        let node = self.node(merged).ok_or(FsError::NotFound)?;
        if let Some(d) = node.delta_ino {
            return Ok(d);
        }
        self.shadow_ancestors(merged).await?;
        let node = self.node(merged).ok_or(FsError::NotFound)?;
        if let Some(d) = node.delta_ino {
            return Ok(d);
        }
        let parent = self.node(node.parent).ok_or(FsError::NotFound)?;
        self.copy_up_entry(node.parent, &parent, merged, &node)
            .await?;
        self.node(merged)
            .and_then(|n| n.delta_ino)
            .ok_or_else(|| FsError::NotFound.into())
    }

    // -- merged listing (§3.3 readdir rows) --

    /// Union listing of a dir: base children (tombstone-filtered) ∪ delta
    /// children (win); merged inos allocated; stable sorted order (R4).
    async fn merged_listing(&self, dir_merged: i64) -> SdkResult<Option<Vec<DirEntry>>> {
        let Some(node) = self.node(dir_merged) else {
            return Ok(None);
        };
        let dir_path = self.path_of(dir_merged);
        let tombstones = self.tombstones.lock().unwrap().clone();
        let mut base_names: HashMap<String, Stats> = HashMap::new();
        let mut delta_names: HashMap<String, Stats> = HashMap::new();

        if let (Some(base), Some(base_ino)) = (self.base.as_ref(), node.base_ino) {
            if let Some(entries) = base.readdir_plus(base_ino).await? {
                for e in entries {
                    if !tombstone_hidden(&child_path(&dir_path, &e.name), &tombstones) {
                        base_names.insert(e.name, e.stats);
                    }
                }
            }
        }
        if let Some(delta_ino) = node.delta_ino {
            if let Some(entries) = self.delta.readdir_plus(delta_ino).await? {
                for e in entries {
                    delta_names.insert(e.name, e.stats);
                }
            }
        }

        let mut names: Vec<String> = base_names
            .keys()
            .chain(delta_names.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let merged = self.alloc_node(dir_merged, &name);
            match (base_names.get(&name), delta_names.get(&name)) {
                // delta wins; keep the base link for future shadowing context
                (Some(b), Some(d)) => self.attach(merged, Some(b.ino), Some(d.ino)),
                (Some(b), None) => self.attach(merged, Some(b.ino), None),
                (None, Some(d)) => self.attach(merged, None, Some(d.ino)),
                (None, None) => unreachable!("name came from one of the two maps"),
            }
            let st = delta_names
                .get(&name)
                .or_else(|| base_names.get(&name))
                .unwrap()
                .clone();
            out.push(DirEntry {
                name,
                stats: Stats { ino: merged, ..st },
            });
        }
        Ok(Some(out))
    }

    /// Cached merged listing; rebuilt only after a mutation in that dir (R4).
    async fn listing(&self, dir_merged: i64) -> SdkResult<Option<Vec<DirEntry>>> {
        if !self.dirty_dirs.lock().unwrap().contains(&dir_merged) {
            let cached = self.listings.lock().unwrap().get(&dir_merged).cloned();
            if let Some(v) = cached {
                return Ok(Some(v));
            }
        }
        let fresh = self.merged_listing(dir_merged).await?;
        if let Some(v) = &fresh {
            let mut dirty = self.dirty_dirs.lock().unwrap();
            // only cache when the dir stayed clean across the rebuild — a
            // mutation during it must not be overwritten by stale data
            if !dirty.contains(&dir_merged) {
                self.listings.lock().unwrap().insert(dir_merged, v.clone());
                dirty.remove(&dir_merged);
            }
        }
        Ok(fresh)
    }
}

/// Read a whole file from a layer through its open handle (pread loop).
async fn read_all(fs: &dyn FileSystem, ino: i64) -> SdkResult<Vec<u8>> {
    let file = fs.open(ino, libc::O_RDONLY).await?;
    let mut out = Vec::new();
    let mut off = 0u64;
    loop {
        let chunk = file.pread(off, COPY_CHUNK).await?;
        if chunk.is_empty() {
            break;
        }
        off += chunk.len() as u64;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[async_trait::async_trait]
impl FileSystem for LayeredFS {
    async fn lookup(&self, parent_ino: i64, name: &str) -> SdkResult<Option<Stats>> {
        let Some(parent) = self.node(parent_ino) else {
            return Err(FsError::NotFound.into());
        };
        // delta wins unconditionally (recreations over tombstones included)
        if let Some(dstats) = self
            .delta
            .lookup(parent.delta_ino.unwrap_or(-1), name)
            .await?
        {
            let merged = self.alloc_node(parent_ino, name);
            self.attach(merged, None, Some(dstats.ino));
            return Ok(Some(Stats {
                ino: merged,
                ..dstats
            }));
        }
        // base fallback, hidden by exact-or-ancestor tombstones
        if let (Some(base), Some(pbase)) = (self.base.as_ref(), parent.base_ino) {
            if let Some(bstats) = base.lookup(pbase, name).await? {
                let cpath = child_path(&self.path_of(parent_ino), name);
                if self.tombstone_hit(&cpath) {
                    return Ok(None);
                }
                let merged = self.alloc_node(parent_ino, name);
                self.attach(merged, Some(bstats.ino), None);
                return Ok(Some(Stats {
                    ino: merged,
                    ..bstats
                }));
            }
        }
        Ok(None)
    }

    async fn getattr(&self, ino: i64) -> SdkResult<Option<Stats>> {
        let Some(node) = self.node(ino) else {
            return Ok(None);
        };
        match node.delta_ino {
            Some(d) => Ok(self.delta.getattr(d).await?.map(|st| Stats { ino, ..st })),
            None => match (self.base.as_ref(), node.base_ino) {
                (Some(base), Some(b)) => Ok(base.getattr(b).await?.map(|st| Stats { ino, ..st })),
                _ => Ok(None),
            },
        }
    }

    async fn readlink(&self, ino: i64) -> SdkResult<Option<String>> {
        let Some(node) = self.node(ino) else {
            return Ok(None);
        };
        match node.delta_ino {
            Some(d) => self.delta.readlink(d).await,
            None => match (self.base.as_ref(), node.base_ino) {
                (Some(base), Some(b)) => base.readlink(b).await,
                _ => Ok(None),
            },
        }
    }

    async fn readdir(&self, ino: i64) -> SdkResult<Option<Vec<String>>> {
        Ok(self
            .listing(ino)
            .await?
            .map(|v| v.into_iter().map(|e| e.name).collect()))
    }

    async fn readdir_plus(&self, ino: i64) -> SdkResult<Option<Vec<DirEntry>>> {
        self.listing(ino).await
    }

    async fn chmod(&self, ino: i64, mode: u32) -> SdkResult<()> {
        // no-op setattr (the kernel re-flushes cached attrs it never
        // changed, e.g. on inode eviction) must NOT copy-up
        if self
            .getattr(ino)
            .await?
            .is_some_and(|st| st.mode & 0o7777 == mode & 0o7777)
        {
            return Ok(());
        }
        let d = self.copy_up(ino).await?;
        self.delta.chmod(d, mode).await
    }

    async fn chown(&self, ino: i64, uid: Option<u32>, gid: Option<u32>) -> SdkResult<()> {
        let cur = self.getattr(ino).await?;
        let no_op = match cur {
            Some(st) => {
                let same_uid = uid.is_none_or(|u| u == st.uid);
                let same_gid = gid.is_none_or(|g| g == st.gid);
                (uid.is_none() && gid.is_none()) || (same_uid && same_gid)
            }
            None => true,
        };
        if no_op {
            return Ok(());
        }
        let d = self.copy_up(ino).await?;
        let parent = self.node(ino).map(|n| n.parent).unwrap_or(0);
        self.delta.chown(d, uid, gid).await?;
        if parent != 0 {
            self.invalidate_listing(parent);
        }
        Ok(())
    }

    async fn utimens(&self, ino: i64, atime: TimeChange, mtime: TimeChange) -> SdkResult<()> {
        // The kernel re-flushes CACHED attrs on inode eviction/unlink with
        // the values we already serve — a no-op utimens must not copy the
        // entry into the delta (a plain `rm` would otherwise materialize
        // every file it deletes).
        let cur = self.getattr(ino).await?;
        let no_op = match cur {
            Some(st) => {
                let atime_same = match atime {
                    TimeChange::Omit => true,
                    TimeChange::Set(a, an) => a == st.atime && an == st.atime_nsec,
                    TimeChange::Now => false,
                };
                let mtime_same = match mtime {
                    TimeChange::Omit => true,
                    TimeChange::Set(m, mn) => m == st.mtime && mn == st.mtime_nsec,
                    TimeChange::Now => false,
                };
                atime_same && mtime_same
            }
            None => true,
        };
        if no_op {
            return Ok(());
        }
        let d = self.copy_up(ino).await?;
        let parent = self.node(ino).map(|n| n.parent).unwrap_or(0);
        self.delta.utimens(d, atime, mtime).await?;
        if parent != 0 {
            self.invalidate_listing(parent);
        }
        Ok(())
    }

    async fn open(&self, ino: i64, flags: i32) -> SdkResult<BoxedFile> {
        let node = self.node(ino).ok_or(FsError::NotFound)?;
        let write = (flags & libc::O_ACCMODE) != libc::O_RDONLY || (flags & libc::O_TRUNC) != 0;
        if write {
            layer_dbg("open-w", ino);
            let d = self.copy_up(ino).await?;
            return self.delta.open(d, flags).await;
        }
        match node.delta_ino {
            Some(d) => self.delta.open(d, flags).await,
            None => match (self.base.as_ref(), node.base_ino) {
                (Some(base), Some(b)) => base.open(b, flags).await,
                _ => Err(FsError::NotFound.into()),
            },
        }
    }

    // -- creation: shared shape (§3.3 create rows) --
    //
    // Creating under a base-resident parent shadows the parent CHAIN (empty
    // dirs in delta) and creates the child in delta; the base subtree is
    // never bulk-copied. Recreating over a tombstone skips existence checks
    // (the path is invisible, so POSIX create semantics hold) and leaves the
    // tombstone row in place — it hides the base copy; the delta entry wins.

    async fn mkdir(
        &self,
        parent_ino: i64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> SdkResult<Stats> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if !self.tombstone_hit(&cpath) {
            if self
                .delta
                .lookup(parent.delta_ino.unwrap_or(-1), name)
                .await?
                .is_some()
            {
                return Err(FsError::AlreadyExists.into());
            }
            if let (Some(base), Some(pbase)) = (self.base.as_ref(), parent.base_ino) {
                if base.lookup(pbase, name).await?.is_some() {
                    return Err(FsError::AlreadyExists.into());
                }
            }
        }
        let pdelta = self.copy_up(parent_ino).await?;
        let st = self.delta.mkdir(pdelta, name, mode, uid, gid).await?;
        let merged = self.alloc_node(parent_ino, name);
        self.attach(merged, None, Some(st.ino));
        self.invalidate_listing(parent_ino);
        Ok(Stats { ino: merged, ..st })
    }

    async fn create_file(
        &self,
        parent_ino: i64,
        name: &str,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> SdkResult<(Stats, BoxedFile)> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if !self.tombstone_hit(&cpath) {
            if self
                .delta
                .lookup(parent.delta_ino.unwrap_or(-1), name)
                .await?
                .is_some()
            {
                return Err(FsError::AlreadyExists.into());
            }
            if let (Some(base), Some(pbase)) = (self.base.as_ref(), parent.base_ino) {
                if base.lookup(pbase, name).await?.is_some() {
                    return Err(FsError::AlreadyExists.into());
                }
            }
        }
        let pdelta = self.copy_up(parent_ino).await?;
        let (st, file) = self.delta.create_file(pdelta, name, mode, uid, gid).await?;
        let merged = self.alloc_node(parent_ino, name);
        self.attach(merged, None, Some(st.ino));
        self.invalidate_listing(parent_ino);
        Ok((Stats { ino: merged, ..st }, file))
    }

    async fn mknod(
        &self,
        parent_ino: i64,
        name: &str,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> SdkResult<Stats> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if !self.tombstone_hit(&cpath) {
            if self
                .delta
                .lookup(parent.delta_ino.unwrap_or(-1), name)
                .await?
                .is_some()
            {
                return Err(FsError::AlreadyExists.into());
            }
            if let (Some(base), Some(pbase)) = (self.base.as_ref(), parent.base_ino) {
                if base.lookup(pbase, name).await?.is_some() {
                    return Err(FsError::AlreadyExists.into());
                }
            }
        }
        let pdelta = self.copy_up(parent_ino).await?;
        let st = self.delta.mknod(pdelta, name, mode, rdev, uid, gid).await?;
        let merged = self.alloc_node(parent_ino, name);
        self.attach(merged, None, Some(st.ino));
        self.invalidate_listing(parent_ino);
        Ok(Stats { ino: merged, ..st })
    }

    async fn symlink(
        &self,
        parent_ino: i64,
        name: &str,
        target: &str,
        uid: u32,
        gid: u32,
    ) -> SdkResult<Stats> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if !self.tombstone_hit(&cpath) {
            if self
                .delta
                .lookup(parent.delta_ino.unwrap_or(-1), name)
                .await?
                .is_some()
            {
                return Err(FsError::AlreadyExists.into());
            }
            if let (Some(base), Some(pbase)) = (self.base.as_ref(), parent.base_ino) {
                if base.lookup(pbase, name).await?.is_some() {
                    return Err(FsError::AlreadyExists.into());
                }
            }
        }
        let pdelta = self.copy_up(parent_ino).await?;
        let st = self.delta.symlink(pdelta, name, target, uid, gid).await?;
        let merged = self.alloc_node(parent_ino, name);
        self.attach(merged, None, Some(st.ino));
        self.invalidate_listing(parent_ino);
        Ok(Stats { ino: merged, ..st })
    }

    // -- deletion (§3.5) --

    async fn unlink(&self, parent_ino: i64, name: &str) -> SdkResult<()> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if self.tombstone_hit(&cpath) {
            return Err(FsError::NotFound.into());
        }
        let Some(child) = self.lookup(parent_ino, name).await? else {
            return Err(FsError::NotFound.into());
        };
        if child.mode & S_IFMT == S_IFDIR {
            return Err(FsError::IsADirectory.into()); // POSIX: unlink(dir) → EISDIR
        }
        if self
            .delta
            .lookup(parent.delta_ino.unwrap_or(-1), name)
            .await?
            .is_some()
        {
            self.delta
                .unlink(parent.delta_ino.unwrap_or(ROOT_INO), name)
                .await?;
        }
        self.tombstone_add(&cpath).await?;
        self.drop_child(parent_ino, name, child.ino);
        self.invalidate_listing(parent_ino);
        Ok(())
    }

    async fn rmdir(&self, parent_ino: i64, name: &str) -> SdkResult<()> {
        let parent = self.node(parent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(parent_ino), name);
        if self.tombstone_hit(&cpath) {
            return Err(FsError::NotFound.into());
        }
        let Some(child) = self.lookup(parent_ino, name).await? else {
            return Err(FsError::NotFound.into());
        };
        if child.mode & S_IFMT != S_IFDIR {
            return Err(FsError::NotADirectory.into());
        }
        // merged children must be empty (union minus tombstones)
        match self.listing(child.ino).await? {
            Some(children) if !children.is_empty() => return Err(FsError::NotEmpty.into()),
            Some(_) => {}
            None => return Err(FsError::NotFound.into()),
        }
        if self
            .delta
            .lookup(parent.delta_ino.unwrap_or(-1), name)
            .await?
            .is_some()
        {
            self.delta
                .rmdir(parent.delta_ino.unwrap_or(ROOT_INO), name)
                .await?;
        }
        // one row covers the (now empty) whole subtree via the ancestor check
        self.tombstone_add(&cpath).await?;
        self.drop_child(parent_ino, name, child.ino);
        self.invalidate_listing(parent_ino);
        Ok(())
    }

    async fn link(&self, ino: i64, newparent_ino: i64, newname: &str) -> SdkResult<Stats> {
        let newp = self.node(newparent_ino).ok_or(FsError::NotFound)?;
        let cpath = child_path(&self.path_of(newparent_ino), newname);
        if !self.tombstone_hit(&cpath) {
            if self
                .delta
                .lookup(newp.delta_ino.unwrap_or(-1), newname)
                .await?
                .is_some()
            {
                return Err(FsError::AlreadyExists.into());
            }
            if let (Some(base), Some(pb)) = (self.base.as_ref(), newp.base_ino) {
                if base.lookup(pb, newname).await?.is_some() {
                    return Err(FsError::AlreadyExists.into());
                }
            }
        }
        if self.node(ino).ok_or(FsError::NotFound)?.delta_ino.is_none() {
            self.copy_up(ino).await?; // hardlinks live only within the delta
        }
        let newp_delta = self.copy_up(newparent_ino).await?;
        let src_delta = self
            .node(ino)
            .ok_or(FsError::NotFound)?
            .delta_ino
            .ok_or(FsError::NotFound)?;
        let st = self.delta.link(src_delta, newp_delta, newname).await?;
        let merged = self.alloc_node(newparent_ino, newname);
        self.attach(merged, None, Some(st.ino));
        self.invalidate_listing(newparent_ino);
        Ok(Stats { ino: merged, ..st })
    }

    async fn rename(
        &self,
        oldparent_ino: i64,
        oldname: &str,
        newparent_ino: i64,
        newname: &str,
    ) -> SdkResult<()> {
        let oldp = self.node(oldparent_ino).ok_or(FsError::NotFound)?;
        let old_path = child_path(&self.path_of(oldparent_ino), oldname);
        let new_path = child_path(&self.path_of(newparent_ino), newname);
        if self.tombstone_hit(&old_path) {
            return Err(FsError::NotFound.into());
        }
        let Some(src_stats) = self.lookup(oldparent_ino, oldname).await? else {
            return Err(FsError::NotFound.into());
        };
        let src_merged = src_stats.ino;
        // POSIX: replacing a non-empty dir with a dir is ENOTEMPTY (kernel
        // checks); files/dirs replace what they can at the delta layer.
        let target_existed = self.lookup(newparent_ino, newname).await?.is_some();

        // copy-up the source entry if base-resident (dir: shadow only)
        if self.node(src_merged).unwrap().delta_ino.is_none() {
            self.copy_up(src_merged).await?;
        }
        let newp_delta = self.copy_up(newparent_ino).await?;
        self.delta
            .rename(
                oldp.delta_ino.unwrap_or(ROOT_INO),
                oldname,
                newp_delta,
                newname,
            )
            .await?;

        // bookkeeping: the source node moves, merged ino unchanged (§3.3)
        if let Some(n) = self.inos.lock().unwrap().get_mut(&src_merged) {
            n.parent = newparent_ino;
            n.name = newname.to_string();
        }
        self.drop_child(oldparent_ino, oldname, src_merged);
        if target_existed {
            // the delta rename replaced the target's delta entry
            if let Some(prev) = self
                .by_child
                .lock()
                .unwrap()
                .remove(&(newparent_ino, newname.to_string()))
            {
                if prev != src_merged {
                    self.detach_delta(prev);
                }
            }
        }
        self.by_child
            .lock()
            .unwrap()
            .insert((newparent_ino, newname.to_string()), src_merged);

        // a moved dir carries its hidden base descendants with it
        if old_path != new_path {
            self.tombstone_rename(&old_path, &new_path).await;
        }
        // tombstone bookkeeping:
        //  - the old path: hide the base copy that now has no delta shadow
        //  - the target: hide its base copy if one existed there
        //  - except: if the moved node IS the base entry at the target path
        //    (a dir renamed away and back), that content is visible again.
        let src_had_base = self.node(src_merged).unwrap().base_ino.is_some();
        if src_had_base && old_path != new_path {
            self.tombstone_add(&old_path).await?;
        }
        if target_existed {
            let target_base = match (
                self.base.as_ref(),
                self.node(newparent_ino).unwrap().base_ino,
            ) {
                (Some(base), Some(pb)) => base.lookup(pb, newname).await?,
                _ => None,
            };
            if target_base.is_some() && new_path != old_path {
                self.tombstone_add(&new_path).await?;
            }
            if src_had_base {
                if let Some(tb) = target_base {
                    if Some(tb.ino) == self.node(src_merged).unwrap().base_ino {
                        self.tombstone_del(&new_path).await;
                    }
                }
            }
        }
        self.invalidate_listing(oldparent_ino);
        self.invalidate_listing(newparent_ino);
        Ok(())
    }

    async fn statfs(&self) -> SdkResult<FilesystemStats> {
        // the delta's footprint is what fills up (§3.3)
        self.delta.statfs().await
    }

    async fn forget(&self, ino: i64, nlookup: u64) {
        // retire the merged node when the kernel's reference count hits zero
        // (mirrors SDK behavior), forwarding to the layers' caches. The
        // parent's cached listing must go too: it names this child by merged
        // ino, and a retired ino would fail getattr (ENOENT on a visible
        // entry) until the listing is rebuilt with fresh inos.
        let Some(node) = self.inos.lock().unwrap().remove(&ino) else {
            return;
        };
        self.drop_child(node.parent, &node.name, ino);
        self.listings.lock().unwrap().remove(&ino);
        self.dirty_dirs.lock().unwrap().remove(&ino);
        if node.parent != 0 {
            self.invalidate_listing(node.parent);
        }
        if let Some(di) = node.delta_ino {
            self.delta.forget(di, nlookup).await;
        }
        if let (Some(base), Some(bi)) = (self.base.as_ref(), node.base_ino) {
            base.forget(bi, nlookup).await;
        }
    }
}

// ── tests (§9 unit list — trait-driven, no FUSE) ────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use agentfs_sdk::{AgentFS, AgentFSOptions, DEFAULT_FILE_MODE};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("den-layer-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn open_db(dir: &Path, name: &str) -> filesystem::AgentFS {
        let p = dir.join(name);
        AgentFS::open(AgentFSOptions::with_path(p.to_string_lossy().to_string()))
            .await
            .unwrap()
            .fs
    }

    /// Seed a base DB: /README.md, /src/{lib.rs,main.rs}, /src/deep/x.txt.
    async fn seed_base(fs: &filesystem::AgentFS) {
        fs.mkdir("/src", 0, 0).await.unwrap();
        fs.mkdir("/src/deep", 0, 0).await.unwrap();
        let files: [(&str, &[u8]); 4] = [
            ("/README.md", b"readme\n"),
            ("/src/lib.rs", b"lib\n"),
            ("/src/main.rs", b"main\n"),
            ("/src/deep/x.txt", b"x\n"),
        ];
        for (path, data) in files {
            fs.create_file(path, DEFAULT_FILE_MODE, 0, 0).await.unwrap();
            fs.pwrite(path, 0, data).await.unwrap();
        }
    }

    async fn open_layer(dir: &Path, seed: bool) -> LayeredFS {
        let base = if seed {
            let b = open_db(dir, "base.db").await;
            seed_base(&b).await;
            Some(b)
        } else {
            None
        };
        let delta = open_db(dir, "fs.db").await;
        LayeredFS::open(base, delta).await.unwrap()
    }

    /// Reopen the SAME DBs as a fresh mount (tombstone persistence check).
    async fn reopen_layer(dir: &Path) -> LayeredFS {
        let base = if dir.join("base.db").exists() {
            Some(open_db(dir, "base.db").await)
        } else {
            None
        };
        let delta = open_db(dir, "fs.db").await;
        LayeredFS::open(base, delta).await.unwrap()
    }

    // 1. lookup resolution order: delta wins, base fallback, tombstone ENOENT
    #[tokio::test]
    async fn lookup_resolution_order() {
        let dir = tmp("lookup");
        {
            let l = open_layer(&dir, true).await;
            let st = l.lookup(1, "README.md").await.unwrap().unwrap();
            assert_eq!(st.size, 7);
            l.create_file(1, "new.txt", DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            let st = l.lookup(1, "new.txt").await.unwrap().unwrap();
            assert_eq!(st.size, 0);
            l.unlink(1, "README.md").await.unwrap();
            assert!(l.lookup(1, "README.md").await.unwrap().is_none());
            // recreation wins over the tombstone
            l.create_file(1, "README.md", DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            assert!(l.lookup(1, "README.md").await.unwrap().is_some());
            // a tombstoned-and-not-recreated path
            l.create_file(1, "gone.txt", DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            l.unlink(1, "gone.txt").await.unwrap();
            assert!(l.lookup(1, "gone.txt").await.unwrap().is_none());
        }
        // tombstones persist with the delta across mounts
        {
            let l = reopen_layer(&dir).await;
            assert!(l.lookup(1, "gone.txt").await.unwrap().is_none());
            assert!(l.lookup(1, "README.md").await.unwrap().is_some()); // recreated
                                                                        // never deleted: full base path still resolves (two-step)
            let src = l.lookup(1, "src").await.unwrap().unwrap().ino;
            assert!(l.lookup(src, "lib.rs").await.unwrap().is_some());
        }
    }

    // 2. readdir union + dedupe + tombstone filter + stable ordering
    #[tokio::test]
    async fn readdir_union_dedupe_tombstone_stable() {
        let dir = tmp("readdir");
        let l = open_layer(&dir, true).await;
        let src = l.lookup(1, "src").await.unwrap().unwrap().ino;
        l.create_file(src, "extra.rs", DEFAULT_FILE_MODE, 0, 0)
            .await
            .unwrap();
        l.unlink(src, "main.rs").await.unwrap();
        let names = l.readdir(src).await.unwrap().unwrap();
        assert_eq!(names, vec!["deep", "extra.rs", "lib.rs"]);
        assert_eq!(l.readdir(src).await.unwrap().unwrap(), names);
        // a tombstoned dir hides its base descendants
        let deep = l.lookup(src, "deep").await.unwrap().unwrap().ino;
        l.unlink(deep, "x.txt").await.unwrap();
        l.rmdir(src, "deep").await.unwrap();
        let names = l.readdir(src).await.unwrap().unwrap();
        assert_eq!(names, vec!["extra.rs", "lib.rs"]);
        // deep's merged ino is gone from the merged view
        let deep = l.lookup(src, "deep").await.unwrap();
        assert!(deep.is_none());
    }

    // 3. copy-up: content/mode/times from base; merged ino unchanged
    #[tokio::test]
    async fn copy_up_preserves_attrs_and_merged_ino() {
        let dir = tmp("copyup");
        let l = open_layer(&dir, true).await;
        let before = l.lookup(1, "README.md").await.unwrap().unwrap(); // base stats
        l.open(before.ino, libc::O_RDWR).await.unwrap(); // copy-up
        let after = l.getattr(before.ino).await.unwrap().unwrap();
        assert_eq!(after.ino, before.ino, "merged ino sticky across copy-up");
        assert_eq!(after.size, before.size);
        assert_eq!(after.mode, before.mode);
        assert_eq!(
            (after.mtime, after.mtime_nsec),
            (before.mtime, before.mtime_nsec)
        );
        // materialized in delta — but the base SUBTREE was not copied
        let delta_root = l.delta.readdir_plus(1).await.unwrap().unwrap();
        let delta_names: Vec<&str> = delta_root.iter().map(|e| e.name.as_str()).collect();
        assert!(delta_names.contains(&"README.md"));
        assert!(!delta_names.contains(&"src"));

        // a write then shows up in merged reads
        let file = l.open(before.ino, libc::O_WRONLY).await.unwrap();
        file.pwrite(0, b"READ").await.unwrap();
        let rd = l.open(before.ino, libc::O_RDONLY).await.unwrap();
        assert_eq!(rd.pread(0, 16).await.unwrap(), b"READme\n");
    }

    // 4. dir shadow: base children still listed after the parent is shadowed
    #[tokio::test]
    async fn shadow_dir_keeps_base_children() {
        let dir = tmp("shadow");
        let l = open_layer(&dir, true).await;
        let src = l.lookup(1, "src").await.unwrap().unwrap().ino;
        l.create_file(src, "new.rs", DEFAULT_FILE_MODE, 0, 0)
            .await
            .unwrap();
        let names = l.readdir(src).await.unwrap().unwrap();
        assert!(names.contains(&"lib.rs".to_string()));
        assert!(names.contains(&"new.rs".to_string()));
        assert!(names.contains(&"deep".to_string()));
        // a base child through the shadowed parent still reads base content
        let lib = l.lookup(src, "lib.rs").await.unwrap().unwrap();
        let data = l.open(lib.ino, libc::O_RDONLY).await.unwrap();
        assert_eq!(data.pread(0, 16).await.unwrap(), b"lib\n");
        // ...and a nested shadowed dir chain works too
        let deep = l.lookup(src, "deep").await.unwrap().unwrap().ino;
        let x = l.lookup(deep, "x.txt").await.unwrap().unwrap();
        assert_eq!(x.size, 2);
    }

    // 5. rename/unlink/rmdir tombstone bookkeeping; ENOTEMPTY from merged view
    #[tokio::test]
    async fn delete_rename_tombstones() {
        let dir = tmp("delrename");
        {
            let l = open_layer(&dir, true).await;
            let src = l.lookup(1, "src").await.unwrap().unwrap().ino;
            // rmdir a non-empty merged dir → ENOTEMPTY
            assert!(matches!(
                l.rmdir(1, "src").await.unwrap_err(),
                agentfs_sdk::error::Error::Fs(FsError::NotEmpty)
            ));
            for n in ["lib.rs", "main.rs"] {
                l.unlink(src, n).await.unwrap();
            }
            let deep = l.lookup(src, "deep").await.unwrap().unwrap().ino;
            l.unlink(deep, "x.txt").await.unwrap();
            l.rmdir(src, "deep").await.unwrap();
            l.rmdir(1, "src").await.unwrap();
            assert!(l.lookup(1, "src").await.unwrap().is_none());
            // rename a base file: old path tombstoned, content survives
            l.rename(1, "README.md", 1, "NOTES.md").await.unwrap();
            assert!(l.lookup(1, "README.md").await.unwrap().is_none());
            let notes = l.lookup(1, "NOTES.md").await.unwrap().unwrap();
            assert_eq!(notes.size, 7);
        }
        // tombstones survive a remount: base README.md stays hidden
        {
            let l = reopen_layer(&dir).await;
            assert!(l.lookup(1, "README.md").await.unwrap().is_none());
            assert!(l.lookup(1, "NOTES.md").await.unwrap().is_some());
            assert!(l.lookup(1, "src").await.unwrap().is_none());
            // moving the renamed file back re-exposes base README.md
            l.rename(1, "NOTES.md", 1, "README.md").await.unwrap();
            let back = l.lookup(1, "README.md").await.unwrap().unwrap();
            assert_eq!(back.size, 7);
        }
        {
            let l = reopen_layer(&dir).await;
            assert!(l.lookup(1, "README.md").await.unwrap().is_some());
            assert!(l.lookup(1, "NOTES.md").await.unwrap().is_none());
        }
    }

    // 6. legacy passthrough (base: None) — exactly today's single-DB behavior
    #[tokio::test]
    async fn legacy_passthrough() {
        let dir = tmp("legacy");
        let l = open_layer(&dir, false).await;
        let (_, file) = l
            .create_file(1, "a.txt", DEFAULT_FILE_MODE, 0, 0)
            .await
            .unwrap();
        file.pwrite(0, b"x").await.unwrap();
        let st = l.lookup(1, "a.txt").await.unwrap().unwrap();
        assert_eq!(st.size, 1);
        assert!(l.lookup(1, "missing").await.unwrap().is_none());
        let names = l.readdir(1).await.unwrap().unwrap();
        assert_eq!(names, vec!["a.txt"]);
    }

    #[tokio::test]
    async fn eexist_from_merged_view() {
        let dir = tmp("eexist");
        let l = open_layer(&dir, true).await;
        assert!(matches!(
            l.mkdir(1, "src", 0o755, 0, 0).await,
            Err(agentfs_sdk::error::Error::Fs(FsError::AlreadyExists))
        ));
        assert!(matches!(
            l.create_file(1, "README.md", DEFAULT_FILE_MODE, 0, 0).await,
            Err(agentfs_sdk::error::Error::Fs(FsError::AlreadyExists))
        ));
    }

    // depth-3 copy-up: /a/b/c.txt shadows BOTH ancestors in the right
    // place (regression: stale parent snapshots put /b under the delta root)
    #[tokio::test]
    async fn deep_copy_up_shadows_correct_chain() {
        let dir = tmp("deep");
        {
            let base = open_db(&dir, "base.db").await;
            base.mkdir("/a", 0, 0).await.unwrap();
            base.mkdir("/a/b", 0, 0).await.unwrap();
            base.create_file("/a/b/c.txt", DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            base.pwrite("/a/b/c.txt", 0, b"deep").await.unwrap();
            let delta = open_db(&dir, "fs.db").await;
            let l = LayeredFS::open(Some(base), delta).await.unwrap();
            let a = l.lookup(1, "a").await.unwrap().unwrap().ino;
            let b = l.lookup(a, "b").await.unwrap().unwrap().ino;
            let c = l.lookup(b, "c.txt").await.unwrap().unwrap().ino;
            l.open(c, libc::O_RDWR).await.unwrap(); // copy-up /a/b/c.txt
                                                    // delta tree: /a/b/c.txt — nothing at the delta root but /a
            let root = l.delta.readdir_plus(1).await.unwrap().unwrap();
            let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, vec!["a"], "delta root must hold only /a");
            let dstats = l.delta.getattr(c).await.unwrap();
            assert!(dstats.is_some(), "deep copy-up materialized the file");
            assert_eq!(dstats.unwrap().size, 4, "content copied");
        }
        // rename at depth 3 (regression: stale old-parent snapshot)
        {
            let base = open_db(&dir, "base.db").await;
            let delta = open_db(&dir, "fs.db").await;
            let l = LayeredFS::open(Some(base), delta).await.unwrap();
            let a = l.lookup(1, "a").await.unwrap().unwrap().ino;
            l.rename(a, "b", a, "b2").await.unwrap();
            let b2 = l.lookup(a, "b2").await.unwrap().unwrap();
            assert_eq!(b2.size, 0); // dir
            let d = l.lookup(b2.ino, "c.txt").await.unwrap().unwrap();
            assert_eq!(d.size, 4);
            assert!(l.lookup(a, "b").await.unwrap().is_none());
        }
    }

    // renaming a dir carries its hidden base descendants (regression:
    // tombstone rows stayed at the old prefix and the child resurrected)
    #[tokio::test]
    async fn rename_rewrites_descendant_tombstones() {
        let dir = tmp("renametomb");
        let base = open_db(&dir, "base.db").await;
        base.mkdir("/a", 0, 0).await.unwrap();
        base.create_file("/a/keep.txt", DEFAULT_FILE_MODE, 0, 0)
            .await
            .unwrap();
        base.create_file("/a/gone.txt", DEFAULT_FILE_MODE, 0, 0)
            .await
            .unwrap();
        let delta = open_db(&dir, "fs.db").await;
        let l = LayeredFS::open(Some(base), delta).await.unwrap();
        l.unlink(1, "a").await.unwrap_err(); // dir: ENOTEMPTY
        let a = l.lookup(1, "a").await.unwrap().unwrap().ino;
        l.unlink(a, "gone.txt").await.unwrap();
        assert!(l.lookup(a, "gone.txt").await.unwrap().is_none());
        // move the whole dir: gone.txt must stay hidden at /b/gone.txt
        l.rename(1, "a", 1, "b").await.unwrap();
        let b = l.lookup(1, "b").await.unwrap().unwrap().ino;
        assert!(l.lookup(b, "gone.txt").await.unwrap().is_none());
        assert!(l.lookup(b, "keep.txt").await.unwrap().is_some());
        // persisted rows moved too
        let rows = l.delta_meta.get_connection().await.unwrap();
        let mut q = rows
            .query("SELECT path FROM fs_whiteout", ())
            .await
            .unwrap();
        let mut found = Vec::new();
        while let Some(row) = q.next().await.unwrap() {
            if let Some(t) = row
                .get_value(0)
                .ok()
                .and_then(|v| v.as_text().map(|s| s.to_string()))
            {
                found.push(t);
            }
        }
        // the moved row + the dir's own old-path row (source was base-resident)
        assert!(found.contains(&"/b/gone.txt".to_string()));
        assert!(found.contains(&"/a".to_string()));
        assert!(!found.contains(&"/a/gone.txt".to_string()));
    }

    // pure helpers
    #[test]
    fn tombstone_prefix_semantics() {
        let ts: HashSet<String> = ["/src".to_string(), "/a.txt".to_string()].into();
        assert!(tombstone_hidden("/src", &ts));
        assert!(tombstone_hidden("/src/lib.rs", &ts));
        assert!(tombstone_hidden("/a.txt", &ts));
        assert!(!tombstone_hidden("/srcx/lib.rs", &ts));
        assert!(!tombstone_hidden("/other", &ts));
        assert_eq!(child_path("/", "x"), "/x");
        assert_eq!(child_path("/src", "x"), "/src/x");
        assert_eq!(child_path("", "x"), "/x");
        assert_eq!(child_path("/src/", "x"), "/src/x");
    }

    #[test]
    fn base_key_charset_and_shape() {
        let k = base_key(
            true,
            Path::new("/home/user/Work/den"),
            Some("0123456789abcdef"),
            "aabbccdd00112233",
        );
        assert!(k.starts_with("git-home-user-work-den-0123456789ab-aabbccdd00112233"));
        assert!(k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        let k2 = base_key(false, Path::new("/tmp/Weird Path/Ω"), None, "ff");
        assert!(k2.starts_with("dir-tmp-weird-path-"));
        assert!(k2.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn key_json_roundtrip() {
        let dir = tmp("keyjson");
        let p = dir.join("key.json");
        let k = BaseKey {
            kind: "git".into(),
            toplevel: "/repo".into(),
            head_sha: Some("abc".into()),
            digest: "dd".into(),
            created: 42,
            refs: 3,
        };
        write_key_json(&p, &k).unwrap();
        assert_eq!(read_key_json(&p).unwrap(), k);
        // head_sha omitted for dir keys
        let k2 = BaseKey {
            kind: "dir".into(),
            toplevel: "/d".into(),
            head_sha: None,
            digest: "dd".into(),
            created: 1,
            refs: 0,
        };
        write_key_json(&p, &k2).unwrap();
        assert_eq!(read_key_json(&p).unwrap(), k2);
    }

    #[test]
    fn digest_changes_on_touch() {
        let dir = tmp("digest");
        std::fs::write(dir.join("a.txt"), "one").unwrap();
        let d1 = worktree_digest(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "two").unwrap();
        let d2 = worktree_digest(&dir).unwrap();
        assert_ne!(d1, d2, "size change must change the digest");
        // determinism
        assert_eq!(worktree_digest(&dir).unwrap(), d2);
        // excludes + .git skip
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::write(dir.join("node_modules/junk.js"), "junk").unwrap();
        std::fs::create_dir(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/HEAD"), "ref: x").unwrap();
        assert_eq!(worktree_digest(&dir).unwrap(), d2);
    }
}
