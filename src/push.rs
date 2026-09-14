//! `den push` — land a session's file changes as a git branch on the host.
//!
//! The push happens HERE, outside the sandbox, at the trust boundary: the
//! agent never sees git credentials (the seeded `/.git/config` is scrubbed at
//! seed time) and never talks to the network. den diffs the session VFS
//! against its seed baseline, applies the delta to a throwaway git worktree
//! of the host repo, commits, and pushes the branch. Review happens in a PR
//! as usual — the sandbox itself never gains push power.
//!
//! Flow:
//!   1. `den` (first run) records the seed baseline to `<session>/seed.snapshot`
//!   2. the agent works; every write lands in the session fs.db
//!   3. `den push` diffs VFS vs baseline -> worktree -> branch -> remote

use crate::snapshot_fs;
use agentfs_sdk::filesystem::{S_IFDIR, S_IFMT, S_IFREG};
use agentfs_sdk::{AgentFS, AgentFSOptions};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// VFS snapshot: path -> (mtime, mtime_nsec, size). Same shape the per-run
/// delta report uses; push reuses it as a persisted seed baseline.
pub(crate) type Snap = HashMap<String, (i64, u32, i64)>;

/// Sandbox-internal top-level dirs never pushed into a branch. The fresh
/// tmpfs mounts (/tmp /run /dev /proc /sys /var/tmp) never reach the VFS DB,
/// but agents can still write DB-backed dirs like /etc or /var — sandbox
/// noise, not repo content. /.git is the session's private git state; pushed
/// branches carry file changes only. A dir that existed in the seed baseline
/// overrides this list (a repo genuinely containing etc/ still pushes).
const PUSH_DENY: &[&str] = &[
    ".git", "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "media", "mnt", "opt",
    "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
];

/// Top-level component of a VFS path ("/src/x.rs" -> "src").
fn top_component(path: &str) -> Option<&str> {
    path.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
}

fn pushable(path: &str, baseline_tops: &HashSet<&str>) -> bool {
    let Some(top) = top_component(path) else {
        return false;
    };
    if top == ".git" {
        return false; // never: the session's private git state
    }
    baseline_tops.contains(top) || !PUSH_DENY.contains(&top)
}

/// (added_or_modified, deleted, dropped) vs the seed baseline. Pure —
/// unit-tested without a VFS. `dropped` holds changed paths excluded from
/// the push by sandbox-dir rules etc. — surface them so agents and users
/// aren't surprised by silently-vanishing files.
pub(crate) fn diff_snapshots(
    baseline: &Snap,
    now: &Snap,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let base_tops: HashSet<&str> = baseline.keys().filter_map(|p| top_component(p)).collect();
    let mut dropped: Vec<String> = now
        .iter()
        .filter(|(p, v)| !pushable(p, &base_tops) && baseline.get(*p) != Some(*v))
        .map(|(p, _)| p.clone())
        .collect();
    dropped.sort();
    let mut changed: Vec<String> = now
        .iter()
        .filter(|(p, v)| pushable(p, &base_tops) && baseline.get(*p) != Some(*v))
        .map(|(p, _)| p.clone())
        .collect();
    let mut deleted: Vec<String> = baseline
        .keys()
        .filter(|p| pushable(p, &base_tops) && !now.contains_key(*p))
        .cloned()
        .collect();
    changed.sort();
    deleted.sort();
    (changed, deleted, dropped)
}

/// Layered-session diff (docs/layered-sessions.md §3.7): the session's
/// delta IS its change set — no whole-tree snapshot walk. Pure, unit-tested.
///   `delta`      every delta entry (path -> attrs); changed candidates
///   `base`       base attrs for delta paths ∪ tombstone descendants
///                (None = not in base, i.e. brand-new)
///   `tombstones` tombstoned base-FILE paths: dir rows are expanded by the
///                caller to the files under them (git deletes files, not
///                dirs); an empty tombstoned dir contributes nothing
/// A path that is tombstoned AND delta-resident is a delete-then-recreate:
/// it counts as changed, not deleted.
pub(crate) fn diff_layers(
    baseline_tops: &[String],
    delta: &HashMap<String, (i64, u32, i64)>,
    base: &HashMap<String, Option<(i64, u32, i64)>>,
    tombstones: &HashSet<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let tops: HashSet<&str> = baseline_tops.iter().map(|s| s.as_str()).collect();
    let mut dropped: Vec<String> = delta
        .iter()
        .filter(|(p, attrs)| {
            !pushable(p, &tops) && base.get(*p).copied().flatten() != Some(**attrs)
        })
        .map(|(p, _)| p.clone())
        .collect();
    dropped.sort();
    let mut changed: Vec<String> = delta
        .iter()
        .filter(|(p, attrs)| {
            pushable(p, &tops)
                && match base.get(*p) {
                    Some(Some(ba)) => ba != *attrs, // copy-up + write
                    _ => true,                      // not in base: brand-new
                }
        })
        .map(|(p, _)| p.clone())
        .collect();
    changed.sort();
    let mut deleted: Vec<String> = tombstones
        .iter()
        .filter(|p| {
            !delta.contains_key(*p)
                && pushable(p, &tops)
                && base.get(*p).is_some_and(|b| b.is_some())
        })
        .cloned()
        .collect();
    deleted.sort();
    (changed, deleted, dropped)
}

/// Baseline serialization: one entry per line, `path\tmtime\tnsec\tsize`.
/// Paths containing \t or \n can't be represented (and can't be pushed
/// safely) — skipped here; snapshot_from_tsv drops them on read too.
pub(crate) fn snapshot_to_tsv(s: &Snap) -> String {
    let mut rows: Vec<String> = s
        .iter()
        .filter(|(p, _)| !p.contains('\t') && !p.contains('\n'))
        .map(|(p, (m, ns, z))| format!("{p}\t{m}\t{ns}\t{z}"))
        .collect();
    rows.sort();
    rows.join("\n")
}

pub(crate) fn snapshot_from_tsv(text: &str) -> Result<Snap> {
    let mut out = Snap::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let bad = || anyhow::anyhow!("seed.snapshot line {}: {line:?}", n + 1);
        let mut f = line.split('\t');
        let (p, m, ns, z) = match (f.next(), f.next(), f.next(), f.next(), f.next()) {
            (Some(p), Some(m), Some(ns), Some(z), None) => (p, m, ns, z),
            _ => return Err(bad()),
        };
        out.insert(
            p.to_string(),
            (
                m.parse::<i64>().map_err(|_| bad())?,
                ns.parse::<u32>().map_err(|_| bad())?,
                z.parse::<i64>().map_err(|_| bad())?,
            ),
        );
    }
    Ok(out)
}

/// Conservative git branch-name check.
fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && name != "HEAD"
        && !name.starts_with(['-', '/'])
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && !name.ends_with(".lock")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-@+".contains(&b))
}

fn git_io(dir: &Path, args: &[&str]) -> Result<(String, String)> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    let so = String::from_utf8_lossy(&out.stdout).into_owned();
    let se = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        bail!("git {} failed:\n{}", args.join(" "), se.trim());
    }
    Ok((so, se))
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    git_io(dir, args).map(|(so, _)| so)
}

/// Ok-or-none git probe (remote existence, repo detection).
fn git_probe(dir: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub(crate) struct PushOpts {
    pub branch: Option<String>,
    pub to: Option<PathBuf>,
    pub remote: Option<String>,
    pub message: Option<String>,
    pub dry_run: bool,
    pub keep: bool,
    pub pr: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PushOutcome {
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
    pub ignored: usize,
    pub status: String,
    pub branch: String,
    pub repo: PathBuf,
    /// Some when the worktree was kept (--keep, or dry-run --keep).
    pub worktree: Option<PathBuf>,
    /// Paths under sandbox-internal dirs (etc/, usr/, …) that were present
    /// but never pushed — counted so the drop isn't silent.
    pub dropped: usize,
    pub pushed: bool,
    /// Remote's own push message (GitHub prints its PR link here).
    pub push_note: String,
}

pub(crate) async fn push_session(
    sid: &str,
    session_dir: &Path,
    o: &PushOpts,
) -> Result<PushOutcome> {
    // Layered sessions diff base ∪ delta − tombstones (the delta IS the
    // change set); legacy sessions diff the whole fs.db against seed.snapshot.
    if session_dir.join("base").exists() {
        push_session_layered(sid, session_dir, o).await
    } else {
        push_session_legacy(sid, session_dir, o).await
    }
}

/// Base-tree file paths under the tombstoned `root` (git needs file-level
/// deletions; one dir row covers its whole subtree). Iterative, no box.
async fn collect_base_files(base: &AgentFS, root: &str, out: &mut HashSet<String>) {
    let mut stack = vec![root.to_string()];
    while let Some(dir) = stack.pop() {
        let Some(st) = base.fs.lstat(&dir).await.ok().flatten() else {
            continue;
        };
        if st.mode & S_IFMT != S_IFDIR {
            continue;
        }
        let names = base
            .fs
            .readdir(st.ino)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        for name in names {
            let child = format!("{dir}/{name}");
            if let Some(cs) = base.fs.lstat(&child).await.ok().flatten() {
                if cs.mode & S_IFMT == S_IFDIR {
                    stack.push(child);
                } else {
                    out.insert(child);
                }
            }
        }
    }
}

async fn push_session_layered(sid: &str, session_dir: &Path, o: &PushOpts) -> Result<PushOutcome> {
    let db = session_dir.join("fs.db");
    let agent =
        match AgentFS::open(AgentFSOptions::with_path(db.to_string_lossy().to_string())).await {
            Ok(a) => a,
            Err(e) => bail!("open {}: {e}", db.display()),
        };
    let base_db = std::fs::read_to_string(session_dir.join("base"))
        .with_context(|| format!("session {sid} has no readable base pointer"))?
        .trim()
        .to_string();
    let base = AgentFS::open(AgentFSOptions::with_path(base_db.clone()))
        .await
        .with_context(|| format!("open base {base_db}"))?;

    // delta entries (the change set)
    let mut delta: HashMap<String, (i64, u32, i64)> = HashMap::new();
    for p in agent.get_delta_paths().await? {
        if let Some(st) = agent.fs.lstat(&p).await.ok().flatten() {
            delta.insert(p, (st.mtime, st.mtime_nsec, st.size));
        }
    }
    // tombstones expanded to base files (dir rows cover their subtree)
    let rows = agent.get_whiteouts().await?;
    let mut tombstones: HashSet<String> = HashSet::new();
    for t in &rows {
        match base.fs.lstat(t).await.ok().flatten() {
            Some(st) if st.mode & S_IFMT == S_IFDIR => {
                collect_base_files(&base, t, &mut tombstones).await;
            }
            Some(_) => {
                tombstones.insert(t.clone());
            }
            None => {}
        }
    }
    // base attrs for delta paths ∪ tombstone descendants
    let tops = base.fs.readdir(1).await.ok().flatten().unwrap_or_default();
    let mut base_attrs: HashMap<String, Option<(i64, u32, i64)>> = HashMap::new();
    for p in delta.keys().chain(tombstones.iter()) {
        let attr = base
            .fs
            .lstat(p)
            .await
            .ok()
            .flatten()
            .map(|st| (st.mtime, st.mtime_nsec, st.size));
        base_attrs.insert(p.clone(), attr);
    }
    let (changed, deleted, dropped) = diff_layers(&tops, &delta, &base_attrs, &tombstones);
    if changed.is_empty() && deleted.is_empty() {
        if dropped.is_empty() {
            bail!("session {sid}: no file changes vs its seed baseline — nothing to push");
        }
        bail!(
            "session {sid}: no pushable changes — {} changed path(s) under sandbox-internal \
             dirs (etc/, usr/, …) are never pushed",
            dropped.len()
        );
    }

    // Contents come from the delta (copy-up already materialized them).
    let mut payload: Vec<(String, Vec<u8>)> = Vec::new();
    let mut ignored = 0usize;
    for p in &changed {
        match agent.fs.lstat(p).await.ok().flatten() {
            Some(s) if s.mode & S_IFMT == S_IFREG => {}
            _ => {
                ignored += 1;
                continue;
            }
        }
        match agent.fs.read_file(p).await.ok().flatten() {
            Some(bytes) => payload.push((p[1..].to_string(), bytes)),
            None => ignored += 1,
        }
    }
    drop(base);
    if payload.is_empty() && deleted.is_empty() {
        if dropped.is_empty() {
            bail!("session {sid}: only non-file changes — nothing pushable");
        }
        bail!(
            "session {sid}: no pushable file changes — sandbox-internal paths ({} dropped) \
             and non-file entries are never pushed",
            dropped.len()
        );
    }
    push_finish(
        sid,
        session_dir,
        o,
        payload,
        deleted,
        ignored,
        dropped.len(),
    )
    .await
}

/// Shared tail of both push paths: baseline-drift check, throwaway worktree,
/// apply + commit + push.
async fn push_finish(
    sid: &str,
    session_dir: &Path,
    o: &PushOpts,
    payload: Vec<(String, Vec<u8>)>,
    deleted: Vec<String>,
    ignored: usize,
    dropped: usize,
) -> Result<PushOutcome> {
    // Where do the changes land? --to wins; else the session's recorded cwd.
    let repo = match &o.to {
        Some(d) => d.clone(),
        None => PathBuf::from(
            std::fs::read_to_string(session_dir.join("base_path"))
                .with_context(|| format!("no base_path for session {sid}; pass --to <repo-dir>"))?
                .trim(),
        ),
    };
    if git_probe(&repo, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        bail!(
            "{} is not a git repository — pass --to <repo-dir>",
            repo.display()
        );
    }
    // Baseline-vs-HEAD drift: the payload diffs against the seed-time tree,
    // but the worktree below is cut from the host's HEAD *now*. If the host
    // repo advanced since seeding, its commits land on the branch and
    // agent-touched files may overwrite newer host content — say so.
    if let Ok(sha) = std::fs::read_to_string(session_dir.join("seed.sha")) {
        if !sha.trim().is_empty()
            && git_probe(&repo, &["rev-parse", "HEAD"]).as_deref() != Some(sha.trim())
        {
            eprintln!(
                "den: warning: {} has advanced past the session's seed commit — \
                 host-side commits since seeding are folded into the branch",
                repo.display()
            );
        }
    }
    let branch = o.branch.clone().unwrap_or_else(|| format!("den/{sid}"));
    if !valid_branch(&branch) {
        bail!("invalid branch name {branch:?}");
    }
    let wt = std::env::temp_dir().join(format!(
        "den-push-{}-{}",
        sid.replace('/', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .subsec_nanos()
    ));
    let res = push_apply(
        &repo, &wt, &branch, &payload, &deleted, ignored, dropped, sid, o,
    );
    if !o.keep {
        // Throwaway worktree — the commit lives in the repo's object store.
        let _ = Command::new("git")
            .current_dir(&repo)
            .args(["worktree", "remove", "--force", &wt.to_string_lossy()])
            .output();
        let _ = Command::new("git")
            .current_dir(&repo)
            .args(["worktree", "prune"])
            .output();
    }
    res
}

pub(crate) async fn push_session_legacy(
    sid: &str,
    session_dir: &Path,
    o: &PushOpts,
) -> Result<PushOutcome> {
    let db = session_dir.join("fs.db");
    if !db.exists() {
        bail!("no fs.db for session {sid} — nothing to push");
    }
    let agent =
        match AgentFS::open(AgentFSOptions::with_path(db.to_string_lossy().to_string())).await {
            Ok(a) => a,
            Err(e) => bail!("open {}: {e}", db.display()),
        };
    let base_text =
        std::fs::read_to_string(session_dir.join("seed.snapshot")).with_context(|| {
            format!(
                "session {sid} has no seed.snapshot (created before seed baselines); \
             re-seed with DEN_NEW=1 to push"
            )
        })?;
    let baseline = snapshot_from_tsv(&base_text)?;
    let now = snapshot_fs(&agent).await;
    let (changed, deleted, dropped) = diff_snapshots(&baseline, &now);
    if changed.is_empty() && deleted.is_empty() {
        if dropped.is_empty() {
            bail!("session {sid}: no file changes vs its seed baseline — nothing to push");
        }
        bail!(
            "session {sid}: no pushable changes — {} changed path(s) under sandbox-internal \
             dirs (etc/, usr/, …) are never pushed",
            dropped.len()
        );
    }

    // Copy contents out of the VFS before any host-side git work: a failure
    // here must not strand a half-applied worktree. Non-regular files (dirs,
    // symlinks) aren't pushed — branches carry file changes only.
    let mut payload: Vec<(String, Vec<u8>)> = Vec::new();
    let mut ignored = 0usize;
    for p in &changed {
        match agent.fs.lstat(p).await.ok().flatten() {
            Some(s) if s.mode & S_IFMT == S_IFREG => {}
            _ => {
                ignored += 1;
                continue;
            }
        }
        match agent.fs.read_file(p).await.ok().flatten() {
            Some(bytes) => payload.push((p[1..].to_string(), bytes)),
            None => ignored += 1,
        }
    }
    drop(agent);
    if payload.is_empty() && deleted.is_empty() {
        if dropped.is_empty() {
            bail!("session {sid}: only non-file changes — nothing pushable");
        }
        bail!(
            "session {sid}: no pushable file changes — sandbox-internal paths ({} dropped) \
             and non-file entries are never pushed",
            dropped.len()
        );
    }

    push_finish(
        sid,
        session_dir,
        o,
        payload,
        deleted,
        ignored,
        dropped.len(),
    )
    .await
}

/// Apply the delta to a fresh worktree of `repo`, then commit + push.
#[allow(clippy::too_many_arguments)]
fn push_apply(
    repo: &Path,
    wt: &Path,
    branch: &str,
    payload: &[(String, Vec<u8>)],
    deleted: &[String],
    ignored: usize,
    dropped: usize,
    sid: &str,
    o: &PushOpts,
) -> Result<PushOutcome> {
    let wt_s = wt.to_string_lossy().to_string();
    git(repo, &["worktree", "add", "--detach", &wt_s, "HEAD"])?;
    // The throwaway worktree root under shared /tmp — keep it private.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(wt, std::fs::Permissions::from_mode(0o700));
    }
    for (rel, bytes) in payload {
        let dst = wt.join(rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        std::fs::write(&dst, bytes).with_context(|| format!("write {}", dst.display()))?;
    }
    for p in deleted {
        // Silent failure is intentional: an already-absent worktree file
        // (or an unfriendly host) shouldn't abort the push.
        let _ = std::fs::remove_file(wt.join(&p[1..]));
    }
    let status = git(wt, &["status", "--porcelain"])?;
    let mut pushed = false;
    let mut note = String::new();
    if !o.dry_run {
        // -B, not -b: a re-push after a partial failure (committed but not
        // pushed) would otherwise die on "branch already exists". The branch
        // tip resets to this worktree; pushing a reset branch stays safe —
        // a non-fast-forward is rejected by the remote.
        git(wt, &["checkout", "-B", branch])?;
        git(wt, &["add", "-A"])?;
        let msg = o.message.clone().unwrap_or_else(|| {
            format!(
                "den: session {sid} — {} file(s) changed, {} deleted",
                payload.len(),
                deleted.len()
            )
        });
        // Fixed identity: the session's work is attributed to den, not to
        // whatever git config happens to exist on the host.
        git(
            wt,
            &[
                "-c",
                "user.name=den",
                "-c",
                "user.email=den@den.local",
                "commit",
                "-m",
                &msg,
                "--quiet",
            ],
        )?;
        let remote = o.remote.as_deref().unwrap_or("origin");
        if git_probe(wt, &["remote", "get-url", remote]).is_none() {
            bail!(
                "no git remote '{remote}' in {} — add one or pass --remote <name>",
                repo.display()
            );
        }
        let (_so, se) = git_io(wt, &["push", remote, branch])?;
        pushed = true;
        note = se;
        if o.pr {
            let out = Command::new("gh")
                .current_dir(wt)
                .args(["pr", "create", "--fill", "--head", branch])
                .output()
                .context("run gh (is the GitHub CLI installed?)")?;
            if !out.status.success() {
                bail!(
                    "branch {branch} was pushed, but `gh pr create` failed:\n{}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            note.push_str(&String::from_utf8_lossy(&out.stdout));
        }
    }
    Ok(PushOutcome {
        changed: payload.iter().map(|(p, _)| format!("/{p}")).collect(),
        deleted: deleted.to_vec(),
        ignored,
        dropped,
        status,
        branch: branch.to_string(),
        repo: repo.to_path_buf(),
        worktree: o.keep.then(|| wt.to_path_buf()),
        pushed,
        push_note: note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_on, seed_session, seed_tree};

    type Attr = (i64, u32, i64);
    type Pair<'a> = (&'a str, Attr);
    type OptPair<'a> = (&'a str, Option<Attr>);
    type AttrMap = HashMap<String, Attr>;
    type OptAttrMap = HashMap<String, Option<Attr>>;

    fn snap(pairs: &[Pair<'_>]) -> Snap {
        pairs.iter().map(|(p, v)| (p.to_string(), *v)).collect()
    }

    fn hm(pairs: &[OptPair<'_>]) -> OptAttrMap {
        pairs.iter().map(|(p, v)| (p.to_string(), *v)).collect()
    }

    fn hmb(pairs: &[Pair<'_>]) -> AttrMap {
        pairs.iter().map(|(p, v)| (p.to_string(), *v)).collect()
    }

    #[test]
    fn diff_semantics() {
        // Repo without an etc/ dir: /etc, /tmp junk is excluded; /.git always.
        let base = snap(&[
            ("/a.txt", (1, 0, 3)),
            ("/src/b.txt", (1, 0, 4)),
            ("/gone.txt", (1, 0, 5)),
            ("/README.md", (1, 0, 6)),
            ("/.git/config", (1, 0, 9)),
        ]);
        let now = snap(&[
            ("/a.txt", (2, 0, 3)),
            ("/src/b.txt", (1, 0, 4)),
            ("/README.md", (1, 0, 6)),
            ("/docs2/new.md", (3, 0, 7)),
            ("/.git/config", (9, 0, 9)),
            ("/etc/hosts", (4, 0, 8)),
            ("/tmp/junk", (4, 0, 1)),
        ]);
        let (changed, deleted, dropped) = diff_snapshots(&base, &now);
        assert_eq!(changed, vec!["/a.txt", "/docs2/new.md"]);
        assert_eq!(deleted, vec!["/gone.txt"]);
        // Sandbox-internal paths that changed after seeding are reported,
        // not swallowed.
        assert_eq!(dropped, vec!["/.git/config", "/etc/hosts", "/tmp/junk"]);

        // A repo that genuinely has etc/ pushes changes under it.
        let base2 = snap(&[("/etc/keep", (1, 0, 2))]);
        let now2 = snap(&[("/etc/hosts", (4, 0, 8))]);
        let (changed2, _, _) = diff_snapshots(&base2, &now2);
        assert_eq!(changed2, vec!["/etc/hosts"]);
    }

    #[test]
    fn diff_layers_semantics() {
        let tops: Vec<String> = vec!["src".into(), "pkg".into()];
        // delta: /src/lib.rs written (copy-up + write), /pkg/new created,
        // /etc/x changed (sandbox-internal → dropped), /src/gone deleted
        // (tombstone; its dir variant expanded by the caller), and a
        // delete-then-recreate of /src/again.txt (tombstone + delta entry)
        let delta = hmb(&[
            ("/src/lib.rs", (200, 1, 10)),
            ("/pkg/new", (300, 0, 4)),
            ("/etc/x", (400, 0, 99)),
            ("/src/back", (500, 0, 3)),
        ]);
        let mut base = hm(&[
            ("/src/lib.rs", Some((100, 0, 9))),
            ("/pkg/new", None),
            ("/etc/x", Some((50, 0, 1))),
            ("/src/old.rs", Some((10, 0, 5))),
            ("/src/back", Some((90, 0, 2))),
        ]);
        base.insert("/src/deleted-dir".to_string(), Some((1, 0, 0)));
        base.insert("/src/deleted-dir/a.txt".to_string(), Some((1, 0, 2)));
        base.insert("/src/gone".to_string(), Some((7, 0, 1)));
        // tombstones as the caller builds them: the dir row expanded to its
        // base files (the dir row itself is not a file to delete)
        let tombstones: HashSet<String> = [
            "/src/deleted-dir/a.txt".to_string(),
            "/src/gone".to_string(),
            "/src/back".to_string(), // tombstone AND delta-resident
        ]
        .into();
        let (changed, deleted, dropped) = diff_layers(&tops, &delta, &base, &tombstones);
        assert_eq!(changed, vec!["/pkg/new", "/src/back", "/src/lib.rs"]);
        // the recreated path stays out of deletions; the tombstoned dir's
        // base files land there expanded
        assert_eq!(deleted, vec!["/src/deleted-dir/a.txt", "/src/gone"]);
        assert_eq!(dropped, vec!["/etc/x"]);
    }

    #[test]
    fn tsv_roundtrip() {
        let s = snap(&[("/a b.txt", (1, 2, 3)), ("/x/y.bin", (7, 999, 0))]);
        assert_eq!(snapshot_from_tsv(&snapshot_to_tsv(&s)).unwrap(), s);
        let r = snapshot_from_tsv(&snapshot_to_tsv(&s)).unwrap();
        assert!(
            diff_snapshots(&r, &s).0.is_empty()
                && diff_snapshots(&r, &s).1.is_empty()
                && diff_snapshots(&r, &s).2.is_empty()
        );
        assert_eq!(snapshot_from_tsv("").unwrap().len(), 0);
        assert!(snapshot_from_tsv("a\tb").is_err());
        // \t in a path can't round-trip — must not be silently corrupted.
        let s2 = snap(&[("/we\tird", (1, 0, 1))]);
        assert_eq!(snapshot_from_tsv(&snapshot_to_tsv(&s2)).unwrap().len(), 0);
    }

    #[test]
    fn branch_names() {
        assert!(valid_branch("den/my-session-1"));
        assert!(valid_branch("den/feat.x_y"));
        assert!(!valid_branch(""));
        assert!(!valid_branch("-evil"));
        assert!(!valid_branch("a..b"));
        assert!(!valid_branch("HEAD"));
        assert!(!valid_branch("x.lock"));
        assert!(!valid_branch("has space"));
    }

    fn g(dir: &Path, args: &[&str]) {
        let mut all: Vec<&str> = vec!["-c", "user.name=t", "-c", "user.email=t@t"];
        all.extend_from_slice(args);
        let out = Command::new("git")
            .current_dir(dir)
            .args(&all)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn push_e2e() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let root = std::env::temp_dir().join(format!("den-push-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Host repo with one commit and a bare origin.
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("README.md"), "hi\n").unwrap();
        std::fs::write(repo.join("src/lib.rs"), "fn a() {}\n").unwrap();
        g(&repo, &["init"]);
        g(&repo, &["add", "-A"]);
        g(&repo, &["commit", "-m", "init", "--quiet"]);
        let origin = root.join("origin.git");
        g(&root, &["init", "--bare", origin.to_str().unwrap()]);
        g(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );

        // Session: seed repo + .git like a real run, record baseline + cwd.
        let sd = root.join("sess");
        std::fs::create_dir_all(&sd).unwrap();
        let before = block_on(async {
            let opts = AgentFSOptions::with_path(sd.join("fs.db").to_string_lossy().to_string());
            let agent = AgentFS::open(opts).await.unwrap();
            seed_session(&agent, &repo, Some(&repo.join(".git")))
                .await
                .unwrap();
            let snap = snapshot_fs(&agent).await;
            drop(agent);
            snap
        })
        .unwrap();
        std::fs::write(sd.join("seed.snapshot"), snapshot_to_tsv(&before)).unwrap();
        std::fs::write(sd.join("base_path"), repo.to_str().unwrap()).unwrap();

        // Agent work: edit a file, delete one, add one (via a second seed dir,
        // the established way to put new files into a VFS in tests).
        let extra = root.join("extra");
        std::fs::create_dir_all(extra.join("docs2")).unwrap();
        std::fs::write(extra.join("docs2/new.md"), "new\n").unwrap();
        block_on(async {
            let opts = AgentFSOptions::with_path(sd.join("fs.db").to_string_lossy().to_string());
            let agent = AgentFS::open(opts).await.unwrap();
            agent
                .fs
                .pwrite("/src/lib.rs", 0, b"fn b() {}\n")
                .await
                .unwrap();
            agent.fs.remove("/README.md").await.unwrap();
            seed_tree(&agent, &extra, PathBuf::new()).await.unwrap();
            drop(agent);
        })
        .unwrap();

        // 1) dry-run, keep: apply to a worktree, commit nothing, push nothing.
        let o = PushOpts {
            branch: None,
            to: None,
            remote: None,
            message: None,
            dry_run: true,
            keep: true,
            pr: false,
        };
        let out = block_on(push_session("push-e2e", &sd, &o))
            .unwrap()
            .unwrap();
        let wt = out.worktree.clone().unwrap();
        assert_eq!(
            std::fs::read_to_string(wt.join("src/lib.rs")).unwrap(),
            "fn b() {}\n"
        );
        assert!(!wt.join("README.md").exists());
        assert_eq!(
            std::fs::read_to_string(wt.join("docs2/new.md")).unwrap(),
            "new\n"
        );
        assert_eq!(out.branch, "den/push-e2e");
        assert!(!out.pushed);
        let _ = Command::new("git")
            .current_dir(&repo)
            .args(["worktree", "remove", "--force", wt.to_str().unwrap()])
            .output();

        // 2) real push: branch lands on the bare remote and in the host repo.
        let o = PushOpts {
            branch: Some("den/feature".into()),
            to: None,
            remote: None,
            message: None,
            dry_run: false,
            keep: false,
            pr: false,
        };
        let out = block_on(push_session("push-e2e", &sd, &o))
            .unwrap()
            .unwrap();
        assert!(out.pushed);
        assert!(out.worktree.is_none());
        assert_eq!(out.branch, "den/feature");
        g(
            &origin,
            &["rev-parse", "--verify", "refs/heads/den/feature"],
        );
        g(&repo, &["rev-parse", "--verify", "refs/heads/den/feature"]);

        let _ = std::fs::remove_dir_all(&root);
    }
}
