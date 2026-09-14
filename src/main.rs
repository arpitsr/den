//! den — run any local coding-agent CLI inside an AgentFS sandbox, with typed
//! SDK access to what it did.
//!
//! The sandbox is in-process (src/sandbox.rs, ported from the agentfs CLI,
//! MIT): a FUSE mount (src/fuse.rs, via the published `fuser` crate) serves
//! the session's virtual filesystem — a SQLite DB at
//! ~/.den/sessions/<sid>/fs.db that IS the whole filesystem (no host base,
//! no overlay). New sessions start empty or seeded from a dir (`--seed`;
//! git-aware: repo history is seeded as /.git, and a dirty worktree seeds
//! HEAD by default — see README "Seeding"); resumed sessions open the DB
//! and nothing else. A fork+unshare child gets
//! a fresh user+mount namespace with the rest of the filesystem read-only.
//! After the agent exits we diff a pre/post snapshot of the virtual FS and
//! report what this run touched.
//!
//! Usage:
//!   den <cmd> [args...]         run any agent CLI in the sandbox; print delta after
//!   den dump <cmd> [args...]    print the resolved sandbox plan (no exec)
//!   den inspect <session-id>     open a session's fs.db and show diff+timeline
//!   den sessions                 list persisted sessions under ~/.den/sessions
//!   den replicate [sid] [url]    litestream daemon: stream the fs.db to S3 continuously
//!   den pull [sid] [url]         restore a session's fs.db from the litestream replica
//!   den list                     list known profiles (any other cmd works too)
//!   den selftest                 sanity-check argv assembly
//!
//! Env:
//!   DEN_SESSION=<id>  reuse/resume this session id (default <profile>-<cwd-slug>)
//!   DEN_NEW=1         start a fresh unique session id like <profile>-<cwd-slug>-<5 chars>
//!   DEN_QUIET=1       don't print the post-run delta summary
//!   DEN_LITESTREAM=<bin>  path to the litestream binary (default: litestream on PATH)
//!   DEN_REPLICA=<url>    replica URL (default: LITESTREAM_REPLICA_URL, then LITESTREAM_BUCKET)
//!   DEN_DETACHED=1  (internal) spawned detached by --autostart; survives Ctrl-C on the run
//!   DEN_NET=proxy|none|full  network isolation (default proxy): slirp4netns netns +
//!     nft egress policy + allowlist proxy (see DEN_PROXY_ALLOW); none = netns only,
//!     full = host network (legacy)
//!   DEN_PROXY_ALLOW=comma,list  extra egress allowlist entries for DEN_NET=proxy
//!   DEN_PROXY_POLICY=path.yaml  egress allow/deny lists (else ./den-egress.yaml if present;
//!     schema: src/default-egress.yaml); deny wins
//!   DEN_HIDE=~/.a:~/.b  extra secrets to hide (colon-separated); DEN_NO_HIDE=~/.ssh restores
//!   DEN_LIMIT_FSIZE/NOFILE/NPROC/AS/CPU  agent rlimits (bytes or K/M/G; "unlimited")
//!   DEN_SECCOMP=0    disable the seccomp syscall deny-list (not recommended)
//!   (writable defaults: the four XDG base dirs plus the legacy agent
//!    dotdirs — see build_allowed_paths in src/sandbox.rs)

use crate::layer::read_key_json;
use agentfs_sdk::filesystem::{S_IFDIR, S_IFMT};
use agentfs_sdk::{AgentFS, AgentFSOptions, ToolCall};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

mod backup;
#[cfg(target_os = "linux")]
mod fuse;
mod layer;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod policy;
mod proxy;
pub(crate) mod push;
#[cfg(target_os = "linux")]
mod sandbox;

#[derive(Clone)]
struct Profile {
    cmd: Vec<String>,
    allows: Vec<String>, // extra host dirs to keep writable inside the sandbox
}

/// Profile for a command name. Every name is valid: known agents just get
/// extra host dirs kept writable (`~/.config` is the default for all), and
/// unknown ones run as-is — `den any-cli args...` wraps any agent.
fn profile(name: &str) -> Profile {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut allows = vec![format!("{home}/.config")];
    let extra: &[&str] = match name {
        "ak" => &[".ak"],
        "pi" => &[".pi"],
        "opencode" => &[".opencode"],
        _ => &[],
    };
    allows.extend(extra.iter().map(|d| format!("{home}/{d}")));
    Profile {
        cmd: vec![name.into()],
        allows,
    }
}

/// Known agent names (for `den list`); any other command works too — these
/// are just the ones that get extra writable dirs in profile().
fn list_profiles() -> Vec<&'static str> {
    let mut v = ["ak", "claude", "codex", "gemini", "opencode", "pi"];
    v.sort();
    v.to_vec()
}

/// lowercased, alnum, hyphen-joined basename — mirrors the bash slug()
fn slug(p: &str) -> String {
    let base = p.rsplit('/').next().unwrap_or(p);
    let mut out = String::new();
    for c in base.to_lowercase().chars() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn new_uuid() -> String {
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/uuid") {
        return s.trim().to_string();
    }
    // fallback: time-based, not a real uuid but unique enough for a session id
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sid-{nanos:x}")
}

/// Random lowercase-alphanumeric suffix (like a k8s pod suffix). 5 chars
/// gives ~60M combinations, which is plenty for a session id.
fn random_suffix(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    if File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback: reuse the UUID hex (very unlikely on Linux)
        let hex = new_uuid().replace('-', "");
        return hex.chars().take(len).collect();
    }
    buf.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}

/// session id: DEN_SESSION wins, else DEN_NEW=1 -> fresh k8s-style id, else <profile>-<cwd-slug>
fn session_id(profile: &str) -> String {
    if let Ok(s) = std::env::var("DEN_SESSION") {
        if !s.is_empty() {
            return s;
        }
    }
    // DEN_NEW=1 — and every nested run (§7): a subagent spawning a subagent
    // must not collide on the deterministic <profile>-<cwd-slug> id.
    if std::env::var("DEN_NEW").as_deref() == Ok("1") || nested_run() {
        return format!("{}-{}-{}", profile, slug(&cwd_string()), random_suffix(5));
    }
    format!("{}-{}", profile, slug(&cwd_string()))
}

fn litestream_bin() -> String {
    std::env::var("DEN_LITESTREAM").unwrap_or_else(|_| "litestream".to_string())
}

/// true if `bin` is an existing path itself, or resolves on PATH
fn bin_found(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).exists();
    }
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

/// Resolve a bare command name to the first executable found on PATH.
/// Absolute/relative paths are returned unchanged.
fn resolve_bin(bin: &str) -> PathBuf {
    if bin.contains('/') {
        return PathBuf::from(bin);
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(bin)
}

/// Replica URL for a session's fs.db: explicit arg wins, then
/// DEN_REPLICA, then LITESTREAM_REPLICA_URL, then LITESTREAM_BUCKET with a
/// per-session path. Credentials are litestream's business (AWS_*/LITESTREAM_*
/// env vars — command-line mode, see https://litestream.io/reference/replicate/).
fn replica_url(sid: &str, explicit: Option<&str>) -> Result<String> {
    if let Some(u) = explicit {
        return Ok(u.to_string());
    }
    for var in ["DEN_REPLICA", "LITESTREAM_REPLICA_URL"] {
        if let Ok(u) = std::env::var(var) {
            if !u.is_empty() {
                return Ok(u);
            }
        }
    }
    if let Ok(b) = std::env::var("LITESTREAM_BUCKET") {
        if !b.is_empty() {
            return Ok(format!("s3://{b}/{sid}/db"));
        }
    }
    bail!(
        "no replica configured — set DEN_REPLICA=s3://bucket/path, \
         LITESTREAM_REPLICA_URL, or LITESTREAM_BUCKET"
    )
}

/// true when `--autostart` should stream via litestream instead of the LTX watch
fn litestream_autostart(sid: &str) -> bool {
    bin_found(&litestream_bin()) && replica_url(sid, None).is_ok()
}

/// ~/.den/sessions — where sessions (and their fs.db files) persist
pub(crate) fn run_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".den/sessions"))
}

/// True inside a sandboxed agent that spawned another den (§7 nesting): the
/// inner den keeps its session state inside the OUTER virtual filesystem.
pub(crate) fn nested_run() -> bool {
    std::env::var("AGENTFS").as_deref() == Ok("1")
}

/// Where session dirs live: ~/.den/sessions on the host, or `<cwd>/.den`
/// inside the outer VFS for nested runs (the only writable tree there).
pub(crate) fn sessions_root() -> Result<PathBuf> {
    if nested_run() {
        return Ok(std::env::current_dir()?.join(".den"));
    }
    run_dir()
}

/// DEN_LAYER=0 forces the legacy per-session seed path (§6 kill switch).
pub(crate) fn layers_enabled() -> bool {
    std::env::var("DEN_LAYER").as_deref() != Ok("0")
}

/// Where shared bases live: ~/.den/bases on the host, `<cwd>/.den/bases`
/// inside the outer VFS for nested runs.
pub(crate) fn bases_root() -> Result<PathBuf> {
    if nested_run() {
        return Ok(std::env::current_dir()?.join(".den/bases"));
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".den/bases"))
}

fn cwd_string() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

/// Run one future on a throwaway runtime (sync CLI entry points).
/// Note: if the future itself returns Result, you need `??` at the call site.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> Result<F::Output> {
    Ok(tokio::runtime::Runtime::new()?.block_on(f))
}

/// Reuse-or-recreate gate for the persisted session dir.
///
/// `agentfs run --session X` silently JOINS an existing session and ignores
/// the --allow flags we pass, so a session created with a different config
/// (e.g. before we added ~/.pi to the allowlist) must be recreated — else the
/// agent hits EROFS on the missing path. But the session dir also holds the
/// fs.db, i.e. every change the agent made; deleting it unconditionally
/// throws that work away. So:
///
///   config unchanged               -> join the session, data survives
///   config changed, fs.db empty    -> delete, start fresh
///   config changed, fs.db has work -> archive (rename aside), never delete
///
/// "Config" = cwd + effective --allow list, stamped to .stamps/<sid>.
/// DEN_NO_DROP=1 keeps the old join-blind behaviour.
fn drop_stale_session(sid: &str, allows: &[String]) -> Result<()> {
    if std::env::var("DEN_NO_DROP").as_deref() == Ok("1") || nested_run() {
        // nested sessions live inside the outer VFS (no host stamp, no
        // archive-or-drop gate); they join blindly, like DEN_NO_DROP=1
        return Ok(());
    }
    let run_dir = run_dir()?;
    let dir = run_dir.join(sid);
    // The stamp carries the pinned base key too: a config change that would
    // seed a different base must archive the session (§3.7 join/resume).
    let base_key = session_base_db(sid)?
        .and_then(|p| {
            p.parent()
                .and_then(|d| d.file_name().map(|n| n.to_string_lossy().to_string()))
        })
        .unwrap_or_default();
    let stamp = format!("{}\n{}\n{}", cwd_string(), allows.join("\n"), base_key);
    let stamp_path = run_dir.join(".stamps").join(sid);

    if dir.exists() {
        let stored = std::fs::read_to_string(&stamp_path).ok();
        let same = stored.as_deref() == Some(stamp.as_str())
            // pre-layer stamps ("cwd\nallows", no base line) match legacy
            // sessions — don't archive them just for the format change
            || (base_key.is_empty()
                && stored.as_deref() == Some(format!("{}\n{}", cwd_string(), allows.join("\n")).as_str()));
        if same {
            return Ok(()); // same config — join, keeping the previous fs.db
        }
        unmount_stale(&dir.join("mnt"));
        if session_has_changes(&dir) {
            // ponytail: archives are never GC'd — rm ~/.den/sessions/*.archived-* by hand
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let name = format!("{sid}.archived-{ts}");
            unpin_session_base(sid);
            std::fs::rename(&dir, run_dir.join(&name))
                .with_context(|| format!("archive session {sid}"))?;
            eprintln!("den: config changed — archived previous session as {name} (den inspect {name} to view)");
        } else {
            unpin_session_base(sid);
            std::fs::remove_dir_all(&dir).with_context(|| format!("drop stale session {sid}"))?;
            eprintln!("den: dropped stale session {sid} (config changed, nothing to keep)");
        }
    }

    if let Some(parent) = stamp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&stamp_path, stamp)?;
    Ok(())
}

/// A previous run may have left a stale FUSE mount on <dir>/mnt (crash,
/// timeout, Ctrl-C cleanup race). Unmount before touching the dir, else the
/// kernel keeps a mount attached to a dead path and the next session at that
/// path fails with ENOENT.
fn unmount_stale(mnt: &Path) {
    if !mnt.exists() {
        return;
    }
    // `fusermount -uz` (lazy unmount); fall back to `umount -l`.
    let unmounted = Command::new("fusermount")
        .args(["-uz", &mnt.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !unmounted {
        let _ = Command::new("umount")
            .args(["-l", &mnt.to_string_lossy()])
            .status();
    }
}

/// True if the session's DB holds anything (an empty virtual FS is worthless).
/// Fails closed (true) so an unreadable DB gets archived, not deleted.
fn session_has_changes(dir: &Path) -> bool {
    let db = dir.join("fs.db");
    if !db.exists() {
        return false;
    }
    let check = async {
        let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
        match AgentFS::open(opts).await {
            Ok(a) => match a.fs.readdir(1).await {
                Ok(Some(names)) => !names.is_empty(),
                _ => true,
            },
            Err(_) => true,
        }
    };
    match tokio::runtime::Runtime::new() {
        Ok(rt) => rt.block_on(check),
        Err(_) => true, // can't build a runtime -> treat as "has changes"
    }
}

/// profile allow dirs that actually exist on this host (missing ones are skipped)
fn effective_allows(p: &Profile) -> Vec<String> {
    p.allows
        .iter()
        .filter(|a| Path::new(a).exists())
        .cloned()
        .collect()
}

/// The argv we exec inside the sandbox (command + passthrough). Used by run,
/// dump, selftest.
fn build_argv(profile_name: &str, passthrough: &[String]) -> Result<Vec<String>> {
    let p = profile(profile_name);
    let mut v = p.cmd.clone();
    // pi: default the session display name to the cwd slug so it's findable
    // in `pi -r`. Skip on resume/continue/session or an explicit --name —
    // renaming a session you're resuming would be a surprise.
    if profile_name == "pi"
        && !passthrough.iter().any(|a| {
            matches!(
                a.as_str(),
                "-c" | "--continue"
                    | "-r"
                    | "--resume"
                    | "--session"
                    | "-n"
                    | "--name"
                    | "--no-session"
            )
        })
    {
        v.push("--name".into());
        v.push(slug(&cwd_string()));
    }
    for a in passthrough {
        v.push(a.clone());
    }
    Ok(v)
}

// ---- AgentFS SDK: open a persisted session fs.db --------------------------
/// ~/.den/sessions/<sid>/fs.db — the session's persisted virtual filesystem
pub(crate) fn session_db_path(sid: &str) -> Result<PathBuf> {
    Ok(sessions_root()?.join(sid).join("fs.db"))
}

/// The session's pinned base DB, or None (legacy/delta-only session).
pub(crate) fn session_base_db(sid: &str) -> Result<Option<PathBuf>> {
    let p = sessions_root()?.join(sid).join("base");
    match std::fs::read_to_string(&p) {
        Ok(t) if !t.trim().is_empty() => Ok(Some(PathBuf::from(t.trim()))),
        _ => Ok(None),
    }
}

/// Open the session's virtual filesystem via the SDK. Returns None if the DB
/// isn't there (e.g. the run never happened or the SDK failed before writing it).
async fn open_session(sid: &str) -> Result<Option<AgentFS>> {
    let p = session_db_path(sid)?;
    if !p.exists() {
        return Ok(None);
    }
    let opts = AgentFSOptions::with_path(p.to_string_lossy().to_string());
    match AgentFS::open(opts).await {
        Ok(a) => Ok(Some(a)),
        Err(e) => bail!("open fs.db for session {sid}: {e}"),
    }
}

// ---- virtual FS: seed + snapshot --------------------------------------------

/// Names never copied into a session when seeding (dep/build dirs). Note:
/// `.git` is NOT excluded here — for a git repo the session's `/.git` is
/// seeded on purpose (see `seed_session`), and this walk of the repo root
/// skips its `.git` dir so it is copied exactly once.
const SEED_EXCLUDES: &[&str] = &[".git", "node_modules", "target"];

/// Copy a host dir into the session's virtual FS. Returns entry count.
/// `git_dir`, when given (a git repo's `.git`), is copied in as `/.git` so the
/// agent gets real git context — diff, log, branch — all private to the
/// session; the host repo is never touched. The copy ships with backup/
/// replicate like everything else in the session DB.
/// ponytail: whole-file reads; chunk pwrite if giant binaries ever matter.
pub(crate) async fn seed_session(
    agent: &AgentFS,
    dir: &Path,
    git_dir: Option<&Path>,
) -> Result<u64> {
    let mut count = seed_tree(agent, dir, PathBuf::new()).await?;
    if let Some(g) = git_dir {
        count += seed_tree(agent, g, PathBuf::from(".git")).await?;
        scrub_git_config(agent).await?;
    }
    Ok(count)
}

/// The seeded `/.git` ships with the session (`den backup`), and git state
/// often embeds host credentials:
///   - remote URLs in `.git/config`: `https://user:token@host/...`
///   - `.git/FETCH_HEAD`: git writes the full fetch URL per ref line
///   - `.git/modules/*/config`: submodule remotes carry the same URLs
///   - `http.<url>.extraheader` in config: CI tooling injects auth headers
///
/// Strip or drop all of it — the sandbox session needs no network access.
async fn scrub_git_config(agent: &AgentFS) -> Result<()> {
    scrub_config_file(agent, "/.git/config").await?;
    // FETCH_HEAD records the fetch URL (with userinfo, for tokened remotes)
    // per fetched ref — and it's junk info for the sandbox anyway.
    let _ = agent.fs.remove("/.git/FETCH_HEAD").await;
    // Submodule configs hide one or two levels down — walk /.git/modules.
    let mut stack = vec!["/.git/modules".to_string()];
    while let Some(dir) = stack.pop() {
        let Some(st) = agent.fs.stat(&dir).await? else {
            continue;
        };
        if st.mode & S_IFMT != S_IFDIR {
            continue;
        }
        let entries = agent.fs.readdir(st.ino).await?.unwrap_or_default();
        for e in entries {
            let p = format!("{dir}/{e}");
            if let Some(es) = agent.fs.lstat(&p).await.ok().flatten() {
                if es.mode & S_IFMT == S_IFDIR {
                    stack.push(p);
                } else if e == "config" {
                    scrub_config_file(agent, &p).await?;
                }
            }
        }
    }
    Ok(())
}

/// Scrub one git config file in the VFS by rewriting its own bytes. No
/// file, or file that isn't text: nothing to do.
async fn scrub_config_file(agent: &AgentFS, path: &str) -> Result<()> {
    let Some(data) = agent.fs.read_file(path).await? else {
        return Ok(());
    };
    let Ok(text) = std::str::from_utf8(&data) else {
        return Ok(());
    };
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        if scrub_drop_line(line) {
            changed = true;
            continue;
        }
        match scrub_url_creds(line) {
            Some(s) => {
                changed = true;
                out.push_str(&s);
            }
            None => out.push_str(line),
        }
    }
    if changed {
        agent.fs.pwrite(path, 0, out.as_bytes()).await?;
        if out.len() < data.len() {
            agent.fs.truncate(path, out.len() as u64).await?;
        }
    }
    Ok(())
}

/// Config lines dropped entirely. `extraheader` keys carry injected HTTP
/// auth headers (e.g. `AUTHORIZATION: basic ***` from CI checkouts); keys
/// like `http.<url>.extraheader` land in the sandbox with the token intact.
/// Dropping them is safe: the session never talks to the network.
fn scrub_drop_line(line: &str) -> bool {
    let Some(eq) = line.find('=') else {
        return false;
    };
    let key = line[..eq].trim();
    let key = key.split('.').next_back().unwrap_or(key);
    key.eq_ignore_ascii_case("extraheader")
}

/// One config line: `url = scheme://user:pass@host/...` loses the userinfo.
/// None when the line needs no change. Guard against cutting path `@`s
/// (`.../repo@v1`): only strip when the candidate userinfo contains no `/`.
fn scrub_url_creds(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    if !line[..eq].trim().eq_ignore_ascii_case("url") {
        return None;
    }
    let val = line[eq + 1..].trim_start();
    for scheme in ["https://", "http://", "ssh://", "git://"] {
        let Some(rest) = val.strip_prefix(scheme) else {
            continue;
        };
        let Some(at) = rest.find('@') else {
            continue;
        };
        if rest[..at].contains('/') {
            continue;
        }
        let head = &line[..line.len() - rest.len()]; // prefix incl. scheme
        return Some(format!("{head}{}", &rest[at + 1..]));
    }
    None
}

/// Walk `host` into the virtual FS under `rel0` ("" seeds the tree at /).
/// The walk only creates children — a non-empty `rel0` mountpoint must be
/// mkdir'd here first, or its first child create fails.
/// ponytail: whole-file reads; chunk pwrite if giant binaries ever matter.
pub(crate) async fn seed_tree(agent: &AgentFS, host_root: &Path, rel0: PathBuf) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut count = 0u64;
    let mut stack = vec![(host_root.to_path_buf(), rel0)]; // (host dir, vfs-relative)
    if let Some(vfs) = stack[0].1.to_str().filter(|s| !s.is_empty()) {
        let md = std::fs::metadata(host_root)?;
        let vfs = format!("/{vfs}");
        agent
            .fs
            .mkdir(&vfs, md.uid(), md.gid())
            .await
            .with_context(|| format!("seed: mkdir {vfs}"))?;
        count += 1;
    }
    while let Some((host, rel)) = stack.pop() {
        for entry in
            std::fs::read_dir(&host).with_context(|| format!("seed: read {}", host.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            if SEED_EXCLUDES.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            let child_rel = rel.join(&name);
            let vfs = format!("/{}", child_rel.display());
            let md = std::fs::symlink_metadata(entry.path())?;
            let (uid, gid) = (md.uid(), md.gid());
            let ft = entry.file_type()?;
            if ft.is_dir() {
                agent
                    .fs
                    .mkdir(&vfs, uid, gid)
                    .await
                    .with_context(|| format!("seed: mkdir {vfs}"))?;
                count += 1;
                stack.push((entry.path(), child_rel));
            } else if ft.is_symlink() {
                let target = std::fs::read_link(entry.path())?;
                agent
                    .fs
                    .symlink(&target.to_string_lossy(), &vfs, uid, gid)
                    .await
                    .with_context(|| format!("seed: symlink {vfs}"))?;
                count += 1;
            } else if ft.is_file() {
                let data = std::fs::read(entry.path())?;
                agent
                    .fs
                    .create_file(&vfs, md.mode(), uid, gid)
                    .await
                    .with_context(|| format!("seed: create {vfs}"))?;
                if !data.is_empty() {
                    agent
                        .fs
                        .pwrite(&vfs, 0, &data)
                        .await
                        .with_context(|| format!("seed: write {vfs}"))?;
                }
                count += 1;
            }
            // fifos/sockets/devices: skip
        }
    }
    Ok(count)
}

/// What `git` told us about the seed dir's repo: where the root is, the seed
/// dir's path inside it ("" when the seed dir IS the root), and the
/// `git status --porcelain` lines (empty = clean worktree).
struct GitSeedCtx {
    toplevel: PathBuf,
    prefix: String,
    dirty: Vec<String>,
    /// The seed-time HEAD sha, or None on an unborn branch (fresh `git
    /// init`, no commits yet). Doubles as the has_head check.
    head_sha: Option<String>,
}

/// Probe the seed dir for a git repo. Any failure — no `git` on PATH, not a
/// repo, bare repo — returns None and seeding falls back to copying the dir
/// as-is, exactly as before this feature existed.
fn git_seed_ctx(dir: &Path) -> Option<GitSeedCtx> {
    let run = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let toplevel = run(&["rev-parse", "--show-toplevel"])?;
    if toplevel.is_empty() {
        return None;
    }
    Some(GitSeedCtx {
        toplevel: PathBuf::from(toplevel),
        prefix: run(&["rev-parse", "--show-prefix"]).unwrap_or_default(),
        dirty: run(&["status", "--porcelain=v1"])?
            .lines()
            .map(str::to_string)
            .collect(),
        head_sha: run(&["rev-parse", "HEAD"]),
    })
}

/// How to treat uncommitted changes when seeding a dirty git repo.
#[derive(Clone, Copy, Debug, PartialEq)]
enum DirtyMode {
    /// Ask `[y/N]` on a TTY; default N when non-interactive.
    Ask,
    /// Seed the worktree as-is, uncommitted changes included.
    All,
    /// Seed the committed state only (`git archive HEAD`).
    Head,
}

fn parse_dirty_mode(s: &str) -> Result<DirtyMode> {
    match s {
        "ask" => Ok(DirtyMode::Ask),
        "all" => Ok(DirtyMode::All),
        "head" => Ok(DirtyMode::Head),
        _ => bail!("--seed-dirty expects ask|all|head, got '{s}'"),
    }
}

/// The `[y/N]` prompt for dirty seeds. Non-TTY stdin defaults to N — a run is
/// reproducible from HEAD, and scripts shouldn't block on a question; pass
/// `--seed-dirty=all` to force the dirt in.
fn ask_seed_dirty(n: usize, dir: &Path) -> Result<bool> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!(
        "den: {} uncommitted change(s) in {} — seed them too? [y/N] ",
        n,
        dir.display()
    );
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let a = line.trim();
    Ok(a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"))
}

/// Materialize the seed dir's committed state into a temp dir via
/// `git archive HEAD[:<prefix>]`, so a dirty worktree seeded as "no" yields
/// exactly HEAD: tracked deletions undone, untracked files absent. Caller
/// removes the dir after seeding.
fn extract_head_archive(ctx: &GitSeedCtx) -> Result<PathBuf> {
    let spec = if ctx.prefix.is_empty() {
        "HEAD".to_string()
    } else {
        format!("HEAD:{}", ctx.prefix.trim_end_matches('/'))
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("den-seed-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    // HEAD's checkout lands here, under shared /tmp — keep it private.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700));
    }
    let mut arch = Command::new("git")
        .arg("-C")
        .arg(&ctx.toplevel)
        .args(["archive", &spec])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("git -C {} archive {spec}", ctx.toplevel.display()))?;
    let tar = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(&tmp)
        .stdin(Stdio::from(
            arch.stdout.take().context("git archive stdout")?,
        ))
        .stderr(Stdio::null())
        .status();
    let arch_st = arch.wait();
    match (tar, arch_st) {
        (Ok(t), Ok(a)) if t.success() && a.success() => Ok(tmp),
        _ => {
            let _ = std::fs::remove_dir_all(&tmp);
            bail!("git archive {spec} failed")
        }
    }
}

/// Where a `--seed <dir>` actually seeds from, decided once, up front.
#[derive(Debug)]
struct ResolvedSeed {
    src: PathBuf,
    /// Repo `.git` to seed as `/.git`. None for non-repos and for repo-subdir
    /// seeds — a subdir seed gets a partial tree, and pairing it with a
    /// root-level `/.git` would make `git status` inside the session lie.
    git_dir: Option<PathBuf>,
    note: Option<String>,
    /// `src` is a temp dir the caller removes after seeding.
    temp: bool,
    /// Host HEAD at seed time, when a repo `.git` is seeded. Persisted as
    /// `<session>/seed.sha`; `den push` warns when the host repo has
    /// advanced past this commit (baseline drift).
    head_sha: Option<String>,
}

/// Decide the seed source: the live dir, or HEAD via `git archive` when the
/// worktree is dirty and the user declines the dirt. `.git` is always seeded
/// when the seed dir is the repo root — clean, dirty-and-accepted, or
/// HEAD-extracted — so the agent sees diff/log/history either way.
fn resolve_seed_source(dir: &Path, mode: DirtyMode) -> Result<ResolvedSeed> {
    let fallback = |note: Option<String>| ResolvedSeed {
        src: dir.to_path_buf(),
        git_dir: None,
        note,
        temp: false,
        head_sha: None,
    };
    let Some(ctx) = git_seed_ctx(dir) else {
        return Ok(fallback(None));
    };
    let git_dir = (ctx.prefix.is_empty() && ctx.toplevel.join(".git").is_dir())
        .then(|| ctx.toplevel.join(".git"));
    let with_git = |src: PathBuf, note: Option<String>, temp: bool| ResolvedSeed {
        src,
        git_dir: git_dir.clone(),
        note,
        temp,
        head_sha: git_dir.as_ref().and(ctx.head_sha.clone()),
    };
    if ctx.dirty.is_empty() {
        return Ok(with_git(dir.into(), None, false));
    }
    let include = match mode {
        DirtyMode::All => true,
        DirtyMode::Head => false,
        DirtyMode::Ask => ask_seed_dirty(ctx.dirty.len(), dir)?,
    };
    // An unborn HEAD can't exclude the dirt (there's no committed state to
    // fall back to) — the options are seeding the dirt or seeding nothing.
    // The user's --seed-dirty=head / "N" answer wins, so refuse instead of
    // seeding the dirt behind their back.
    if !include && ctx.head_sha.is_none() {
        bail!(
            "{} has no commits yet (unborn HEAD) and {} uncommitted change(s) are excluded \
             by --seed-dirty — nothing to seed; commit first or use --seed-dirty=all",
            dir.display(),
            ctx.dirty.len()
        );
    }
    if include {
        return Ok(with_git(dir.into(), None, false));
    }
    let src = extract_head_archive(&ctx)?;
    Ok(with_git(
        src,
        Some(format!(
            "{} uncommitted change(s) excluded — seeded from HEAD (--seed-dirty=all to include)",
            ctx.dirty.len()
        )),
        true,
    ))
}

/// path -> (mtime, mtime_nsec, size) for every entry in the virtual FS.
/// Comparing two snapshots tells you what a run touched.
pub(crate) async fn snapshot_fs(agent: &AgentFS) -> HashMap<String, (i64, u32, i64)> {
    let mut out = HashMap::new();
    let mut stack = vec![(String::new(), 1i64)]; // (path, ino); root ino = 1
    while let Some((path, ino)) = stack.pop() {
        let names = agent
            .fs
            .readdir(ino)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        for name in names {
            let child = format!("{path}/{name}");
            let Some(st) = agent.fs.lstat(&child).await.ok().flatten() else {
                continue;
            };
            out.insert(child.clone(), (st.mtime, st.mtime_nsec, st.size));
            if st.mode & S_IFMT == S_IFDIR {
                stack.push((child, st.ino));
            }
        }
    }
    out
}

/// compact post-run summary: what this run touched in the virtual FS
/// (added/modified/removed vs the pre-run snapshot) + capped listing
async fn print_run_summary(sid: &str, before: &RunSnap) -> Result<()> {
    if std::env::var("DEN_QUIET").as_deref() == Ok("1") {
        return Ok(());
    }
    let agent = match open_session(sid).await {
        Ok(Some(a)) => a,
        Ok(None) => return Ok(()), // no session DB — nothing to summarize
        Err(e) => {
            eprintln!("\nagentfs: {e}");
            return Ok(());
        }
    };
    // (kind, path) triples: "+" added, "M" modified, "-" removed
    let (added, modified, removed) = match before {
        RunSnap::Legacy(b) => {
            let after = snapshot_fs(&agent).await;
            let added: HashSet<String> = after
                .keys()
                .filter(|k| !b.contains_key(*k))
                .cloned()
                .collect();
            let removed: HashSet<String> = b
                .keys()
                .filter(|k| !after.contains_key(*k))
                .cloned()
                .collect();
            let modified: HashSet<String> = after
                .iter()
                .filter(|(k, v)| b.get(*k).is_some_and(|bv| bv != *v))
                .map(|(k, _)| k.clone())
                .collect();
            (added, modified, removed)
        }
        RunSnap::Layered(b) => {
            let after = delta_snapshot(&agent).await?;
            // Base attrs tell copy-ups from new files and no-ops from edits:
            // a delta entry whose attrs match the base is an unmodified
            // copy-up (mtime preserved), not a change.
            let mut base_attrs: HashMap<String, (i64, u32, i64)> = HashMap::new();
            if let Some(p) = session_base_db(sid)? {
                if let Ok(base) =
                    AgentFS::open(AgentFSOptions::with_path(p.to_string_lossy().to_string())).await
                {
                    for path in after.delta.keys() {
                        if let Some(st) = base.fs.lstat(path).await.ok().flatten() {
                            base_attrs.insert(path.clone(), (st.mtime, st.mtime_nsec, st.size));
                        }
                    }
                }
            }
            let mut added: HashSet<String> = HashSet::new();
            let mut modified: HashSet<String> = HashSet::new();
            for (p, v) in &after.delta {
                match b.delta.get(p) {
                    // this run already knew the entry: report attr changes
                    Some(bv) => {
                        if bv != v {
                            modified.insert(p.clone());
                        }
                    }
                    None => match base_attrs.get(p) {
                        Some(ba) if ba == v => {} // no-op copy-up: attrs identical
                        Some(_) => {
                            modified.insert(p.clone()); // copied up + written
                        }
                        None => {
                            added.insert(p.clone()); // brand-new
                        }
                    },
                }
            }
            let mut removed: HashSet<String> = after
                .tombstones
                .difference(&b.tombstones)
                .cloned()
                .collect();
            for p in b.delta.keys() {
                if !after.delta.contains_key(p) {
                    removed.insert(p.clone());
                }
            }
            (added, modified, removed)
        }
    };
    eprintln!(
        "\nden: session {sid} — {} added, {} modified, {} removed this run",
        added.len(),
        modified.len(),
        removed.len()
    );
    for (mark, set) in [("+", &added), ("M", &modified), ("-", &removed)] {
        let mut list: Vec<_> = set.iter().collect();
        list.sort();
        for p in list.iter().take(20) {
            eprintln!("  {mark} {p}");
        }
        if list.len() > 20 {
            eprintln!("  … {} more", list.len() - 20);
        }
    }
    Ok(())
}

// ---- subcommands -------------------------------------------------------------

// ---- layered sessions: shared base + per-session delta (§3.6) ---------------

/// A resolved base: shared read-only DB + its content-identity key.
struct PreparedBase {
    key: String,
    db_path: PathBuf,
    /// Seed-time HEAD (git seeds) — echoed into the session's seed.sha.
    head_sha: Option<String>,
    note: Option<String>,
    /// True when this call created the base (vs reused an existing one).
    fresh_base: bool,
}

/// key.json content for a resolved seed source.
async fn base_key_meta(
    seed: &Path,
    git: bool,
    head_sha: Option<&str>,
    digest: String,
) -> layer::BaseKey {
    let toplevel = if git {
        git_seed_ctx(seed)
            .map(|c| c.toplevel)
            .unwrap_or_else(|| seed.to_path_buf())
    } else {
        seed.to_path_buf()
    };
    layer::BaseKey {
        kind: if git { "git" } else { "dir" }.into(),
        toplevel: toplevel.to_string_lossy().to_string(),
        head_sha: head_sha.map(|s| s.to_string()),
        digest,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        refs: 0,
    }
}

/// Create or open the shared base for a seed source (§3.6). The key is
/// content-identity (worktree digest + git HEAD), so identical worktrees
/// share one base. Reuses the existing seed machinery verbatim
/// (resolve_seed_source / seed_session / scrub_git_config — the credential
/// scrub now runs once per base instead of per session).
async fn prepare_base(seed: &Path, dirty: DirtyMode) -> Result<PreparedBase> {
    let rs = resolve_seed_source(seed, dirty)?;
    let digest = layer::worktree_digest(&rs.src)?;
    let key = layer::base_key(
        rs.git_dir.is_some(),
        &rs.src,
        rs.head_sha.as_deref(),
        &digest,
    );
    let dir = bases_root()?.join(&key);
    std::fs::create_dir_all(&dir)?;
    let db = dir.join("base.db");
    // One creator per key; joiners wait for base.db (same-user single host).
    // A stale .seed-lock (crashed creator) is removed by hand.
    let guard = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(".seed-lock"))
    {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
        Err(e) => return Err(e.into()),
    };
    if guard.is_none() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !db.exists() {
            if std::time::Instant::now() > deadline {
                bail!(
                    "base {key} is being created elsewhere (if that failed, remove {} and retry)",
                    dir.join(".seed-lock").display()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    let mut fresh_base = false;
    if !db.exists() {
        let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
        let agent = AgentFS::open(opts).await.context("create base DB")?;
        let seeded = seed_session(&agent, &rs.src, rs.git_dir.as_deref()).await;
        if rs.temp {
            // Clean up whether seeding succeeded or failed — a `?` would
            // otherwise leak the HEAD-extract temp dir.
            let _ = std::fs::remove_dir_all(&rs.src);
        }
        let n = seeded?;
        eprintln!(
            "den: seeded base {key} with {n} entries from {}",
            seed.display()
        );
        if rs.git_dir.is_some() {
            eprintln!("den: repo history seeded as /.git (shared; credentials scrubbed once)");
        }
        layer::write_key_json(
            &dir.join("key.json"),
            &base_key_meta(
                seed,
                rs.git_dir.is_some(),
                rs.head_sha.as_deref(),
                digest.clone(),
            )
            .await,
        )?;
        fresh_base = true;
    }
    // Self-heal a base whose key.json is missing (crash between seed and
    // write): the key already carries the identity just computed.
    if layer::read_key_json(&dir.join("key.json")).is_err() {
        layer::write_key_json(
            &dir.join("key.json"),
            &base_key_meta(seed, rs.git_dir.is_some(), rs.head_sha.as_deref(), digest).await,
        )?;
    }
    pin_base(&dir, 1)?;
    Ok(PreparedBase {
        key,
        db_path: db,
        head_sha: rs.head_sha,
        note: rs.note,
        fresh_base,
    })
}

/// Adjust a base's pin count (advisory; v1 GC is manual): +1 on session
/// creation, -1 when a session is rm'd or archived.
fn pin_base(base_dir: &Path, delta: i64) -> Result<()> {
    let p = base_dir.join("key.json");
    let mut k = layer::read_key_json(&p)?;
    k.refs = ((k.refs as i64) + delta).max(0) as u64;
    layer::write_key_json(&p, &k)
}

/// The pinned base's seed-time HEAD (for `den push` baseline-drift checks);
/// read from the base's key.json — a host file, opened read-only.
fn base_head_sha(base_db: &Path) -> Option<String> {
    layer::read_key_json(&base_db.parent()?.join("key.json"))
        .ok()?
        .head_sha
}

/// Unpin the base a session points at, if any (on rm / archive).
fn unpin_session_base(sid: &str) {
    if let Ok(Some(p)) = session_base_db(sid) {
        if let Some(d) = p.parent() {
            let _ = pin_base(d, -1);
        }
    }
}

/// Update the config stamp's base line after a fresh session pins its base
/// (drop_stale_session wrote the stamp before the base existed).
fn stamp_set_base(sid: &str, allows: &[String], base_key: &str) -> Result<()> {
    if nested_run() {
        return Ok(()); // nested sessions live in the outer VFS; no host stamp
    }
    let stamp_path = run_dir()?.join(".stamps").join(sid);
    if let Some(parent) = stamp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &stamp_path,
        format!("{}\n{}\n{}", cwd_string(), allows.join("\n"), base_key),
    )?;
    Ok(())
}

/// Create the session's delta DB and pin it to a prepared base (cmd_run's
/// fresh-layered path; the sandbox selftest reuses it verbatim).
async fn create_layered_session(sid: &str, p: &PreparedBase) -> Result<()> {
    let db = session_db_path(sid)?;
    std::fs::create_dir_all(db.parent().unwrap_or(Path::new(".")))?;
    let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
    let delta = AgentFS::open(opts)
        .await
        .context("create session delta DB")?;
    drop(delta);
    let sd = db.parent().context("session dir")?;
    std::fs::write(sd.join("base"), p.db_path.to_string_lossy().to_string())?;
    if let Some(sha) = &p.head_sha {
        std::fs::write(sd.join("seed.sha"), sha)?;
    }
    Ok(())
}

/// Pre/post-run snapshot of what the session OWNS: for layered sessions that
/// is its delta + tombstones (small — the base is shared and read-only); for
/// legacy/delta-only sessions it is the whole virtual-FS tree.
enum RunSnap {
    /// full virtual-FS path -> (mtime, mtime_nsec, size)
    Legacy(HashMap<String, (i64, u32, i64)>),
    Layered(DeltaSnap),
}

#[derive(Default)]
struct DeltaSnap {
    delta: HashMap<String, (i64, u32, i64)>,
    tombstones: HashSet<String>,
}

/// path -> (mtime, nsec, size) for every entry in the session's DELTA (what
/// it created, copied up, or tombstoned) — O(session changes), not O(repo).
async fn delta_snapshot(agent: &AgentFS) -> Result<DeltaSnap> {
    let mut snap = DeltaSnap::default();
    for p in agent.get_delta_paths().await? {
        if let Some(st) = agent.fs.lstat(&p).await.ok().flatten() {
            snap.delta.insert(p, (st.mtime, st.mtime_nsec, st.size));
        }
    }
    snap.tombstones = agent.get_whiteouts().await.unwrap_or_default();
    Ok(snap)
}

/// path -> (mtime, nsec, size) for a whole layer tree. `filter` applies the
/// tombstone ancestor check (base walks only — the delta namespace always
/// wins, so delta walks are unfiltered).
async fn walk_tree(
    agent: &AgentFS,
    out: &mut HashMap<String, (i64, u32, i64)>,
    filter: Option<&HashSet<String>>,
) {
    let mut stack = vec![(String::new(), 1i64)]; // (path, ino); root ino = 1
    while let Some((path, ino)) = stack.pop() {
        let names = agent
            .fs
            .readdir(ino)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let names = match filter {
            Some(ts) => layer::filter_base_children(&path, &names, ts),
            None => names,
        };
        for name in names {
            let child = format!("{path}/{name}");
            let Some(st) = agent.fs.lstat(&child).await.ok().flatten() else {
                continue;
            };
            if st.mode & S_IFMT == S_IFDIR {
                stack.push((child.clone(), st.ino));
            }
            out.insert(child, (st.mtime, st.mtime_nsec, st.size));
        }
    }
}

/// The MERGED view of a layered session (§3.7 inspect): base ∪ delta, minus
/// tombstoned base paths (and their subtrees). No FUSE, no merged-ino map —
/// a plain union of both trees; delta attrs win on shared paths.
async fn snapshot_merged(session_dir: &Path) -> Result<HashMap<String, (i64, u32, i64)>> {
    let delta_path = session_dir.join("fs.db");
    let delta = AgentFS::open(AgentFSOptions::with_path(
        delta_path.to_string_lossy().to_string(),
    ))
    .await
    .context("open session delta DB")?;
    let tombstones = delta.get_whiteouts().await.unwrap_or_default();
    let mut merged = HashMap::new();
    if let Some(base_db) = std::fs::read_to_string(session_dir.join("base"))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        let base = AgentFS::open(AgentFSOptions::with_path(base_db)).await?;
        walk_tree(&base, &mut merged, Some(&tombstones)).await;
    }
    walk_tree(&delta, &mut merged, None).await;
    Ok(merged)
}

fn cmd_run(
    profile_name: &str,
    sid: &str,
    passthrough: &[String],
    autostart: bool,
    auto_out: Option<PathBuf>,
    seed: Option<PathBuf>,
    dirty: DirtyMode,
) -> Result<i32> {
    // full-vfs: layered sessions mount base+delta (§3); the delta starts
    // empty and holds only the session's changes. Legacy mode (DEN_LAYER=0,
    // or a pre-layer session dir without a `base` file) seeds fs.db itself.
    let db = session_db_path(sid)?;
    let fresh = !db.exists();
    let allows = effective_allows(&profile(profile_name));
    // Nested runs (§7 step 2): no --seed — the subagent inherits the outer
    // session's pinned base (its delta lives inside the outer VFS at
    // <cwd>/.den/<sid>/fs.db).
    let nested_base: Option<PathBuf> = if fresh && seed.is_none() && nested_run() {
        std::env::var("DEN_BASE_DB")
            .ok()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty() && Path::new(p).is_file())
            .map(PathBuf::from)
    } else {
        None
    };
    let prepared = if fresh && seed.is_some() && layers_enabled() {
        Some(block_on(prepare_base(
            seed.as_deref().context("seed dir")?,
            dirty,
        ))??)
    } else {
        None
    };
    let before: RunSnap = block_on(async {
        let snap: RunSnap = if fresh {
            std::fs::create_dir_all(db.parent().unwrap_or(Path::new(".")))?;
            match (&prepared, nested_base) {
                (None, Some(b)) => {
                    // Nested session (§7 step 2): delta empty inside the
                    // outer VFS; base inherited from the outer session.
                    let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
                    let delta = AgentFS::open(opts)
                        .await
                        .context("create nested session DB")?;
                    drop(delta);
                    let sd = db.parent().context("nested session dir")?;
                    std::fs::write(sd.join("base"), b.to_string_lossy().to_string())?;
                    // Echo the base's seed HEAD for push-drift (v2 push reads it).
                    if let Some(sha) = base_head_sha(&b) {
                        std::fs::write(sd.join("seed.sha"), sha)?;
                    }
                    RunSnap::Layered(DeltaSnap::default())
                }
                (Some(p), _) => {
                    // delta starts EMPTY; the session pins the shared base.
                    create_layered_session(sid, p).await?;
                    stamp_set_base(sid, &allows, &p.key)?;
                    let what = if p.fresh_base { "new" } else { "reused" };
                    eprintln!("den: session {sid} on {what} base {} — delta empty", p.key);
                    if let Some(x) = &p.note {
                        eprintln!("den: {x}");
                    }
                    RunSnap::Layered(DeltaSnap::default())
                }
                (None, None) => {
                    let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
                    let agent = AgentFS::open(opts).await.context("open session DB")?;
                    if let Some(d) = &seed {
                        let rs = resolve_seed_source(d, dirty)?;
                        let seeded = seed_session(&agent, &rs.src, rs.git_dir.as_deref()).await;
                        if rs.temp {
                            // Clean up whether seeding succeeded or failed —
                            // a `?` would leak the HEAD-extract temp dir.
                            let _ = std::fs::remove_dir_all(&rs.src);
                        }
                        let n = seeded?;
                        eprintln!(
                            "den: seeded session {sid} with {n} entries from {}",
                            d.display()
                        );
                        if rs.git_dir.is_some() {
                            eprintln!("den: repo history seeded as /.git (private to the session)");
                        }
                        if let Some(x) = &rs.note {
                            eprintln!("den: {x}");
                        }
                        if let Some(sha) = &rs.head_sha {
                            let sd = db.parent().context("session dir")?;
                            std::fs::write(sd.join("seed.sha"), sha)?;
                        }
                    }
                    let snap = snapshot_fs(&agent).await;
                    // Seed baseline for `den push` (legacy sessions only —
                    // layered sessions diff against their base instead).
                    if seed.is_some() {
                        let sd = db.parent().context("session dir")?;
                        std::fs::write(sd.join("seed.snapshot"), push::snapshot_to_tsv(&snap))?;
                    }
                    RunSnap::Legacy(snap)
                }
            }
        } else {
            if seed.is_some() {
                eprintln!(
                    "den: session {sid} already exists — --seed ignored (DEN_NEW=1 for a fresh session)"
                );
            }
            let agent = open_session(sid).await?.context("no session DB")?;
            if session_base_db(sid)?.is_some() {
                RunSnap::Layered(delta_snapshot(&agent).await?)
            } else {
                RunSnap::Legacy(snapshot_fs(&agent).await)
            }
        };
        anyhow::Ok(snap)
    })??;
    let mut argv = build_argv(profile_name, passthrough)?;
    // Resolve the command on the host PATH before entering the sandbox, so a
    // file created in the overlay (e.g. a previous run's fake `bin/pi`) can't
    // shadow the real agent binary via PATH ordering inside the sandbox.
    argv[0] = resolve_bin(&argv[0]).to_string_lossy().to_string();
    if autostart {
        spawn_watch(sid, auto_out.as_deref())?;
    }
    // The sandbox is in-process: FUSE merge + fork/unshare child. The child
    // keeps the default signal dispositions (inherited across fork), and the
    // sandbox parent installs forward-to-child handlers itself, so Ctrl-C
    // reaches the agent directly — no wrapper in between to ignore it.
    #[cfg(target_os = "linux")]
    // block_on wraps the Result, so unwrap twice (see the `??` note at block_on).
    let code = block_on(sandbox::run_cmd(
        allows,
        sid.to_string(),
        PathBuf::from(&argv[0]),
        argv[1..].to_vec(),
    ))??;
    #[cfg(not(target_os = "linux"))]
    let code = {
        // ponytail: the macOS NFS+sandbox-exec path was not ported; the FUSE
        // sandbox is Linux-only. Re-add when macOS matters (port cli/src/sandbox/darwin.rs).
        let _ = &argv;
        bail!("den's in-process sandbox is Linux-only; run den on Linux")
    };
    // The agent has exited and the session DB is persisted — diff what the
    // session owns against the pre-run snapshot.
    block_on(print_run_summary(sid, &before))??;
    Ok(code)
}

/// Strip den's own flags from a run's passthrough args (the rest go to the
/// agent): `--seed <dir>` and `--seed-dirty <mode>` always, `--autostart
/// [--out <base.ltx>]` only when --autostart is present, so plain agent args
/// are never eaten.
fn split_run_args(
    rest: &[String],
) -> (
    bool,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<String>,
    Vec<String>,
) {
    let autostart = rest.iter().any(|a| a == "--autostart");
    let mut out = None;
    let mut seed = None;
    let mut dirty = None;
    let mut pass = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--seed" if rest.get(i + 1).is_some() => {
                seed = Some(PathBuf::from(&rest[i + 1]));
                i += 1;
            }
            "--seed-dirty" if rest.get(i + 1).is_some() => {
                dirty = Some(rest[i + 1].clone());
                i += 1;
            }
            "--autostart" => {}
            "--out" if autostart && rest.get(i + 1).is_some() => {
                out = Some(PathBuf::from(&rest[i + 1]));
                i += 1;
            }
            a => pass.push(a.to_string()),
        }
        i += 1;
    }
    (autostart, out, seed, dirty, pass)
}

/// Spawn a detached `den` subcommand for this session: stdin null, output to
/// `<session>/<log_name>`, DEN_DETACHED=1 so the subcommand knows it must
/// survive `den run`'s Ctrl-C. The child inherits `den run`'s SIG_IGN for
/// SIGINT/SIGTERM, so it outlives Ctrl-C; subcommands restore TERM handling
/// themselves so `kill` still stops them.
fn spawn_detached(sid: &str, args: &[&str], log_name: &str) -> Result<u32> {
    let log = crate::sessions_root()?.join(sid).join(log_name);
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(args)
        .env("DEN_DETACHED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file));
    // SAFETY: pre_exec runs post-fork in the child; sigaction(SIG_IGN) is
    // async-signal-safe, so the detached daemon ignores INT/TERM (it restores
    // TERM handling itself) and survives Ctrl-C on the run.
    unsafe {
        cmd.pre_exec(|| {
            // SAFETY: see ignore_int_term.
            ignore_int_term();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn detached {} for session {sid}", args[0]))?;
    Ok(child.id())
}

/// `den <profile> --autostart`: stream the session's changes while the agent
/// works. Preferred: a detached litestream daemon continuously replicating
/// the fs.db to S3 (`den replicate <sid>`), when a replica is configured
/// (DEN_REPLICA / LITESTREAM_REPLICA_URL / LITESTREAM_BUCKET) and the
/// binary is installed. Fallback: the local LTX chain watch (`den backup
/// <sid> --watch` -> `<sid>.ltx`). Both survive Ctrl-C on the run, refuse a
/// second autostart on the same session (flock), and exit on their own when
/// the session is deleted.
///
/// Detached children get SIGINT/SIGTERM ignored via pre_exec so Ctrl-C on
/// the run (which the sandbox parent forwards to the agent) doesn't kill
/// the streaming daemon. They restore normal TERM handling themselves for
/// `kill`.
fn spawn_watch(sid: &str, out: Option<&Path>) -> Result<()> {
    if litestream_autostart(sid) {
        let pid = spawn_detached(sid, &["replicate", sid], "replicate.log")?;
        eprintln!(
            "den: autostarted litestream for {sid} -> {} (pid {pid}, log: {})",
            replica_url(sid, None)?,
            crate::sessions_root()?
                .join(sid)
                .join("replicate.log")
                .display()
        );
        return Ok(());
    }
    let out = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(format!("{sid}.ltx")));
    let log = crate::sessions_root()?.join(sid).join("backup-watch.log");
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["backup", sid, "--watch", "--out"])
        .arg(&out)
        .env("DEN_DETACHED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file));
    // SAFETY: see spawn_detached — SIG_IGN pre-exec so Ctrl-C doesn't kill it.
    unsafe {
        cmd.pre_exec(|| {
            // SAFETY: see ignore_int_term.
            ignore_int_term();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn backup watch for session {sid}"))?;
    drop(child); // detached: the watcher outlives this run
    eprintln!(
        "den: autostarted backup watch for {sid} -> {} (log: {})",
        out.display(),
        log.display()
    );
    Ok(())
}

/// SIG_IGN for SIGINT/SIGTERM, to be installed in a forked child pre-exec
/// (async-signal-safe).
unsafe fn ignore_int_term() {
    // SAFETY: sigaction with zeroed struct; SIG_IGN is async-signal-safe.
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = libc::SIG_IGN;
    libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
}

// ---- litestream replication (continuous, off-host) --------------------------

/// One daemon per session: exclusive flock on <session>/replicate.lock for
/// the process lifetime (mirrors the LTX watcher's lock_watch). The lock
/// dies with the process — no stale-pid bookkeeping.
fn replicate_lock(sid: &str) -> Result<File> {
    let path = sessions_root()?.join(sid).join("replicate.lock");
    let f = File::create(&path)?;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        bail!(
            "another litestream daemon is already replicating session {sid} ({})",
            path.display()
        );
    }
    Ok(f)
}

/// Forward a signal to the litestream child so it shuts down cleanly instead
/// of being orphaned when `den replicate` is Ctrl-C'd or killed.
static LITESTREAM_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_to_litestream(_sig: i32) {
    let pid = LITESTREAM_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

fn install_forwarder(sig: i32) {
    // SAFETY: handler only calls kill(2) on a stored pid — async-signal-safe.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = forward_to_litestream as *const () as usize;
    unsafe {
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

/// How long to keep a session's db absent before declaring the session
/// deleted and stopping the daemon.
const REAP_POLL: Duration = Duration::from_secs(5);

/// `den replicate [sid] [replica-url]` — run a litestream daemon that
/// continuously replicates the session's fs.db to S3. Command-line mode
/// (`litestream replicate <db> <url>`, flags before positionals); credentials
/// come from AWS_*/LITESTREAM_* env vars, so no config file is generated.
/// `-restore-if-db-not-exists` pulls the session back from the replica on a
/// fresh machine. Foreground by default (Ctrl-C stops it); `den <profile>
/// --autostart` spawns it detached, and it then exits on its own when the
/// session dir is deleted (else it would hold replicate.lock forever and
/// block the next run).
fn cmd_replicate_args(rest: &[String]) -> Result<()> {
    let mut sid = None;
    let mut url = None;
    for a in rest {
        if a.contains("://") {
            if url.is_some() {
                bail!("unexpected argument '{a}'");
            }
            url = Some(a.clone());
        } else if sid.is_none() {
            sid = Some(a.clone());
        } else {
            bail!("unexpected argument '{a}'");
        }
    }
    let sid = match sid {
        Some(s) => s,
        None => select_session()?,
    };
    valid_sid(&sid)?;
    cmd_replicate(&sid, url.as_deref())
}

fn cmd_replicate(sid: &str, url_opt: Option<&str>) -> Result<()> {
    let url = replica_url(sid, url_opt)?;
    let bin = litestream_bin();
    if !bin_found(&bin) {
        bail!(
            "litestream not found. Install it:\n  \
             curl -s https://litestream.io/install.sh | sh\n\
             (or set DEN_LITESTREAM=/path/to/litestream)"
        );
    }
    let session_dir = sessions_root()?.join(sid);
    std::fs::create_dir_all(&session_dir)?;
    let db = session_dir.join("fs.db");
    let _lock = replicate_lock(sid)?;
    // Manual runs: Ctrl-C must stop litestream. Detached runs keep the
    // inherited SIG_IGN for SIGINT so they survive Ctrl-C on `den run`;
    // TERM is restored in both so `kill` works.
    if std::env::var("DEN_DETACHED").as_deref() != Ok("1") {
        install_forwarder(libc::SIGINT);
    }
    install_forwarder(libc::SIGTERM);
    let mut child = Command::new(&bin)
        .args(["replicate", "-restore-if-db-not-exists"])
        .arg(&db)
        .arg(&url)
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn {bin}"))?;
    LITESTREAM_PID.store(child.id() as i32, Ordering::Relaxed);
    eprintln!(
        "den: litestream replicating {sid} -> {url} (pid {}, db: {})",
        child.id(),
        db.display()
    );
    // Reap: exit when the session is deleted (mirrors the LTX watcher). A
    // never-seen db is just a session still starting up — keep waiting.
    let mut seen_db = db.exists();
    let mut gone = 0;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("{bin} exited with {status}");
            }
            return Ok(());
        }
        std::thread::sleep(REAP_POLL);
        let dir_gone = !session_dir.exists();
        let db_gone = seen_db && !db.exists();
        if dir_gone || db_gone {
            gone += 1;
        } else {
            gone = 0;
            seen_db = seen_db || db.exists();
        }
        if gone >= 3 {
            eprintln!("den: session {sid} gone — stopping litestream");
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
    }
}

/// `den pull [sid] [replica-url] [--force] [--to <db>]` — restore the
/// session's fs.db from the litestream replica (newest state), defaulting
/// back into the session dir. Refuses to overwrite an existing db unless
/// --force; `-if-replica-exists` makes a never-backed-up session a no-op.
fn cmd_pull_args(rest: &[String]) -> Result<()> {
    let mut sid = None;
    let mut url = None;
    let mut force = false;
    let mut to = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            "--to" => to = Some(take_value(rest, &mut i, "--to")?),
            s if s.contains("://") => {
                if url.is_some() {
                    bail!("unexpected argument '{s}'");
                }
                url = Some(s.to_string());
                i += 1;
            }
            s => {
                if sid.is_some() {
                    bail!("unexpected argument '{s}'");
                }
                sid = Some(s.to_string());
                i += 1;
            }
        }
    }
    let sid = match sid {
        Some(s) => s,
        None => select_session()?,
    };
    valid_sid(&sid)?;
    cmd_pull(&sid, url.as_deref(), force, to)
}

fn cmd_pull(sid: &str, url_opt: Option<&str>, force: bool, to: Option<PathBuf>) -> Result<()> {
    let url = replica_url(sid, url_opt)?;
    let bin = litestream_bin();
    if !bin_found(&bin) {
        bail!(
            "litestream not found. Install it:\n  \
             curl -s https://litestream.io/install.sh | sh\n\
             (or set DEN_LITESTREAM=/path/to/litestream)"
        );
    }
    let to = to.unwrap_or(session_db_path(sid)?);
    let mut args = vec![
        "restore".to_string(),
        "-if-replica-exists".to_string(),
        "-integrity-check".to_string(),
        "quick".to_string(),
        "-o".to_string(),
        to.display().to_string(),
        url.clone(),
    ];
    if force {
        args.insert(2, "-force".to_string());
    }
    let status = Command::new(&bin)
        .args(&args)
        .status()
        .with_context(|| format!("failed to spawn {bin}"))?;
    if !status.success() {
        bail!("litestream restore failed ({status}) — pull into a fresh path with --to, or --force to overwrite");
    }
    println!("den: restored {sid} from {url} -> {}", to.display());
    Ok(())
}

fn cmd_dump(profile_name: &str, passthrough: &[String]) -> Result<()> {
    let sid = session_id(profile_name);
    // Run strips den's own flags (--seed/--seed-dirty/--autostart...); dump
    // must preview the same argv the agent will actually get.
    let (_, _, _, _, passthrough) = split_run_args(passthrough);
    let mut argv = build_argv(profile_name, &passthrough)?;
    argv[0] = resolve_bin(&argv[0]).to_string_lossy().to_string();
    let allows = effective_allows(&profile(profile_name));
    println!("session: {sid}");
    println!("fs.db: {}", session_db_path(&sid)?.display());
    println!("command:  {}", argv.join(" "));
    if allows.is_empty() {
        println!("allow:    (defaults only)");
    } else {
        println!("allow:    {}", allows.join(" "));
    }
    Ok(())
}

fn cmd_inspect(sid: &str) -> Result<()> {
    valid_sid(sid)?;
    block_on(async move {
        let db_path = session_db_path(sid)?;
        let agent = match open_session(sid).await? {
            Some(a) => a,
            None => bail!("no fs.db for session {sid} at {}", db_path.display()),
        };
        // Layered session: merged view = base ∪ delta − tombstones (§3.7).
        // Legacy session: fs.db IS the tree, as before.
        let snap = if session_base_db(sid)?.is_some() {
            snapshot_merged(&sessions_root()?.join(sid)).await?
        } else {
            snapshot_fs(&agent).await
        };
        let bytes: i64 = snap.values().map(|v| v.2).sum();
        println!("session {sid}: {} entries, {} bytes", snap.len(), bytes);
        let mut paths: Vec<_> = snap.keys().collect();
        paths.sort();
        for p in paths.iter().take(50) {
            println!("  {p}");
        }
        if paths.len() > 50 {
            println!("  … {} more", paths.len() - 50);
        }
        // Timeline: only populated if the agent itself records tool calls via the
        // SDK. Wrapped CLIs (claude/codex/...) usually leave it empty.
        let recent: Vec<ToolCall> = agent.tools.recent(Some(100i64)).await.unwrap_or_default();
        if !recent.is_empty() {
            println!("timeline ({}):", recent.len());
            for t in &recent {
                let dur = t
                    .duration_ms
                    .map(|d| format!("{d}ms"))
                    .unwrap_or_else(|| "--".into());
                println!("  {:>5}  {:<8}  {:<8}  {}", t.id, t.name, t.status, dur);
            }
        }
        Ok(())
    })?
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionRow {
    sid: String,
    entries: Option<usize>,
    base_path: String,
}

async fn collect_session_rows(run_dir: &Path) -> Result<Vec<SessionRow>> {
    let mut sids: Vec<String> = std::fs::read_dir(run_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir() && !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    sids.sort();

    let mut rows = Vec::with_capacity(sids.len());
    for sid in sids {
        let session_dir = run_dir.join(&sid);
        let db = session_dir.join("fs.db");
        let base_path = std::fs::read_to_string(session_dir.join("base_path"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let entries = if db.exists() {
            // layered: merged view; legacy: the DB alone
            if session_dir.join("base").exists() {
                match snapshot_merged(&session_dir).await {
                    Ok(snap) => Some(snap.len()),
                    Err(_) => Some(0),
                }
            } else {
                let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
                match AgentFS::open(opts).await {
                    Ok(agent) => Some(snapshot_fs(&agent).await.len()),
                    Err(_) => Some(0),
                }
            }
        } else {
            None
        };
        rows.push(SessionRow {
            sid,
            entries,
            base_path,
        });
    }
    Ok(rows)
}

fn format_session_rows(rows: &[SessionRow], numbered: bool) -> String {
    rows.iter()
        .enumerate()
        .map(|(idx, row)| {
            let prefix = if numbered {
                format!("[{}]\t", idx + 1)
            } else {
                String::new()
            };
            let counts = match row.entries {
                Some(n) => format!("{n} entries"),
                None => "(no session DB)".to_string(),
            };
            format!("{prefix}{}\t{counts}\t{}", row.sid, row.base_path)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_session_selection(input: &str, rows: &[SessionRow]) -> Result<String> {
    let choice = input.trim();
    if choice.is_empty() {
        bail!("no session selected");
    }
    if let Ok(n) = choice.parse::<usize>() {
        if (1..=rows.len()).contains(&n) {
            return Ok(rows[n - 1].sid.clone());
        }
        bail!("selection {n} is out of range (1-{})", rows.len());
    }
    if rows.iter().any(|row| row.sid == choice) {
        return Ok(choice.to_string());
    }
    bail!("unknown session '{choice}'");
}

fn prompt_session_selection(rows: &[SessionRow]) -> Result<String> {
    eprintln!("{}", format_session_rows(rows, true));
    eprint!("select session: ");
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    parse_session_selection(&input, rows)
}

fn load_session_rows() -> Result<(PathBuf, Vec<SessionRow>)> {
    let run_dir = sessions_root()?;
    if !run_dir.exists() {
        return Ok((run_dir, Vec::new()));
    }
    let rows = block_on(collect_session_rows(&run_dir))??;
    Ok((run_dir, rows))
}

fn select_session() -> Result<String> {
    let (run_dir, rows) = load_session_rows()?;
    if rows.is_empty() {
        bail!("no sessions at {}", run_dir.display());
    }
    prompt_session_selection(&rows)
}

fn cmd_sessions(select: bool) -> Result<()> {
    let (run_dir, rows) = load_session_rows()?;
    if rows.is_empty() {
        println!("(no sessions at {})", run_dir.display());
        return Ok(());
    }
    if select {
        let sid = prompt_session_selection(&rows)?;
        println!("{sid}");
    } else {
        println!("{}", format_session_rows(&rows, false));
    }
    Ok(())
}

/// Session ids are directory names under ~/.den/sessions (slug, DEN_SESSION,
/// or a listed session) — refuse anything that could escape the tree: a
/// stray `den rm ..` must not delete ~/.den itself.
fn valid_sid(sid: &str) -> Result<()> {
    if sid.is_empty() || sid == "." || sid == ".." || sid.contains('/') || sid.contains('\\') {
        bail!("invalid session id '{sid}'");
    }
    Ok(())
}

/// Delete a session dir: unmount any stale FUSE mount first, then remove
/// the dir and its config stamp. Mirrors drop_stale_session's cleanup order.
fn cmd_rm(sid: &str) -> Result<()> {
    valid_sid(sid)?;
    let run_dir = run_dir()?;
    let dir = run_dir.join(sid);
    if !dir.exists() {
        bail!("no session {} at {}", sid, run_dir.display());
    }
    unmount_stale(&dir.join("mnt"));
    unpin_session_base(sid);
    std::fs::remove_dir_all(&dir).with_context(|| format!("rm session {sid}"))?;
    let stamp = run_dir.join(".stamps").join(sid);
    if stamp.exists() {
        std::fs::remove_file(&stamp).with_context(|| format!("rm stamp {sid}"))?;
    }
    println!("den: removed session {sid}");
    Ok(())
}

fn cmd_selftest(rest: &[String]) -> Result<()> {
    if rest.iter().any(|a| a == "--sandbox") {
        selftest_sandbox()?;
        return Ok(());
    }
    // Deterministic: pin the session id, assert argv assembly + passthrough.
    std::env::set_var("DEN_SESSION", "selftest-sid");
    let argv = build_argv(
        "codex",
        &["exec".into(), "--json".into(), "-m".into(), "gpt-5".into()],
    )?;
    std::env::remove_var("DEN_SESSION");

    let joined = argv.join("\u{1f}"); // unit separator so substring matches are unambiguous
    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !($cond) {
                bail!("selftest FAIL: {}\nargv: {:?}", $msg, joined);
            }
        };
    }
    check!(argv[0] == "codex", "command slot");
    check!(
        joined.contains("codex\u{1f}exec\u{1f}--json\u{1f}-m\u{1f}gpt-5"),
        "passthrough incl. flags"
    );
    println!("selftest OK");
    println!("  {}", argv.join(" "));
    Ok(())
}

/// Full sandbox round-trip: seeded virtual FS + fork/unshare child in a temp
/// dir. Verifies (1) seeding copies the tree into the session DB, (2) agent
/// writes/deletes land in the DB only — the host tree is untouched, (3) the
/// rest of the filesystem is read-only, (4) session join works.
fn selftest_sandbox() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("selftest --sandbox is Linux-only");

    #[cfg(target_os = "linux")]
    {
        let dir = std::env::temp_dir().join(format!("den-sandbox-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("README.md"), "hello\n")?;
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("src/a.txt"), "orig\n")?;
        std::env::set_current_dir(&dir)?;

        let sid = format!("selftest-sandbox-{}", std::process::id());

        // Create the session DB and seed it from the temp dir.
        let (n, before) = block_on(async {
            let dbp = session_db_path(&sid)?;
            std::fs::create_dir_all(dbp.parent().unwrap_or(Path::new(".")))?;
            let opts = AgentFSOptions::with_path(dbp.to_string_lossy().to_string());
            let agent = AgentFS::open(opts).await?;
            let n = seed_session(&agent, &dir, None).await?;
            anyhow::Ok((n, snapshot_fs(&agent).await))
        })??;
        check_sandbox(n == 3, true, "seed copied 3 entries")?;
        check_sandbox(before.contains_key("/README.md"), true, "seeded /README.md")?;
        check_sandbox(before.contains_key("/src/a.txt"), true, "seeded /src/a.txt")?;

        let script = "echo new > created.txt; rm README.md; mkdir -p dir1; echo x > dir1/f.txt";
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), script.into()],
        ))??;
        check_sandbox(code == 0, true, "sandboxed script exit code")?;

        // Host tree untouched: README.md still here, created.txt never written.
        check_sandbox(
            std::fs::read_to_string(dir.join("README.md"))
                .map(|s| s == "hello\n")
                .unwrap_or(false),
            true,
            "host README.md untouched",
        )?;
        check_sandbox(
            !dir.join("created.txt").exists(),
            true,
            "created.txt not on host",
        )?;

        // Session DB: created.txt + dir1/f.txt added, README.md removed — and
        // the touched-this-run diff against the pre-run snapshot agrees.
        let sid_check = sid.clone();
        let after = block_on(async move {
            let agent = open_session(&sid_check)
                .await?
                .context("no session DB after run")?;
            anyhow::Ok(snapshot_fs(&agent).await)
        })??;
        for p in ["/created.txt", "/dir1/f.txt"] {
            check_sandbox(
                after.contains_key(p),
                true,
                &format!("session FS contains {p}"),
            )?;
        }
        check_sandbox(
            !after.contains_key("/README.md"),
            true,
            "/README.md removed from session FS",
        )?;
        check_sandbox(
            after.contains_key("/src/a.txt"),
            true,
            "untouched seed file survives",
        )?;
        let touched: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
        check_sandbox(
            touched.len() == 3,
            true,
            "3 added this run (created.txt, dir1, dir1/f.txt)",
        )?;

        // Read-only enforcement: /etc is not writable from inside the sandbox.
        let diag = format!("/tmp/den-sandbox-diag-{}.txt", std::process::id());
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec![
                "-c".into(),
                format!("{{ ls -la; echo ---; cat created.txt; }} > {diag} 2>&1"),
            ],
        ))??;
        if let Ok(d) = std::fs::read_to_string(&diag) {
            println!("{d}");
        }
        let _ = std::fs::remove_file(&diag);
        check_sandbox(code == 0, true, "diagnostic run exit code")?;

        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "touch /etc/den-sandbox-evil".into()],
        ))??;
        check_sandbox(code != 0, true, "/etc write rejected (EROFS)")?;

        // Session join: second run with the same sid joins, fs.db survives.
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "echo more >> created.txt".into()],
        ))??;
        check_sandbox(code == 0, true, "join-session run exit code")?;

        std::fs::remove_dir_all(&dir)?;
        let _ = std::fs::remove_dir_all(
            session_db_path(&sid)?
                .parent()
                .unwrap_or(std::path::Path::new("")),
        );
        println!("sandbox selftest OK (seed, mount, vfs writes, ro-enforcement, join)");
    }
    selftest_layered()?;
    Ok(())
}

/// Layered round-trip (docs/layered-sessions.md §9 selftest): shared base +
/// per-session delta, base reuse on identical seed, join, RO enforcement.
fn selftest_layered() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("selftest --sandbox is Linux-only");
    #[cfg(target_os = "linux")]
    {
        let dir = std::env::temp_dir().join(format!("den-layer-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("README.md"), "hello\n")?;
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("src/a.txt"), "orig\n")?;
        // The legacy selftest above left the process cwd on a deleted dir;
        // every run_cmd below needs a valid cwd (it becomes the mount target).
        std::env::set_current_dir(&dir).with_context(|| format!("chdir {}", dir.display()))?;

        let sid = format!("selftest-layered-{}", std::process::id());
        std::env::remove_var("DEN_LAYER");

        // Fresh layered session: base seeded once, delta starts empty.
        let (prep, before) = block_on(async {
            let p = prepare_base(&dir, DirtyMode::All).await?;
            create_layered_session(&sid, &p).await?;
            let delta = open_session(&sid).await?.context("delta DB")?;
            anyhow::Ok((p, delta_snapshot(&delta).await?))
        })??;
        let base_db = prep.db_path.clone();
        let base_hash_before = hash_file(&base_db);
        check_sandbox(before.delta.is_empty(), true, "fresh delta empty")?;
        check_sandbox(before.tombstones.is_empty(), true, "fresh tombstones empty")?;

        // Identical seed again → the SAME base is reused (key = content id).
        let prep2 = block_on(prepare_base(&dir, DirtyMode::All))??;
        check_sandbox(
            prep2.db_path == prep.db_path,
            true,
            "identical seed reuses base",
        )?;
        let key_json = read_key_json(&base_db.parent().unwrap().join("key.json"))?;
        check_sandbox(key_json.refs >= 2, true, "base refs counted both pins")?;

        let script = "echo hi >> README.md; echo x > new.txt; rm src/a.txt";
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), script.into()],
        ))??;
        check_sandbox(code == 0, true, "layered run exit code")?;

        // The base DB never changed.
        check_sandbox(
            hash_file(&base_db) == base_hash_before,
            true,
            "base.db untouched by the run",
        )?;

        // The delta holds exactly this run's changes (host tree copied out
        // into base.db at seed time, so none of it is in the delta).
        let sid_c = sid.clone();
        let after = block_on(async move {
            let delta = open_session(&sid_c).await?.context("delta after run")?;
            delta_snapshot(&delta).await
        })??;
        check_sandbox(
            after.delta.contains_key("/README.md") && after.delta.contains_key("/new.txt"),
            true,
            "delta holds modified + added files",
        )?;
        check_sandbox(
            !after.delta.contains_key("/src") && !after.delta.contains_key("/src/a.txt"),
            true,
            "untouched base subtree never copied into the delta",
        )?;
        check_sandbox(
            after.tombstones.contains("/src/a.txt"),
            true,
            "deleted base file leaves a tombstone",
        )?;

        // Merged view: base ∪ delta − tombstones — all three effects visible.
        let sdir = sessions_root()?.join(&sid);
        let merged = block_on(snapshot_merged(&sdir))??;
        check_sandbox(
            merged.contains_key("/README.md") && merged.contains_key("/new.txt"),
            true,
            "merged shows modified + added",
        )?;
        check_sandbox(
            merged.contains_key("/src/a.txt"),
            false,
            "merged hides deleted",
        )?;
        check_sandbox(
            merged.contains_key("/src"),
            true,
            "merged still lists base dir",
        )?;

        // Join: a second run appends to the same delta.
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "echo more >> new.txt".into()],
        ))??;
        check_sandbox(code == 0, true, "join-run exit code")?;
        let sid_c = sid.clone();
        let after2 = block_on(async move {
            let delta = open_session(&sid_c).await?.context("delta after join")?;
            let snap = delta_snapshot(&delta).await?;
            let bytes = delta.fs.read_file("/new.txt").await.ok().flatten();
            anyhow::Ok((snap, bytes))
        })??;
        check_sandbox(
            after2.0.delta.contains_key("/new.txt"),
            true,
            "delta survives join",
        )?;
        check_sandbox(
            after2
                .1
                .is_some_and(|b| String::from_utf8_lossy(&b).contains("x\nmore\n")),
            true,
            "joined write landed in the delta",
        )?;

        // /etc stays read-only (RO sweep unchanged by layering).
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "touch /etc/den-layer-evil".into()],
        ))??;
        check_sandbox(code != 0, true, "/etc write rejected (EROFS)")?;

        // DEN_LAYER=0 escape hatch: fs.db seeded directly, no base pointer.
        let legacy_sid = format!("selftest-legacy-{}", std::process::id());
        std::env::set_var("DEN_LAYER", "0");
        let legacy_fresh = {
            let dbp = session_db_path(&legacy_sid)?;
            let created = block_on(async {
                std::fs::create_dir_all(dbp.parent().unwrap_or(Path::new(".")))?;
                let opts = AgentFSOptions::with_path(dbp.to_string_lossy().to_string());
                let agent = AgentFS::open(opts).await?;
                let n = seed_session(&agent, &dir, None).await?;
                anyhow::Ok(n)
            })??;
            check_sandbox(created == 3, true, "legacy seed copied 3 entries")?;
            !session_base_db(&legacy_sid)?.is_some()
        };
        check_sandbox(legacy_fresh, true, "DEN_LAYER=0 session has no base")?;
        check_sandbox(
            session_db_path(&legacy_sid)?.exists(),
            true,
            "legacy session DB seeded in place",
        )?;

        // Cleanup: sessions + the base the selftest created (2 pins).
        unpin_session_base(&sid);
        let _ = std::fs::remove_dir_all(sessions_root()?.join(&sid));
        let _ = std::fs::remove_dir_all(sessions_root()?.join(&legacy_sid));
        let _ = std::fs::remove_file(sessions_root()?.join(".stamps").join(&sid));
        let _ = std::fs::remove_dir_all(&dir);
        if let Ok(key_json) = read_key_json(&base_db.parent().unwrap().join("key.json")) {
            if key_json.refs == 0 {
                let _ = std::fs::remove_dir_all(base_db.parent().unwrap());
            }
        }
        println!("layered selftest OK (base, delta, tombstone, merge, join, DEN_LAYER=0)");
    }
    Ok(())
}

fn hash_file(p: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if let Ok(bytes) = std::fs::read(p) {
        bytes.iter().for_each(|b| b.hash(&mut h));
    }
    h.finish()
}

fn check_sandbox(cond: bool, expected: bool, what: &str) -> Result<()> {
    if cond != expected {
        bail!("sandbox selftest FAIL: {what} (got {cond}, expected {expected})");
    }
    Ok(())
}

fn usage() -> String {
    "usage:\n  \
     den <cmd> [args...]         run any agent CLI in the sandbox; --seed <dir> preloads a\n  \
                                 new session, --autostart streams a backup watch\n  \
     den dump <cmd> [args...]    print the resolved sandbox plan (no exec)\n  \
     den inspect [session-id]     list a session's virtual FS + timeline\n  \
     den push [sid] [--branch b] [--to dir] [--remote r] [-m msg] [--dry-run]\n  \
                [--keep] [--pr]  land a session's changes as a git branch on the host\n  \
     den sessions [--select]      list persisted sessions, optionally choose one\n  \
     den rm <session-id>          delete a session dir (unmounts stale mounts first)\n  \
     den replicate [sid] [url]    stream a session's fs.db to S3 via litestream (daemon)
  \
     den pull [sid] [url] [--force] [--to db]   restore a session from its litestream replica
  \
     den backup [sid] [--from prev.ltx] [--out path] [-c] [--watch]  LTX backup of a session's fs.db\n  \
     den restore <file.ltx> [--to db]  apply an LTX backup (and chain) back into a session\n  \
     den ltx <file.ltx>         inspect/verify a backup file\n  \
     den list                     list known profiles (any other cmd works too)\n  \
     den selftest                 sanity check\n\n\
env: DEN_NET=proxy|none|full  DEN_PROXY_ALLOW/DEN_PROXY_POLICY  DEN_HIDE/DEN_NO_HIDE  DEN_LIMIT_*  DEN_SECCOMP\n"
        .to_string()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [] => {
            eprintln!("{}", usage());
            bail!("no arguments");
        }
        [c] if c == "list" => {
            for p in list_profiles() {
                println!("{p}");
            }
            Ok(())
        }
        [c, rest @ ..] if c == "selftest" => cmd_selftest(rest),
        [c] if c == "sessions" => cmd_sessions(false),
        [c, flag] if c == "sessions" && flag == "--select" => cmd_sessions(true),
        [c] if c == "help" || c == "--help" || c == "-h" => {
            println!("{}", usage());
            Ok(())
        }
        [c, rest @ ..] if c == "dump" => {
            let (pname, passthrough) = split_profile(rest)?;
            cmd_dump(&pname, &passthrough)
        }
        [c, rest @ ..] if c == "rm" => {
            let sid = match rest.first().map(String::as_str) {
                Some("--select") => select_session()?,
                Some(sid) => sid.to_string(),
                None => bail!("den rm <session-id> (or --select)"),
            };
            cmd_rm(&sid)
        }
        [c, rest @ ..] if c == "inspect" => {
            let sid = match rest.first().map(String::as_str) {
                None | Some("--select") => select_session()?,
                Some(sid) => sid.to_string(),
            };
            cmd_inspect(&sid)
        }
        [c, rest @ ..] if c == "backup" => cmd_backup_args(rest),
        [c, rest @ ..] if c == "push" => cmd_push_args(rest),
        [c, rest @ ..] if c == "replicate" => cmd_replicate_args(rest),
        [c, rest @ ..] if c == "pull" => cmd_pull_args(rest),
        [c, rest @ ..] if c == "restore" => cmd_restore_args(rest),
        [c, rest @ ..] if c == "ltx" => {
            let path = rest.first().context("den ltx <file.ltx>")?;
            if rest.len() > 1 {
                bail!("unexpected argument '{}'", rest[1]);
            }
            backup::cmd_ltx_info(Path::new(path))
        }
        // Internal: the sandbox proxy child (spawned by M with fd 3 as the
        // listener). Not a user-facing command.
        [c] if c == "proxy" => {
            #[cfg(target_os = "linux")]
            {
                proxy::run(3)
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("proxy is Linux-only")
            }
        }
        // Internal: run an arbitrary command inside the sandbox (testing).
        [c, rest @ ..] if c == "raw" => {
            #[cfg(target_os = "linux")]
            {
                let (cmd, args) = rest.split_first().context("den raw <cmd> [args...]")?;
                let sid = format!("raw-{}", std::process::id());
                let code = block_on(sandbox::run_cmd(
                    Vec::new(),
                    sid.clone(),
                    std::path::PathBuf::from(cmd),
                    args.to_vec(),
                ))??;
                std::process::exit(code)
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("sandbox is Linux-only")
            }
        }
        [pname, passthrough @ ..] => {
            // "run" is not a command name; the run is implicit (`den claude`).
            if pname == "run" {
                bail!("den run isn't a command — the run is implicit: den <cmd> [args...]");
            }
            let (autostart, auto_out, seed, dirty_raw, passthrough) = split_run_args(passthrough);
            let dirty = match dirty_raw.as_deref() {
                None => DirtyMode::Ask,
                Some(s) => parse_dirty_mode(s)?,
            };
            let sid = session_id(pname);
            let allows = effective_allows(&profile(pname));
            drop_stale_session(&sid, &allows)?;
            let code = cmd_run(pname, &sid, &passthrough, autostart, auto_out, seed, dirty)?;
            std::process::exit(code);
        }
    }
}

/// Consume `--flag <value>` at `rest[i]`, advancing `i` past both. The only
/// flag form backup/restore need — kept inline rather than a generic parser,
/// which would hide the small shape behind indirection.
fn take_value(rest: &[String], i: &mut usize, flag: &str) -> Result<PathBuf> {
    let v = rest
        .get(*i + 1)
        .with_context(|| format!("{flag} needs a path"))?;
    *i += 2;
    Ok(PathBuf::from(v))
}

/// `den push [sid] [--branch b] [--to dir] [--remote r] [-m msg] [--dry-run]
/// [--keep] [--pr]` — diff the session VFS against its seed baseline and land
/// the delta as a git branch on the host. The push runs here, outside the
/// sandbox, at the trust boundary: the agent never sees git credentials.
fn cmd_push_args(rest: &[String]) -> Result<()> {
    let mut sid: Option<String> = None;
    let mut o = push::PushOpts {
        branch: None,
        to: None,
        remote: None,
        message: None,
        dry_run: false,
        keep: false,
        pr: false,
    };
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        let value = |i: &mut usize, flag: &str| -> Result<String> {
            let v = rest
                .get(*i + 1)
                .with_context(|| format!("{flag} needs a value"))?
                .clone();
            *i += 2;
            Ok(v)
        };
        match a {
            "--branch" => o.branch = Some(value(&mut i, a)?),
            "--to" => o.to = Some(PathBuf::from(value(&mut i, a)?)),
            "--remote" => o.remote = Some(value(&mut i, a)?),
            "--message" | "-m" => o.message = Some(value(&mut i, a)?),
            "--dry-run" => {
                o.dry_run = true;
                i += 1;
            }
            "--keep" => {
                o.keep = true;
                i += 1;
            }
            "--pr" => {
                o.pr = true;
                i += 1;
            }
            _ if a.starts_with('-') => bail!("unknown flag '{a}'"),
            _ => {
                if sid.is_some() {
                    bail!("unexpected argument '{a}'");
                }
                sid = Some(a.to_string());
                i += 1;
            }
        }
    }
    let sid = match sid {
        Some(s) => s,
        None => select_session()?,
    };
    let sdir = sessions_root()?.join(&sid);
    let out = block_on(push::push_session(&sid, &sdir, &o))??;

    println!(
        "den: session {sid} — {} changed, {} deleted{}{}",
        out.changed.len(),
        out.deleted.len(),
        if out.ignored > 0 {
            format!(", {} non-file ignored", out.ignored)
        } else {
            String::new()
        },
        if out.dropped > 0 {
            format!(
                ", {} under sandbox dirs not pushed (etc/, usr/, …)",
                out.dropped
            )
        } else {
            String::new()
        }
    );
    for (mark, list) in [("M", &out.changed), ("D", &out.deleted)] {
        for p in list.iter().take(20) {
            println!("  {mark} {p}");
        }
        if list.len() > 20 {
            println!("  … {} more", list.len() - 20);
        }
    }
    if !out.status.trim().is_empty() {
        println!("den: worktree status:");
        for l in out.status.lines() {
            println!("  {l}");
        }
    }
    if o.dry_run {
        match &out.worktree {
            Some(w) => println!("den: dry-run — worktree kept at {}", w.display()),
            None => println!("den: dry-run — worktree discarded (pass --keep to inspect it)"),
        }
        return Ok(());
    }
    if out.pushed {
        println!("den: pushed {} ({})", out.branch, out.repo.display());
    }
    if !out.push_note.trim().is_empty() {
        println!("{}", out.push_note.trim());
    }
    if !o.pr {
        let gh = Command::new("gh").arg("--version").output().is_ok();
        if gh {
            println!("next: gh pr create --fill --head {}", out.branch);
        } else {
            println!("next: open a PR for branch {}", out.branch);
        }
    }
    Ok(())
}

/// `den backup [sid] [--from <prev.ltx>] [--out <path>] [-c] [--watch]` — sid
/// defaults to an interactive selection when `--select` is given or omitted
/// with no positional argument (mirrors `den inspect`). `--watch` streams
/// chained deltas until interrupted instead of writing one file.
fn cmd_backup_args(rest: &[String]) -> Result<()> {
    let mut from = None;
    let mut out = None;
    let mut sid = None;
    let mut compress = false;
    let mut select = false;
    let mut watch = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--from" => from = Some(take_value(rest, &mut i, "--from")?),
            "--out" => out = Some(take_value(rest, &mut i, "--out")?),
            "-c" | "--compress" => {
                compress = true;
                i += 1;
            }
            "--select" => {
                select = true;
                i += 1;
            }
            "--watch" => {
                watch = true;
                i += 1;
            }
            s => {
                if sid.is_some() {
                    bail!("unexpected argument '{s}'");
                }
                sid = Some(s.to_string());
                i += 1;
            }
        }
    }
    if select && sid.is_some() {
        bail!("cannot combine a session id with --select");
    }
    if watch && from.is_some() {
        bail!("--from is not used with --watch (the chain resumes from --out)");
    }
    let sid = match sid {
        Some(s) => s,
        None => select_session()?,
    };
    valid_sid(&sid)?;
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{sid}.ltx")));
    if watch {
        backup::cmd_backup_watch(&sid, &out, compress)
    } else {
        backup::cmd_backup(&sid, from.as_deref(), &out, compress)
    }
}

/// `den restore <file.ltx> [--to <db>]` — target defaults to the session the
/// file is named after (codex-foo.ltx -> ~/.den/sessions/codex-foo/fs.db).
fn cmd_restore_args(rest: &[String]) -> Result<()> {
    let mut ltx = None;
    let mut to = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--to" => to = Some(take_value(rest, &mut i, "--to")?),
            s => {
                if ltx.is_some() {
                    bail!("unexpected argument '{s}'");
                }
                ltx = Some(PathBuf::from(s));
                i += 1;
            }
        }
    }
    let ltx = ltx.context("den restore <file.ltx> [--to <db>]")?;
    let to = match to {
        Some(t) => t,
        None => backup::default_restore_target(&ltx)?,
    };
    backup::cmd_restore(&ltx, &to)?;
    // a --watch chain (base.ltx + base.NNNN.ltx) restores as a stream:
    // replay the numbered siblings so it comes back at its newest state.
    // existing_chain_indices refuses gaps — a missing middle link means
    // newer deltas sit beyond it, and replaying only the prefix would
    // silently restore a stale state.
    let chain = backup::existing_chain_indices(&ltx)?;
    for k in &chain {
        backup::cmd_restore(&backup::chain_path(&ltx, *k), &to)?;
    }
    if !chain.is_empty() {
        println!(
            "den: replayed {} chain delta(s) onto {}",
            chain.len(),
            to.display()
        );
    }
    Ok(())
}

/// For `dump`: everything after `dump` is `<profile> [passthrough...]`.
fn split_profile(rest: &[String]) -> Result<(String, Vec<String>)> {
    match rest {
        [] => bail!("den dump <cmd> [args...]"),
        [p, rest @ ..] => Ok((p.clone(), rest.to_vec())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// env vars are process-global; serialize the tests that swap them
    /// (mirrors backup.rs's HOME_LOCK).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn session_rows_include_numbered_choices() {
        let rows = vec![
            SessionRow {
                sid: "codex-alpha".into(),
                entries: Some(42),
                base_path: "/tmp/alpha".into(),
            },
            SessionRow {
                sid: "pi-beta".into(),
                entries: None,
                base_path: String::new(),
            },
        ];

        let rendered = format_session_rows(&rows, true);

        assert!(rendered.contains("[1]\tcodex-alpha\t42 entries\t/tmp/alpha"));
        assert!(rendered.contains("[2]\tpi-beta\t(no session DB)\t"));
    }

    #[test]
    fn parse_session_selection_accepts_index_or_session_id() {
        let rows = vec![
            SessionRow {
                sid: "codex-alpha".into(),
                entries: None,
                base_path: String::new(),
            },
            SessionRow {
                sid: "pi-beta".into(),
                entries: None,
                base_path: String::new(),
            },
        ];

        assert_eq!(parse_session_selection("2", &rows).unwrap(), "pi-beta");
        assert_eq!(
            parse_session_selection("codex-alpha", &rows).unwrap(),
            "codex-alpha"
        );
    }

    #[test]
    fn parse_session_selection_rejects_unknown_values() {
        let rows = vec![SessionRow {
            sid: "codex-alpha".into(),
            entries: None,
            base_path: String::new(),
        }];

        assert!(parse_session_selection("0", &rows).is_err());
        assert!(parse_session_selection("missing", &rows).is_err());
    }

    #[test]
    fn split_run_args_extracts_autostart() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        let (auto, out, seed, dirty, pass) =
            split_run_args(&v(&["--autostart", "--out", "s.ltx", "-y"]));
        assert!(auto);
        assert_eq!(out.unwrap().to_str().unwrap(), "s.ltx");
        assert!(seed.is_none() && dirty.is_none());
        assert_eq!(pass, v(&["-y"]));

        // without --autostart, --out is not stripped (but --seed always is)
        let (auto, out, seed, dirty, pass) = split_run_args(&v(&["--out", "s.ltx", "--seed", "."]));
        assert!(!auto && out.is_none());
        assert_eq!(seed.unwrap().to_str().unwrap(), ".");
        assert!(dirty.is_none());
        assert_eq!(pass, v(&["--out", "s.ltx"]));

        // flags may come after positional args
        let (auto, _, _, _, pass) = split_run_args(&v(&["-y", "--autostart"]));
        assert!(auto);
        assert_eq!(pass, v(&["-y"]));
    }

    #[test]
    fn split_run_args_extracts_seed_dirty() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        let (_, _, seed, dirty, pass) =
            split_run_args(&v(&["--seed", ".", "--seed-dirty", "all", "-y"]));
        assert_eq!(seed.unwrap().to_str().unwrap(), ".");
        assert_eq!(dirty.as_deref(), Some("all"));
        assert_eq!(pass, v(&["-y"]));

        // --seed-dirty without --seed is still stripped (harmless, ignored later)
        let (_, _, seed, dirty, pass) = split_run_args(&v(&["--seed-dirty", "head", "task"]));
        assert!(seed.is_none() && dirty.as_deref() == Some("head"));
        assert_eq!(pass, v(&["task"]));
    }

    #[test]
    fn parse_dirty_mode_validates() {
        assert_eq!(parse_dirty_mode("ask").unwrap(), DirtyMode::Ask);
        assert_eq!(parse_dirty_mode("all").unwrap(), DirtyMode::All);
        assert_eq!(parse_dirty_mode("head").unwrap(), DirtyMode::Head);
        assert!(parse_dirty_mode("").is_err());
        assert!(parse_dirty_mode("wat").is_err());
    }

    #[test]
    fn scrub_drops_injected_auth_headers() {
        assert!(scrub_drop_line(
            "\textraheader = AUTHORIZATION: basic dXNlcjp0b2s=\n"
        ));
        assert!(scrub_drop_line("    http.extraHeader = Bearer tok\n"));
        assert!(!scrub_drop_line("\turl = https://user:tok@host/x.git\n"));
        assert!(!scrub_drop_line("\tbare = true\n"));
        assert!(!scrub_drop_line("[http \"https://example.com\"]\n"));
    }

    /// Unborn HEAD + dirty worktree + dirt excluded: refuse to seed rather    /// than silently seeding the dirt despite --seed-dirty=head / a "no".
    #[test]
    fn resolve_seed_unborn_dirty_bails_when_dirt_excluded() {
        let dir = std::env::temp_dir().join(format!("den-seedtest-unborn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "dirty\n").unwrap();
        let st = std::process::Command::new("git")
            .args(["init", "-q", "."])
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(st.success());

        let rs = resolve_seed_source(&dir, DirtyMode::Head);
        let err = rs.unwrap_err().to_string();
        assert!(err.contains("unborn"), "err: {err}");
        // Ask mode in a non-TTY test run also declines the dirt (same path).
        let err2 = resolve_seed_source(&dir, DirtyMode::Ask)
            .unwrap_err()
            .to_string();
        assert!(err2.contains("unborn"), "err: {err2}");
        // --seed-dirty all is the escape hatch.
        let rs3 = resolve_seed_source(&dir, DirtyMode::All).unwrap();
        assert!(rs3.head_sha.is_none() && rs3.git_dir.is_some());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Dirty repo + --seed-dirty head: seeds exactly HEAD via `git archive`
    /// (dirty edit and untracked file excluded), and seeds the repo's `.git`
    /// as `/.git` into the session DB. Also checks the non-repo fallback.
    #[test]
    fn resolve_seed_head_extracts_committed_state() {
        let git = |dir: &Path, c: &str| {
            let st = std::process::Command::new("sh")
                .arg("-c")
                .arg(c)
                .current_dir(dir)
                .status()
                .unwrap();
            assert!(st.success(), "cmd failed: {c}");
        };
        let dir = std::env::temp_dir().join(format!("den-seedtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "committed\n").unwrap();
        git(&dir, "git init -q .");
        git(
            &dir,
            "git remote add origin https://user:tok123@github.com/x/y.git",
        );
        git(&dir, "git -c user.email=t@t -c user.name=t add a.txt");
        git(&dir, "git -c user.email=t@t -c user.name=t commit -qm init");
        std::fs::write(dir.join("a.txt"), "dirty\n").unwrap();
        std::fs::write(dir.join("untracked.txt"), "x\n").unwrap();

        let rs = resolve_seed_source(&dir, DirtyMode::Head).unwrap();
        assert!(rs.temp && rs.note.as_deref().unwrap().contains("excluded"));
        assert!(rs.head_sha.is_some(), "seed-time HEAD sha must be captured");
        assert_eq!(
            std::fs::read_to_string(rs.src.join("a.txt")).unwrap(),
            "committed\n"
        );
        assert!(!rs.src.join("untracked.txt").exists());
        assert!(rs.git_dir.as_ref().unwrap().ends_with(".git"));

        // Full path: seed into a session DB, /.git must land with real history.
        let sid = format!("selftest-seedgit-{}", std::process::id());
        let dbp = session_db_path(&sid).unwrap();
        block_on(async {
            std::fs::create_dir_all(dbp.parent().unwrap())?;
            let opts = AgentFSOptions::with_path(dbp.to_string_lossy().to_string());
            let agent = AgentFS::open(opts).await?;
            seed_session(&agent, &rs.src, rs.git_dir.as_deref()).await?;
            let snap = snapshot_fs(&agent).await;
            assert!(snap.contains_key("/a.txt"));
            assert!(snap.contains_key("/.git/HEAD"));
            // /.git ships with the session — its config url must arrive
            // credential-free.
            let cfg_raw = agent.fs.read_file("/.git/config").await?.unwrap();
            let cfg = String::from_utf8_lossy(&cfg_raw);
            assert!(cfg.contains("https://github.com/x/y.git"), "url: {cfg}");
            assert!(!cfg.contains("tok123"), "credentials leaked: {cfg}");
            anyhow::Ok(())
        })
        .unwrap()
        .unwrap();

        std::fs::remove_dir_all(&rs.src).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let _ = std::fs::remove_dir_all(dbp.parent().unwrap());

        // Non-repo dir: no git context, live seed, no temp.
        let plain = std::env::temp_dir().join(format!("den-seedtest-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&plain);
        std::fs::create_dir_all(&plain).unwrap();
        let rs2 = resolve_seed_source(&plain, DirtyMode::Ask).unwrap();
        assert!(rs2.git_dir.is_none() && !rs2.temp && rs2.note.is_none());
        std::fs::remove_dir_all(&plain).unwrap();
    }

    #[test]
    fn replica_url_resolution_precedence() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LITESTREAM_BUCKET", "mybucket");
        std::env::remove_var("DEN_REPLICA");
        std::env::remove_var("LITESTREAM_REPLICA_URL");

        // bucket alone synthesizes a per-session path
        assert_eq!(
            replica_url("codex-foo", None).unwrap(),
            "s3://mybucket/codex-foo/db"
        );
        // explicit arg beats everything
        assert_eq!(
            replica_url("codex-foo", Some("s3://other/x")).unwrap(),
            "s3://other/x"
        );
        // LITESTREAM_REPLICA_URL beats the bucket
        std::env::set_var("LITESTREAM_REPLICA_URL", "s3://env-bucket/env-path");
        assert_eq!(
            replica_url("codex-foo", None).unwrap(),
            "s3://env-bucket/env-path"
        );
        // DEN_REPLICA beats both
        std::env::set_var("DEN_REPLICA", "s3://den-bucket/den-path");
        assert_eq!(
            replica_url("codex-foo", None).unwrap(),
            "s3://den-bucket/den-path"
        );
        std::env::remove_var("DEN_REPLICA");
        std::env::remove_var("LITESTREAM_REPLICA_URL");
        std::env::remove_var("LITESTREAM_BUCKET");
        assert!(replica_url("codex-foo", None).is_err());
    }

    #[test]
    fn litestream_autostart_requires_binary_and_replica() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LITESTREAM_BUCKET", "b");
        std::env::set_var("DEN_LITESTREAM", "/bin/true"); // exists, so bin_found
        assert!(litestream_autostart("x"));

        std::env::set_var("DEN_LITESTREAM", "/nonexistent/den-ls");
        assert!(!litestream_autostart("x")); // binary missing -> LTX fallback

        std::env::remove_var("LITESTREAM_BUCKET");
        std::env::remove_var("DEN_LITESTREAM");
        assert!(!litestream_autostart("x")); // no replica -> LTX fallback
    }
}
