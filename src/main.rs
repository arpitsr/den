//! pit — run any local coding-agent CLI inside an AgentFS sandbox, with typed
//! SDK access to what it did.
//!
//! The sandbox is in-process (src/sandbox.rs, ported from the agentfs CLI,
//! MIT): a FUSE overlay (src/fuse.rs, via the published `fuser` crate) makes
//! the cwd copy-on-write, a fork+unshare child gets a fresh user+mount
//! namespace with the rest of the filesystem read-only, and every write lands
//! in the session's SQLite delta DB (~/.agentfs/run/<sid>/delta.db). After the
//! agent exits we bind `agentfs-sdk` to open that DB in-process and surface a
//! typed diff (changed/deleted paths) + tool-call timeline.
//!
//! Usage:
//!   pit <profile> [args...]      run the agent in the sandbox; print delta after
//!   pit dump <profile> [args...] print the resolved sandbox plan (no exec)
//!   pit inspect <session-id>     open a session's delta DB and show diff+timeline
//!   pit sessions                 list persisted sessions under ~/.agentfs/run
//!   pit replicate [sid] [url]    litestream daemon: stream the delta DB to S3 continuously
//!   pit pull [sid] [url]         restore a session's delta DB from the litestream replica
//!   pit list                     list configured profiles
//!   pit selftest                 sanity-check argv assembly
//!
//! Env:
//!   PIT_SESSION=<id>  reuse/resume this session id (default <profile>-<cwd-slug>)
//!   PIT_NEW=1         start a fresh unique session instead of the default id
//!   PIT_QUIET=1       don't print the post-run delta summary
//!   PIT_LITESTREAM=<bin>  path to the litestream binary (default: litestream on PATH)
//!   PIT_REPLICA=<url>    replica URL (default: LITESTREAM_REPLICA_URL, then LITESTREAM_BUCKET)
//!   PIT_DETACHED=1  (internal) spawned detached by --autostart; survives Ctrl-C on the run
//!   PIT_NET=proxy|none|full  network isolation (default proxy): slirp4netns netns +
//!     nft egress policy + allowlist proxy (see PIT_PROXY_ALLOW); none = netns only,
//!     full = host network (legacy)
//!   PIT_PROXY_ALLOW=comma,list  extra egress allowlist entries for PIT_NET=proxy
//!   PIT_HIDE=~/.a:~/.b  extra secrets to hide (colon-separated); PIT_NO_HIDE=~/.ssh restores
//!   PIT_LIMIT_FSIZE/NOFILE/NPROC/AS/CPU  agent rlimits (bytes or K/M/G; "unlimited")
//!   PIT_SECCOMP=0    disable the seccomp syscall deny-list (not recommended)

use agentfs_sdk::{AgentFS, AgentFSOptions, ToolCall};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

mod backup;
#[cfg(target_os = "linux")]
mod fuse;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod sandbox;

#[derive(Clone)]
struct Profile {
    cmd: Vec<String>,
    allows: Vec<String>, // extra host dirs to keep writable inside the sandbox
}

/// Built-in agent profiles. To add a custom agent, add a match arm (or bring
/// back a TOML config when you have more than a couple — YAGNI for now).
fn profile(name: &str) -> Option<Profile> {
    let home = std::env::var("HOME").ok()?;
    let cfg = || vec![format!("{home}/.config")];
    Some(match name {
        "claude" => Profile {
            cmd: vec!["claude".into()],
            allows: cfg(),
        },
        "codex" => Profile {
            cmd: vec!["codex".into()],
            allows: cfg(),
        },
        "gemini" => Profile {
            cmd: vec!["gemini".into()],
            allows: cfg(),
        },
        "pi" => Profile {
            cmd: vec!["pi".into()],
            allows: cfg().into_iter().chain([format!("{home}/.pi")]).collect(),
        },
        "opencode" => Profile {
            cmd: vec!["opencode".into()],
            allows: vec![format!("{home}/.config"), format!("{home}/.opencode")],
        },
        _ => return None,
    })
}

fn list_profiles() -> Vec<&'static str> {
    let mut v = ["claude", "codex", "gemini", "opencode", "pi"];
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

/// session id: PIT_SESSION wins, else PIT_NEW=1 -> fresh uuid, else <profile>-<cwd-slug>
fn session_id(profile: &str) -> String {
    if let Ok(s) = std::env::var("PIT_SESSION") {
        if !s.is_empty() {
            return s;
        }
    }
    if std::env::var("PIT_NEW").as_deref() == Ok("1") {
        return new_uuid();
    }
    format!("{}-{}", profile, slug(&cwd_string()))
}

fn litestream_bin() -> String {
    std::env::var("PIT_LITESTREAM").unwrap_or_else(|_| "litestream".to_string())
}

/// true if `bin` is an existing path itself, or resolves on PATH
fn bin_found(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).exists();
    }
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join(bin).is_file())
    })
}

/// Replica URL for a session's delta.db: explicit arg wins, then
/// PIT_REPLICA, then LITESTREAM_REPLICA_URL, then LITESTREAM_BUCKET with a
/// per-session path. Credentials are litestream's business (AWS_*/LITESTREAM_*
/// env vars — command-line mode, see https://litestream.io/reference/replicate/).
fn replica_url(sid: &str, explicit: Option<&str>) -> Result<String> {
    if let Some(u) = explicit {
        return Ok(u.to_string());
    }
    for var in ["PIT_REPLICA", "LITESTREAM_REPLICA_URL"] {
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
        "no replica configured — set PIT_REPLICA=s3://bucket/path, \
         LITESTREAM_REPLICA_URL, or LITESTREAM_BUCKET"
    )
}

/// true when `--autostart` should stream via litestream instead of the LTX watch
fn litestream_autostart(sid: &str) -> bool {
    bin_found(&litestream_bin()) && replica_url(sid, None).is_ok()
}

/// ~/.agentfs/run — where sessions (and their delta DBs) persist
pub(crate) fn run_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".agentfs/run"))
}

fn cwd_string() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

/// Run one future on a throwaway runtime (sync CLI entry points).
/// Note: if the future itself returns Result, you need `??` at the call site.
fn block_on<F: std::future::Future>(f: F) -> Result<F::Output> {
    Ok(tokio::runtime::Runtime::new()?.block_on(f))
}

/// Reuse-or-recreate gate for the persisted session dir.
///
/// `agentfs run --session X` silently JOINS an existing session and ignores
/// the --allow flags we pass, so a session created with a different config
/// (e.g. before we added ~/.pi to the allowlist) must be recreated — else the
/// agent hits EROFS on the missing path. But the session dir also holds the
/// delta DB, i.e. every change the agent made; deleting it unconditionally
/// throws that work away. So:
///
///   config unchanged               -> join the session, delta survives
///   config changed, delta empty    -> delete, start fresh
///   config changed, delta has work -> archive (rename aside), never delete
///
/// "Config" = cwd + effective --allow list, stamped to .stamps/<sid>.
/// PIT_NO_DROP=1 keeps the old join-blind behaviour.
fn drop_stale_session(sid: &str, allows: &[String]) -> Result<()> {
    if std::env::var("PIT_NO_DROP").as_deref() == Ok("1") {
        return Ok(());
    }
    let run_dir = run_dir()?;
    let dir = run_dir.join(sid);
    let stamp = format!("{}\n{}", cwd_string(), allows.join("\n"));
    let stamp_path = run_dir.join(".stamps").join(sid);

    if dir.exists() {
        if std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str()) {
            return Ok(()); // same config — join, keeping the previous delta
        }
        unmount_stale(&dir.join("mnt"));
        if session_has_changes(&dir) {
            // ponytail: archives are never GC'd — rm ~/.agentfs/run/*.archived-* by hand
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let name = format!("{sid}.archived-{ts}");
            std::fs::rename(&dir, run_dir.join(&name))
                .with_context(|| format!("archive session {sid}"))?;
            eprintln!("pit: config changed — archived previous session as {name} (pit inspect {name} to view)");
        } else {
            std::fs::remove_dir_all(&dir).with_context(|| format!("drop stale session {sid}"))?;
            eprintln!("pit: dropped stale session {sid} (config changed, nothing to keep)");
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

/// True if the session's delta DB records any change. Fails closed (true) so
/// an unreadable DB gets archived, not deleted.
fn session_has_changes(dir: &Path) -> bool {
    let db = dir.join("delta.db");
    if !db.exists() {
        return false;
    }
    let check = async {
        let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
        match AgentFS::open(opts).await {
            Ok(a) => {
                let (delta, whiteouts) = fetch_diff(&a).await;
                !delta.is_empty() || !whiteouts.is_empty()
            }
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
    let p = profile(profile_name).ok_or_else(|| {
        anyhow!(
            "unknown profile '{profile_name}' (defined: {})",
            list_profiles().join(" ")
        )
    })?;
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

// ---- AgentFS SDK: open a persisted session delta DB --------------------------
/// ~/.agentfs/run/<sid>/delta.db — the session's persisted change log
pub(crate) fn delta_db_path(sid: &str) -> Result<PathBuf> {
    Ok(run_dir()?.join(sid).join("delta.db"))
}

/// Open the session's delta layer via the SDK. Returns None if the DB isn't
/// there (e.g. the run never happened or agentfs failed before writing it).
async fn open_session(sid: &str) -> Result<Option<AgentFS>> {
    let p = delta_db_path(sid)?;
    if !p.exists() {
        return Ok(None);
    }
    let opts = AgentFSOptions::with_path(p.to_string_lossy().to_string());
    match AgentFS::open(opts).await {
        Ok(a) => Ok(Some(a)),
        Err(e) => bail!("open delta DB for session {sid}: {e}"),
    }
}

async fn fetch_diff(agent: &AgentFS) -> (HashSet<String>, HashSet<String>) {
    let delta = agent.get_delta_paths().await.unwrap_or_default();
    let whiteouts = agent.get_whiteouts().await.unwrap_or_default();
    (delta, whiteouts)
}

async fn print_diff_labels(agent: &AgentFS, sid: &str) {
    if let Ok(Some(base)) = agent.is_overlay_enabled().await {
        println!("session {sid} (overlay base: {base})");
    } else {
        println!("session {sid}");
    }
}

fn sorted(v: &HashSet<String>) -> Vec<&String> {
    let mut s: Vec<_> = v.iter().collect();
    s.sort();
    s
}

/// compact post-run summary: "session X — 3 changed, 1 deleted" + capped listing
async fn print_run_summary(sid: &str) {
    if std::env::var("PIT_QUIET").as_deref() == Ok("1") {
        return;
    }
    let agent = match open_session(sid).await {
        Ok(Some(a)) => a,
        Ok(None) => return, // no delta DB yet — nothing to summarize
        Err(e) => {
            eprintln!("\nagentfs: {e}");
            return;
        }
    };
    let (delta, whiteouts) = fetch_diff(&agent).await;
    eprintln!();
    let untouched = delta.is_empty() && whiteouts.is_empty();
    eprintln!(
        "agentfs: session {sid} — {} changed, {} deleted {}",
        delta.len(),
        whiteouts.len(),
        if untouched {
            "(host tree untouched)"
        } else {
            ""
        }
    );
    for p in sorted(&delta).into_iter().take(20) {
        eprintln!("  + {p}");
    }
    if delta.len() > 20 {
        eprintln!("  … {} more", delta.len() - 20);
    }
    for p in sorted(&whiteouts).into_iter().take(20) {
        eprintln!("  - {p}");
    }
    if whiteouts.len() > 20 {
        eprintln!("  … {} more deleted", whiteouts.len() - 20);
    }
}

// ---- subcommands -------------------------------------------------------------

fn cmd_run(
    profile_name: &str,
    sid: &str,
    passthrough: &[String],
    autostart: bool,
    auto_out: Option<PathBuf>,
) -> Result<i32> {
    let argv = build_argv(profile_name, passthrough)?;
    let allows = effective_allows(&profile(profile_name).expect("profile checked by caller"));
    if autostart {
        spawn_watch(sid, auto_out.as_deref())?;
    }
    // The sandbox is in-process: FUSE overlay + fork/unshare child. The child
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
    ))
    ??;
    #[cfg(not(target_os = "linux"))]
    let code = {
        // ponytail: the macOS NFS+sandbox-exec path was not ported; the FUSE
        // sandbox is Linux-only. Re-add when macOS matters (port cli/src/sandbox/darwin.rs).
        let _ = (allows, &argv);
        bail!("pit's in-process sandbox is Linux-only; run pit on Linux")
    };
    // This runs after the sandboxed agent has exited and the delta DB is
    // persisted — the point where we bind the SDK.
    block_on(print_run_summary(sid))?;
    Ok(code)
}

/// Strip pit's own `--autostart [--out <base.ltx>]` from a run's passthrough
/// args (the rest go to agentfs). Nothing is stripped unless --autostart is
/// present, so plain agent args are never eaten.
fn split_run_args(rest: &[String]) -> (bool, Option<PathBuf>, Vec<String>) {
    let autostart = rest.iter().any(|a| a == "--autostart");
    if !autostart {
        return (false, None, rest.to_vec());
    }
    let mut out = None;
    let mut pass = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--autostart" => {}
            "--out" if rest.get(i + 1).is_some() => {
                out = Some(PathBuf::from(&rest[i + 1]));
                i += 1;
            }
            a => pass.push(a.to_string()),
        }
        i += 1;
    }
    (true, out, pass)
}

/// Spawn a detached `pit` subcommand for this session: stdin null, output to
/// `<session>/<log_name>`, PIT_DETACHED=1 so the subcommand knows it must
/// survive `pit run`'s Ctrl-C. The child inherits `pit run`'s SIG_IGN for
/// SIGINT/SIGTERM, so it outlives Ctrl-C; subcommands restore TERM handling
/// themselves so `kill` still stops them.
fn spawn_detached(sid: &str, args: &[&str], log_name: &str) -> Result<u32> {
    let log = crate::run_dir()?.join(sid).join(log_name);
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(args)
        .env("PIT_DETACHED", "1")
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

/// `pit <profile> --autostart`: stream the session's changes while the agent
/// works. Preferred: a detached litestream daemon continuously replicating
/// the delta DB to S3 (`pit replicate <sid>`), when a replica is configured
/// (PIT_REPLICA / LITESTREAM_REPLICA_URL / LITESTREAM_BUCKET) and the
/// binary is installed. Fallback: the local LTX chain watch (`pit backup
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
            "pit: autostarted litestream for {sid} -> {} (pid {pid}, log: {})",
            replica_url(sid, None)?,
            crate::run_dir()?.join(sid).join("replicate.log").display()
        );
        return Ok(());
    }
    let out = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(format!("{sid}.ltx")));
    let log = crate::run_dir()?.join(sid).join("backup-watch.log");
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["backup", sid, "--watch", "--out"])
        .arg(&out)
        .env("PIT_DETACHED", "1")
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
        "pit: autostarted backup watch for {sid} -> {} (log: {})",
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
    let path = run_dir()?.join(sid).join("replicate.lock");
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
/// of being orphaned when `pit replicate` is Ctrl-C'd or killed.
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

/// `pit replicate [sid] [replica-url]` — run a litestream daemon that
/// continuously replicates the session's delta.db to S3. Command-line mode
/// (`litestream replicate <db> <url>`, flags before positionals); credentials
/// come from AWS_*/LITESTREAM_* env vars, so no config file is generated.
/// `-restore-if-db-not-exists` pulls the session back from the replica on a
/// fresh machine. Foreground by default (Ctrl-C stops it); `pit <profile>
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
             (or set PIT_LITESTREAM=/path/to/litestream)"
        );
    }
    let session_dir = run_dir()?.join(sid);
    std::fs::create_dir_all(&session_dir)?;
    let db = session_dir.join("delta.db");
    let _lock = replicate_lock(sid)?;
    // Manual runs: Ctrl-C must stop litestream. Detached runs keep the
    // inherited SIG_IGN for SIGINT so they survive Ctrl-C on `pit run`;
    // TERM is restored in both so `kill` works.
    if std::env::var("PIT_DETACHED").as_deref() != Ok("1") {
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
        "pit: litestream replicating {sid} -> {url} (pid {}, db: {})",
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
            eprintln!("pit: session {sid} gone — stopping litestream");
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
    }
}

/// `pit pull [sid] [replica-url] [--force] [--to <db>]` — restore the
/// session's delta.db from the litestream replica (newest state), defaulting
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
             (or set PIT_LITESTREAM=/path/to/litestream)"
        );
    }
    let to = to.unwrap_or(delta_db_path(sid)?);
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
    println!("pit: restored {sid} from {url} -> {}", to.display());
    Ok(())
}

fn cmd_dump(profile_name: &str, passthrough: &[String]) -> Result<()> {
    let sid = session_id(profile_name);
    let argv = build_argv(profile_name, passthrough)?;
    let allows = effective_allows(&profile(profile_name).expect("profile checked by caller"));
    println!("session: {sid}");
    println!("delta db: {}", delta_db_path(&sid)?.display());
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
        let db_path = delta_db_path(sid)?;
        let agent = match open_session(sid).await? {
            Some(a) => a,
            None => bail!("no delta DB for session {sid} at {}", db_path.display()),
        };
        print_diff_labels(&agent, sid).await;
        let (delta, whiteouts) = fetch_diff(&agent).await;
        println!("changed ({}):", delta.len());
        for p in sorted(&delta) {
            println!("  + {p}");
        }
        println!("deleted ({}):", whiteouts.len());
        for p in sorted(&whiteouts) {
            println!("  - {p}");
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
    changed: Option<(usize, usize)>,
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
        let db = session_dir.join("delta.db");
        let base_path = std::fs::read_to_string(session_dir.join("base_path"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let changed = if db.exists() {
            let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
            match AgentFS::open(opts).await {
                Ok(agent) => {
                    let (delta, whiteouts) = fetch_diff(&agent).await;
                    Some((delta.len(), whiteouts.len()))
                }
                Err(_) => Some((0, 0)),
            }
        } else {
            None
        };
        rows.push(SessionRow {
            sid,
            changed,
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
            let counts = match row.changed {
                Some((changed, deleted)) => format!("{changed} changed, {deleted} deleted"),
                None => "(no delta DB)".to_string(),
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
    let run_dir = run_dir()?;
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

/// Session ids are directory names under ~/.agentfs/run (slug, PIT_SESSION,
/// or a listed session) — refuse anything that could escape the tree: a
/// stray `pit rm ..` must not delete ~/.agentfs itself.
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
    std::fs::remove_dir_all(&dir).with_context(|| format!("rm session {sid}"))?;
    let stamp = run_dir.join(".stamps").join(sid);
    if stamp.exists() {
        std::fs::remove_file(&stamp).with_context(|| format!("rm stamp {sid}"))?;
    }
    println!("pit: removed session {sid}");
    Ok(())
}

fn cmd_selftest(rest: &[String]) -> Result<()> {
    if rest.iter().any(|a| a == "--sandbox") {
        selftest_sandbox()?;
        return Ok(());
    }
    // Deterministic: pin the session id, assert argv assembly + passthrough.
    std::env::set_var("PIT_SESSION", "selftest-sid");
    let argv = build_argv(
        "codex",
        &["exec".into(), "--json".into(), "-m".into(), "gpt-5".into()],
    )?;
    std::env::remove_var("PIT_SESSION");

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

/// Full sandbox round-trip: FUSE overlay + fork/unshare child in a temp dir.
/// Verifies (1) writes land in the delta DB, not on the host, (2) deletes
/// become whiteouts, (3) the host tree is untouched, (4) the rest of the
/// filesystem is actually read-only.
fn selftest_sandbox() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("selftest --sandbox is Linux-only");

    #[cfg(target_os = "linux")]
    {
        let dir = std::env::temp_dir().join(format!("pit-sandbox-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("README.md"), "hello\n")?;
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("src/a.txt"), "orig\n")?;
        std::env::set_current_dir(&dir)?;

        let sid = format!("selftest-sandbox-{}", std::process::id());
        let script = "echo new > created.txt; rm README.md; mkdir -p dir1; echo x > dir1/f.txt";
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), script.into()],
        ))
        ??;
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

        // Delta DB: created.txt + dir1/f.txt changed, README.md deleted.
        let sid_check = sid.clone();
        let (delta, whiteouts) = block_on(async move {
            let agent = open_session(&sid_check).await?.context("no delta DB after run")?;
            let d = agent.get_delta_paths().await.unwrap_or_default();
            let w = agent.get_whiteouts().await.unwrap_or_default();
            anyhow::Ok((d, w))
        })
        ??;
        for p in ["/created.txt", "/dir1/f.txt"] {
            check_sandbox(delta.contains(p), true, &format!("delta contains {p}"))?;
        }
        check_sandbox(
            whiteouts.contains("/README.md"),
            true,
            "whiteout contains /README.md",
        )?;

        // Read-only enforcement: /etc is not writable from inside the sandbox.
        let diag = format!("/tmp/pit-sandbox-diag-{}.txt", std::process::id());
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec![
                "-c".into(),
                format!("{{ ls -la; echo ---; cat created.txt; }} > {diag} 2>&1"),
            ],
        ))
        ??;
        if let Ok(d) = std::fs::read_to_string(&diag) {
            println!("{d}");
        }
        let _ = std::fs::remove_file(&diag);
        check_sandbox(code == 0, true, "diagnostic run exit code")?;

        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "touch /etc/pit-sandbox-evil".into()],
        ))
        ??;
        check_sandbox(code != 0, true, "/etc write rejected (EROFS)")?;

        // Session join: second run with the same sid joins, delta survives.
        let code = block_on(sandbox::run_cmd(
            Vec::new(),
            sid.clone(),
            "/bin/sh".into(),
            vec!["-c".into(), "echo more >> created.txt".into()],
        ))
        ??;
        check_sandbox(code == 0, true, "join-session run exit code")?;

        std::fs::remove_dir_all(&dir)?;
        let _ = std::fs::remove_dir_all(delta_db_path(&sid)?.parent().unwrap_or(std::path::Path::new("")));
        println!("sandbox selftest OK (mount, delta, whiteouts, ro-enforcement, join)");
    }
    Ok(())
}

fn check_sandbox(cond: bool, expected: bool, what: &str) -> Result<()> {
    if cond != expected {
        bail!("sandbox selftest FAIL: {what} (got {cond}, expected {expected})");
    }
    Ok(())
}

fn usage() -> String {
    "usage:\n  \
     pit <profile> [args...]      run agent in the sandbox; --autostart streams a backup watch\n  \
     pit dump <profile> [args...] print the resolved sandbox plan (no exec)\n  \
     pit inspect [session-id]     show diff + timeline for a session\n  \
     pit sessions [--select]      list persisted sessions, optionally choose one\n  \
     pit rm <session-id>          delete a session dir (unmounts stale mounts first)\n  \
     pit replicate [sid] [url]    stream a session's delta DB to S3 via litestream (daemon)
  \
     pit pull [sid] [url] [--force] [--to db]   restore a session from its litestream replica
  \
     pit backup [sid] [--from prev.ltx] [--out path] [-c] [--watch]  LTX backup of a session's delta DB\n  \
     pit restore <file.ltx> [--to db]  apply an LTX backup (and chain) back into a session\n  \
     pit ltx <file.ltx>         inspect/verify a backup file\n  \
     pit list                     list profiles\n  \
     pit selftest                 sanity check\n\n\
env: PIT_NET=proxy|none|full  PIT_PROXY_ALLOW  PIT_HIDE/PIT_NO_HIDE  PIT_LIMIT_*  PIT_SECCOMP\n"
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
                None => bail!("pit rm <session-id> (or --select)"),
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
        [c, rest @ ..] if c == "replicate" => cmd_replicate_args(rest),
        [c, rest @ ..] if c == "pull" => cmd_pull_args(rest),
        [c, rest @ ..] if c == "restore" => cmd_restore_args(rest),
        [c, rest @ ..] if c == "ltx" => {
            let path = rest.first().context("pit ltx <file.ltx>")?;
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
                let (cmd, args) = rest
                    .split_first()
                    .context("pit raw <cmd> [args...]")?;
                let sid = format!("raw-{}", std::process::id());
                let code = block_on(sandbox::run_cmd(
                    Vec::new(),
                    sid.clone(),
                    std::path::PathBuf::from(cmd),
                    args.to_vec(),
                ))
                ??;
                std::process::exit(code)
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("sandbox is Linux-only")
            }
        }
        [pname, passthrough @ ..] => {
            if profile(pname).is_none() {
                bail!(
                    "unknown profile '{pname}' (defined: {}). {}",
                    list_profiles().join(" "),
                    if pname == "run" {
                        "(did you mean: pit <profile>? run is implicit)"
                    } else {
                        ""
                    }
                );
            }
            let (autostart, auto_out, passthrough) = split_run_args(passthrough);
            let sid = session_id(pname);
            let allows = effective_allows(&profile(pname).expect("profile checked above"));
            drop_stale_session(&sid, &allows)?;
            let code = cmd_run(pname, &sid, &passthrough, autostart, auto_out)?;
            std::process::exit(code);
        }
    }
}

/// Consume `--flag <value>` at `rest[i]`, advancing `i` past both. The only
/// flag form backup/restore need — kept inline rather than a generic parser,
/// which would hide the small shape behind indirection.
fn take_value(rest: &[String], i: &mut usize, flag: &str) -> Result<PathBuf> {
    let v = rest.get(*i + 1).with_context(|| format!("{flag} needs a path"))?;
    *i += 2;
    Ok(PathBuf::from(v))
}

/// `pit backup [sid] [--from <prev.ltx>] [--out <path>] [-c] [--watch]` — sid
/// defaults to an interactive selection when `--select` is given or omitted
/// with no positional argument (mirrors `pit inspect`). `--watch` streams
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

/// `pit restore <file.ltx> [--to <db>]` — target defaults to the session the
/// file is named after (codex-foo.ltx -> ~/.agentfs/run/codex-foo/delta.db).
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
    let ltx = ltx.context("pit restore <file.ltx> [--to <db>]")?;
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
            "pit: replayed {} chain delta(s) onto {}",
            chain.len(),
            to.display()
        );
    }
    Ok(())
}

/// For `dump`: everything after `dump` is `<profile> [passthrough...]`.
fn split_profile(rest: &[String]) -> Result<(String, Vec<String>)> {
    match rest {
        [] => bail!("pit dump <profile> [args...]"),
        [p, rest @ ..] => {
            if profile(p).is_none() {
                bail!(
                    "unknown profile '{p}' (defined: {})",
                    list_profiles().join(" ")
                );
            }
            Ok((p.clone(), rest.to_vec()))
        }
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
                changed: Some((2, 1)),
                base_path: "/tmp/alpha".into(),
            },
            SessionRow {
                sid: "pi-beta".into(),
                changed: None,
                base_path: String::new(),
            },
        ];

        let rendered = format_session_rows(&rows, true);

        assert!(rendered.contains("[1]\tcodex-alpha\t2 changed, 1 deleted\t/tmp/alpha"));
        assert!(rendered.contains("[2]\tpi-beta\t(no delta DB)\t"));
    }

    #[test]
    fn parse_session_selection_accepts_index_or_session_id() {
        let rows = vec![
            SessionRow {
                sid: "codex-alpha".into(),
                changed: None,
                base_path: String::new(),
            },
            SessionRow {
                sid: "pi-beta".into(),
                changed: None,
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
            changed: None,
            base_path: String::new(),
        }];

        assert!(parse_session_selection("0", &rows).is_err());
        assert!(parse_session_selection("missing", &rows).is_err());
    }

    #[test]
    fn split_run_args_extracts_autostart() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        let (auto, out, pass) = split_run_args(&v(&["--autostart", "--out", "s.ltx", "-y"]));
        assert!(auto);
        assert_eq!(out.unwrap().to_str().unwrap(), "s.ltx");
        assert_eq!(pass, v(&["-y"]));

        // without --autostart, nothing is stripped
        let (auto, out, pass) = split_run_args(&v(&["--out", "s.ltx"]));
        assert!(!auto && out.is_none());
        assert_eq!(pass, v(&["--out", "s.ltx"]));

        // flags may come after positional args
        let (auto, _, pass) = split_run_args(&v(&["-y", "--autostart"]));
        assert!(auto);
        assert_eq!(pass, v(&["-y"]));
    }

    #[test]
    fn replica_url_resolution_precedence() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LITESTREAM_BUCKET", "mybucket");
        std::env::remove_var("PIT_REPLICA");
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
        // PIT_REPLICA beats both
        std::env::set_var("PIT_REPLICA", "s3://pit-bucket/pit-path");
        assert_eq!(
            replica_url("codex-foo", None).unwrap(),
            "s3://pit-bucket/pit-path"
        );
        std::env::remove_var("PIT_REPLICA");
        std::env::remove_var("LITESTREAM_REPLICA_URL");
        std::env::remove_var("LITESTREAM_BUCKET");
        assert!(replica_url("codex-foo", None).is_err());
    }

    #[test]
    fn litestream_autostart_requires_binary_and_replica() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LITESTREAM_BUCKET", "b");
        std::env::set_var("PIT_LITESTREAM", "/bin/true"); // exists, so bin_found
        assert!(litestream_autostart("x"));

        std::env::set_var("PIT_LITESTREAM", "/nonexistent/pit-ls");
        assert!(!litestream_autostart("x")); // binary missing -> LTX fallback

        std::env::remove_var("LITESTREAM_BUCKET");
        std::env::remove_var("PIT_LITESTREAM");
        assert!(!litestream_autostart("x")); // no replica -> LTX fallback
    }
}
