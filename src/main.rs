//! pit — run any local coding-agent CLI inside an AgentFS sandbox, with typed
//! SDK access to what it did.
//!
//! Design split (see README.md):
//!   * OS sandbox: exec'd by the `agentfs` CLI (`agentfs run ...`). The FUSE +
//!     user/mount-namespace isolation is NOT in the agentfs-sdk crate; it's
//!     ~400 lines of unsafe libc in the CLI. We do not reimplement it.
//!   * State: this binary binds `agentfs-sdk` to open the session's persisted
//!     delta DB (`~/.agentfs/run/<sid>/delta.db`) in-process and surface a
//!     typed diff (changed/deleted paths) + tool-call timeline.
//!
//! Usage:
//!   pit <profile> [args...]      run the agent in the sandbox; print delta after
//!   pit dump <profile> [args...] print the `agentfs run` argv (no exec)
//!   pit inspect <session-id>     open a session's delta DB and show diff+timeline
//!   pit sessions                 list persisted sessions under ~/.agentfs/run
//!   pit list                     list configured profiles
//!   pit selftest                 sanity-check argv assembly (no agentfs needed)
//!
//! Env:
//!   SB_SESSION=<id>  reuse/resume this session id (default <profile>-<cwd-slug>)
//!   SB_NEW=1         start a fresh unique session instead of the default id
//!   PIT_AGENTFS=<bin>  path to the agentfs binary (default: agentfs on PATH)
//!   SB_QUIET=1       don't print the post-run delta summary

use agentfs_sdk::{AgentFS, AgentFSOptions, ToolCall};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        "claude" => Profile { cmd: vec!["claude".into()], allows: cfg() },
        "codex" => Profile { cmd: vec!["codex".into()], allows: cfg() },
        "gemini" => Profile { cmd: vec!["gemini".into()], allows: cfg() },
        "pi" => Profile { cmd: vec!["pi".into()], allows: cfg().into_iter().chain([format!("{home}/.pi")]).collect() },
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

/// session id: SB_SESSION wins, else SB_NEW=1 -> fresh uuid, else <profile>-<cwd-slug>
fn session_id(profile: &str) -> String {
    if let Ok(s) = std::env::var("SB_SESSION") {
        if !s.is_empty() {
            return s;
        }
    }
    if std::env::var("SB_NEW").as_deref() == Ok("1") {
        return new_uuid();
    }
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!("{}-{}", profile, slug(&cwd))
}

fn agentfs_bin() -> String {
    std::env::var("PIT_AGENTFS").unwrap_or_else(|_| "agentfs".to_string())
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
/// SB_NO_DROP=1 keeps the old join-blind behaviour.
fn drop_stale_session(sid: &str, allows: &[String]) -> Result<()> {
    if std::env::var("SB_NO_DROP").as_deref() == Ok("1") {
        return Ok(());
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    let run_dir = PathBuf::from(format!("{home}/.agentfs/run"));
    let dir = run_dir.join(sid);
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let stamp = format!("{cwd}\n{}", allows.join("\n"));
    let stamp_path = run_dir.join(".stamps").join(sid);

    if dir.exists() {
        if std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str()) {
            return Ok(()); // same config — join, keeping the previous delta
        }
        // A previous run may have left a stale FUSE mount on <dir>/mnt (crash,
        // timeout, Ctrl-C cleanup race). Unmount before touching the dir, else
        // the kernel keeps a mount attached to a dead path and the next
        // session at that path fails with ENOENT.
        let mnt = dir.join("mnt");
        if mnt.exists() {
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
        if session_has_changes(&dir) {
            // ponytail: archives are never GC'd — rm ~/.agentfs/run/*.archived-* by hand
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let name = format!("{sid}.archived-{ts}");
            std::fs::rename(&dir, run_dir.join(&name)).with_context(|| format!("archive session {sid}"))?;
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

/// True if the session's delta DB records any change. Fails closed (true) so
/// an unreadable DB gets archived, not deleted.
fn session_has_changes(dir: &Path) -> bool {
    let db = dir.join("delta.db");
    if !db.exists() {
        return false;
    }
    let has = |rt: tokio::runtime::Runtime| {
        rt.block_on(async {
            let opts = AgentFSOptions::with_path(db.to_string_lossy().to_string());
            match AgentFS::open(opts).await {
                Ok(a) => {
                    let (delta, whiteouts) = fetch_diff(&a).await;
                    !delta.is_empty() || !whiteouts.is_empty()
                }
                Err(_) => true,
            }
        })
    };
    match tokio::runtime::Runtime::new() {
        Ok(rt) => has(rt),
        Err(_) => true,
    }
}

/// Ignore SIGINT/SIGTERM in `pit` itself while the sandboxed agent runs.
/// `agentfs run` and the agent are in the same process group, so when you hit
/// Ctrl-C the kernel delivers SIGINT to the whole group. `agentfs` already
/// handles it (forward to child; SIGKILL on the second). If `pit` kept the
/// default disposition it would die mid-wait and short-circuit that cleanup.
/// Ignoring here lets the agent own the keyboard exactly as it would without
/// the wrapper — `pit` just waits for `agentfs` to exit and then reports.
fn ignore_stdin_signals() {
    // SAFETY: sigaction with a valid struct and zeroed sa_mask is well-defined;
    // we install SIG_IGN which is async-signal-safe. No handler touches state.
    for sig in [libc::SIGINT, libc::SIGTERM] {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = libc::SIG_IGN;
        unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()); }
    }
}

/// profile allow dirs that actually exist on this host (missing ones are skipped)
fn effective_allows(p: &Profile) -> Vec<String> {
    p.allows.iter().filter(|a| Path::new(a).exists()).cloned().collect()
}

/// The exact argv we'd pass to exec `agentfs run`. Used by run, dump, selftest.
fn build_argv(
    agentfs: &str,
    profile_name: &str,
    sid: &str,
    passthrough: &[String],
) -> Result<Vec<String>> {
    let p = profile(profile_name).ok_or_else(|| {
        anyhow!("unknown profile '{profile_name}' (defined: {})", list_profiles().join(" "))
    })?;
    let mut v = vec![agentfs.to_string(), "run".into(), "--session".into(), sid.to_string()];
    for a in effective_allows(&p) {
        v.push("--allow".into());
        v.push(a);
    }
    for c in &p.cmd {
        v.push(c.clone());
    }
    // pi: default the session display name to the cwd slug so it's findable
    // in `pi -r`. Skip on resume/continue/session or an explicit --name —
    // renaming a session you're resuming would be a surprise.
    if profile_name == "pi"
        && !passthrough.iter().any(|a| {
            matches!(a.as_str(), "-c" | "--continue" | "-r" | "--resume" | "--session" | "-n" | "--name" | "--no-session")
        })
    {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        v.push("--name".into());
        v.push(slug(&cwd));
    }
    for a in passthrough {
        v.push(a.clone());
    }
    Ok(v)
}

// ---- AgentFS SDK: open a persisted session delta DB --------------------------
fn delta_db_path(sid: &str) -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(format!("{home}/.agentfs/run/{sid}/delta.db")))
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
    if std::env::var("SB_QUIET").as_deref() == Ok("1") {
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
        if untouched { "(host tree untouched)" } else { "" }
    );
    for p in sorted(&delta).iter().take(20) {
        eprintln!("  + {p}");
    }
    if delta.len() > 20 {
        eprintln!("  … {} more", delta.len() - 20);
    }
    for p in sorted(&whiteouts).iter().take(20) {
        eprintln!("  - {p}");
    }
    if whiteouts.len() > 20 {
        eprintln!("  … {} more deleted", whiteouts.len() - 20);
    }
}

// ---- subcommands -------------------------------------------------------------

fn cmd_run(profile_name: &str, passthrough: &[String]) -> Result<i32> {
    let bin = agentfs_bin();
    let sid = session_id(profile_name);
    let argv = build_argv(&bin, profile_name, &sid, passthrough)?;
    // spawn + wait (not exec) so we can print the SDK delta summary afterwards
    // signal handlers so SIGINT goes to the sandboxed agent (same pgrp) and
    // not to `pit`.
    ignore_stdin_signals();
    let status = match Command::new(&argv[0]).args(&argv[1..]).status() {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "agentfs CLI not found. Install it:\n  \
                 curl -fsSL https://github.com/tursodatabase/agentfs/releases/latest/download/agentfs-installer.sh | sh\n\
                 (or set PIT_AGENTFS=/path/to/agentfs)"
            );
        }
        Err(e) => bail!("failed to spawn {bin}: {e}"),
    };
    // This runs after the sandboxed agent has exited and the delta DB is
    // persisted — the point where we bind the SDK.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(print_run_summary(&sid));
    Ok(status.code().unwrap_or(1))
}

fn cmd_dump(profile_name: &str, passthrough: &[String]) -> Result<()> {
    let argv = build_argv(&agentfs_bin(), profile_name, &session_id(profile_name), passthrough)?;
    println!("{}", argv.join(" "));
    Ok(())
}

fn cmd_inspect(sid: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
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
                let dur = t.duration_ms.map(|d| format!("{d}ms")).unwrap_or_else(|| "--".into());
                println!("  {:>5}  {:<8}  {:<8}  {}", t.id, t.name, t.status, dur);
            }
        }
        Ok(())
    })
}

fn cmd_sessions() -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let run_dir = PathBuf::from(format!("{home}/.agentfs/run"));
    if !run_dir.exists() {
        println!("(no sessions at {})", run_dir.display());
        return Ok(());
    }
    let mut sids: Vec<String> = std::fs::read_dir(&run_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir() && !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    sids.sort();
    if sids.is_empty() {
        println!("(no sessions)");
        return Ok(());
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        for sid in &sids {
            let db = delta_db_path(sid)?;
            let base_path = std::fs::read_to_string(format!("{home}/.agentfs/run/{sid}/base_path"))
                .unwrap_or_default()
                .trim()
                .to_string();
            if !db.exists() {
                println!("{sid}\t(no delta DB)\t{base_path}");
                continue;
            }
            let (n_changed, n_deleted) = match open_session(sid).await {
                Ok(Some(a)) => {
                    let (d, w) = fetch_diff(&a).await;
                    (d.len(), w.len())
                }
                _ => (0, 0),
            };
            println!("{sid}\t{n_changed} changed, {n_deleted} deleted\t{base_path}");
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn cmd_selftest() -> Result<()> {
    // Deterministic: pin the session id, assert argv assembly + passthrough.
    std::env::set_var("SB_SESSION", "selftest-sid");
    let argv = build_argv(
        "agentfs",
        "codex",
        &session_id("codex"),
        &["exec".into(), "--json".into(), "-m".into(), "gpt-5".into()],
    )?;
    std::env::remove_var("SB_SESSION");

    let joined = argv.join("\u{1f}"); // unit separator so substring matches are unambiguous
    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !($cond) {
                bail!("selftest FAIL: {}\nargv: {:?}", $msg, joined);
            }
        };
    }
    check!(argv[0] == "agentfs", "bin slot");
    check!(argv[1] == "run", "run subcommand");
    check!(joined.contains("\u{1f}--session\u{1f}selftest-sid\u{1f}"), "session id");
    check!(
        joined.contains("\u{1f}codex\u{1f}exec\u{1f}--json\u{1f}-m\u{1f}gpt-5"),
        "passthrough incl. flags"
    );
    check!(joined.contains("--allow"), "at least one --allow");
    println!("selftest OK");
    println!("  {}", argv.join(" "));
    Ok(())
}

fn usage() -> String {
    "usage:\n  \
     pit <profile> [args...]      run agent in the sandbox\n  \
     pit dump <profile> [args...] print the agentfs run argv\n  \
     pit inspect <session-id>     show diff + timeline for a session\n  \
     pit sessions                 list persisted sessions\n  \
     pit list                     list profiles\n  \
     pit selftest                 sanity check\n"
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
        [c] if c == "selftest" => cmd_selftest(),
        [c] if c == "sessions" => cmd_sessions(),
        [c] if c == "help" || c == "--help" || c == "-h" => {
            println!("{}", usage());
            Ok(())
        }
        [c, rest @ ..] if c == "dump" => {
            let (pname, passthrough) = split_profile(rest)?;
            cmd_dump(&pname, &passthrough)
        }
        [c, rest @ ..] if c == "inspect" => {
            let sid = rest
                .first()
                .ok_or_else(|| anyhow!("pit inspect <session-id>"))?;
            cmd_inspect(sid)
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
            let sid = session_id(pname);
            let allows = effective_allows(&profile(pname).expect("profile checked above"));
            drop_stale_session(&sid, &allows)?;
            let code = cmd_run(pname, passthrough)?;
            std::process::exit(code);
        }
    }
}

/// For `dump`: everything after `dump` is `<profile> [passthrough...]`.
fn split_profile(rest: &[String]) -> Result<(String, Vec<String>)> {
    match rest {
        [] => bail!("pit dump <profile> [args...]"),
        [p, rest @ ..] => {
            if profile(p).is_none() {
                bail!("unknown profile '{p}' (defined: {})", list_profiles().join(" "));
            }
            Ok((p.clone(), rest.to_vec()))
        }
    }
}