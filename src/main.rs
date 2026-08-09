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
//!   PIT_SESSION=<id>  reuse/resume this session id (default <profile>-<cwd-slug>)
//!   PIT_NEW=1         start a fresh unique session instead of the default id
//!   PIT_AGENTFS=<bin>  path to the agentfs binary (default: agentfs on PATH)
//!   PIT_QUIET=1       don't print the post-run delta summary

use agentfs_sdk::{AgentFS, AgentFSOptions, ToolCall};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

mod backup;

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

fn agentfs_bin() -> String {
    std::env::var("PIT_AGENTFS").unwrap_or_else(|_| "agentfs".to_string())
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
        unsafe {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
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

/// The exact argv we'd pass to exec `agentfs run`. Used by run, dump, selftest.
fn build_argv(
    agentfs: &str,
    profile_name: &str,
    sid: &str,
    passthrough: &[String],
) -> Result<Vec<String>> {
    let p = profile(profile_name).ok_or_else(|| {
        anyhow!(
            "unknown profile '{profile_name}' (defined: {})",
            list_profiles().join(" ")
        )
    })?;
    let mut v = vec![
        agentfs.to_string(),
        "run".into(),
        "--session".into(),
        sid.to_string(),
    ];
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

fn cmd_run(profile_name: &str, sid: &str, passthrough: &[String]) -> Result<i32> {
    let bin = agentfs_bin();
    let argv = build_argv(&bin, profile_name, sid, passthrough)?;
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
    block_on(print_run_summary(sid))?;
    Ok(status.code().unwrap_or(1))
}

fn cmd_dump(profile_name: &str, passthrough: &[String]) -> Result<()> {
    let argv = build_argv(
        &agentfs_bin(),
        profile_name,
        &session_id(profile_name),
        passthrough,
    )?;
    println!("{}", argv.join(" "));
    Ok(())
}

fn cmd_inspect(sid: &str) -> Result<()> {
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

fn cmd_selftest() -> Result<()> {
    // Deterministic: pin the session id, assert argv assembly + passthrough.
    std::env::set_var("PIT_SESSION", "selftest-sid");
    let argv = build_argv(
        "agentfs",
        "codex",
        &session_id("codex"),
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
    check!(argv[0] == "agentfs", "bin slot");
    check!(argv[1] == "run", "run subcommand");
    check!(
        joined.contains("\u{1f}--session\u{1f}selftest-sid\u{1f}"),
        "session id"
    );
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
     pit inspect [session-id]     show diff + timeline for a session\n  \
     pit sessions [--select]      list persisted sessions, optionally choose one\n  \
     pit backup [sid] [--from prev.ltx] [--out path] [-c] [--watch]  LTX backup of a session's delta DB\n  \
     pit restore <file.ltx> [--to db]  apply an LTX backup (and chain) back into a session\n  \
     pit ltx <file.ltx>         inspect/verify a backup file\n  \
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
        [c, rest @ ..] if c == "inspect" => {
            let sid = match rest.first().map(String::as_str) {
                None | Some("--select") => select_session()?,
                Some(sid) => sid.to_string(),
            };
            cmd_inspect(&sid)
        }
        [c, rest @ ..] if c == "backup" => cmd_backup_args(rest),
        [c, rest @ ..] if c == "restore" => cmd_restore_args(rest),
        [c, rest @ ..] if c == "ltx" => {
            let path = rest.first().context("pit ltx <file.ltx>")?;
            if rest.len() > 1 {
                bail!("unexpected argument '{}'", rest[1]);
            }
            backup::cmd_ltx_info(Path::new(path))
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
            let code = cmd_run(pname, &sid, passthrough)?;
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
    // replay the numbered siblings so it comes back at its newest state
    let mut n = 1;
    loop {
        let next = backup::chain_path(&ltx, n);
        if !next.exists() {
            break;
        }
        backup::cmd_restore(&next, &to)?;
        n += 1;
    }
    if n > 1 {
        println!("pit: replayed {} chain delta(s) onto {}", n - 1, to.display());
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
}
