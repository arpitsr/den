//! den serve — the platform API (docs/platform-api.md).
//!
//! A supervisor, not a sandbox host: every session is a direct child
//! process (`den <profile> …`), spawned with its own process group and
//! reaped here. The sandbox's fork chain stays untouched; the registry
//! (platform.db) is bookkeeping — fs.db is the truth.
//!
//! Env: DEN_API_TOKEN (required — no token, no server), DEN_BIND
//! (default 127.0.0.1:8520), DEN_MAX_RUNS (default 8).

use crate::registry::{self, NewRun, NewSession, Registry};
use crate::{
    bin_found, cmd_rm, delta_snapshot, diff_run_snap, headless_argv, open_session, random_suffix,
    session_base_db, session_db_path, sessions_root, snapshot_fs, valid_sid,
};
use anyhow::{bail, Context, Result};
use axum::extract::{Path as AxPath, Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::fd::AsRawFd as _;
// ExitStatusExt: signal() — did our SIGTERM/SIGKILL stop the child?
use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::process::Command;

/// platform.db sits next to the sessions root: ~/.den/platform.db
fn platform_db_path() -> Result<std::path::PathBuf> {
    Ok(sessions_root()?
        .parent()
        .context("den state dir")?
        .join("platform.db"))
}

/// Lock file for a session's live child, next to the session dir.
fn session_lock_path(sid: &str) -> Result<std::path::PathBuf> {
    Ok(sessions_root()?.join(format!("{sid}.lock")))
}

/// Delete a session's lock file after the child is gone (keep the tree tidy).
struct Child {
    run_id: String,
    pid: u32,
    killed: AtomicBool,
    /// flock(LOCK_EX) held until the child is reaped — one live process per
    /// session, across serve restarts and manual `den <profile>` runs.
    _lock: std::fs::File,
}

struct ServeState {
    reg: Arc<Registry>,
    token: String,
    max_runs: usize,
    /// sid -> live child (turn kind; daemon kind joins in Phase 2)
    children: Mutex<HashMap<String, Arc<Child>>>,
}

// ---- helpers ---------------------------------------------------------------

/// Constant-time token compare (length difference is fine to leak — the
/// scheme prefix is public).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn err_json(status: StatusCode, code: &str, msg: impl std::fmt::Display) -> Response {
    (
        status,
        Json(json!({"error": {"code": code, "message": msg.to_string()}})),
    )
        .into_response()
}

/// Run a registry op on the blocking pool (sync rusqlite behind a Mutex).
async fn reg<T, F>(r: &Arc<Registry>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Registry) -> Result<T> + Send + 'static,
{
    let r = r.clone();
    tokio::task::spawn_blocking(move || f(&r))
        .await
        .context("registry task")?
}

/// pid liveness via kill(pid, 0): a reaped child returns ESRCH, so this is
/// false for anything serve already reaped or that init reaped.
fn pid_alive(p: i32) -> bool {
    // SAFETY: kill with signal 0 only probes permission/existence.
    unsafe { libc::kill(p, 0) == 0 }
}

// ---- auth ------------------------------------------------------------------

async fn auth_mw(
    State(st): State<Arc<ServeState>>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let want = format!("Bearer {}", st.token);
    let ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|got| ct_eq(got, &want));
    if ok {
        next.run(req).await
    } else {
        err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or bad bearer token",
        )
    }
}

// ---- routes ----------------------------------------------------------------

fn router(st: Arc<ServeState>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/sessions", post(create_session).get(list_sessions))
        .route("/sessions/{sid}", get(get_session).delete(delete_session))
        .route(
            "/sessions/{sid}/runs",
            post(launch_run).get(list_session_runs),
        )
        .route("/runs/{rid}", get(get_run))
        .route("/runs/{rid}/log", get(run_log))
        .route("/runs/{rid}/kill", post(kill_run))
        .layer(axum::middleware::from_fn_with_state(st.clone(), auth_mw))
        .with_state(st);
    Router::new().nest("/v1", api)
}

async fn health(State(st): State<Arc<ServeState>>) -> Response {
    let running = st.children.lock().unwrap().len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "running": running,
        "max_runs": st.max_runs,
        "fusermount3": bin_found("fusermount3"),
        "slirp4netns": bin_found("slirp4netns"),
        "litestream": bin_found(&crate::litestream_bin()),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct CreateReq {
    sid: Option<String>,
    /// turn | daemon (default turn; daemon launches arrive in Phase 2)
    kind: Option<String>,
    profile: String,
    seed_dir: Option<String>,
    seed_dirty: Option<String>,
}

async fn create_session(State(st): State<Arc<ServeState>>, Json(req): Json<CreateReq>) -> Response {
    let sid = match &req.sid {
        Some(s) => match valid_sid(s) {
            Ok(()) => s.clone(),
            Err(e) => return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e),
        },
        None => format!("s-{}", random_suffix(5)),
    };
    let seed_json = match (&req.seed_dir, &req.seed_dirty) {
        (None, Some(_)) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_seed",
                "seed_dirty without seed_dir",
            )
        }
        (None, None) => None,
        (Some(dir), dirty) => {
            Some(json!({"dir": dir, "dirty": dirty.as_deref().unwrap_or("ask")}).to_string())
        }
    };
    let ns = NewSession {
        sid: sid.clone(),
        kind: req.kind.unwrap_or_else(|| "turn".into()),
        profile: req.profile.clone(),
        seed_json,
        owner: None,
    };
    match reg(&st.reg, move |r| r.create_session(&ns)).await {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{e:#}");
            let code = if msg.contains("UNIQUE") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return err_json(code, "create_failed", msg);
        }
    }
    match reg(&st.reg, move |r| r.get_session(&sid)).await {
        Ok(Some(row)) => (StatusCode::CREATED, Json(row)).into_response(),
        Ok(None) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_row",
            "session vanished",
        ),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

async fn list_sessions(State(st): State<Arc<ServeState>>) -> Response {
    match reg(&st.reg, |r| r.list_sessions()).await {
        Ok(rows) => Json(json!({"sessions": rows})).into_response(),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

async fn list_session_runs(
    State(st): State<Arc<ServeState>>,
    AxPath(sid): AxPath<String>,
) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    match reg(&st.reg, move |r| r.list_runs(&sid)).await {
        Ok(rows) => Json(json!({"runs": rows})).into_response(),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

async fn get_session(State(st): State<Arc<ServeState>>, AxPath(sid): AxPath<String>) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    match reg(&st.reg, move |r| r.get_session(&sid)).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "unknown_session", "no such session"),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

async fn delete_session(
    State(st): State<Arc<ServeState>>,
    AxPath(sid): AxPath<String>,
) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    if st.children.lock().unwrap().contains_key(&sid) {
        return err_json(
            StatusCode::CONFLICT,
            "session_busy",
            "a run is live — kill it first",
        );
    }
    let del = {
        let sid = sid.clone();
        reg(&st.reg, move |r| r.delete_session(&sid)).await
    };
    if let Err(e) = del {
        let msg = format!("{e:#}");
        return err_json(
            if msg.contains("no session") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            "delete_failed",
            msg,
        );
    }
    // rm the dir too (unmounts stale FUSE mounts first, like `den rm`)
    let rm = {
        let sid = sid.clone();
        tokio::task::spawn_blocking(move || cmd_rm(&sid)).await
    };
    match rm {
        Ok(Ok(())) => Json(json!({"removed": sid})).into_response(),
        Ok(Err(e)) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "rm_failed",
            format!("{e:#}"),
        ),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "rm_task", format!("{e}")),
    }
}

// ---- runs ------------------------------------------------------------------

#[derive(Deserialize)]
struct LaunchReq {
    prompt: String,
}

async fn launch_run(
    State(st): State<Arc<ServeState>>,
    AxPath(sid): AxPath<String>,
    Json(req): Json<LaunchReq>,
) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    if req.prompt.trim().is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_prompt", "prompt is empty");
    }
    let Some(sess) = (match reg(&st.reg, {
        let sid = sid.clone();
        move |r| r.get_session(&sid)
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registry",
                format!("{e:#}"),
            )
        }
    }) else {
        return err_json(StatusCode::NOT_FOUND, "unknown_session", "no such session");
    };
    if sess.kind != "turn" {
        return err_json(
            StatusCode::BAD_REQUEST,
            "wrong_kind",
            format!(
                "session kind '{}' takes /attach, not /runs (Phase 2)",
                sess.kind
            ),
        );
    }
    {
        let children = st.children.lock().unwrap();
        if children.len() >= st.max_runs {
            return err_json(
                StatusCode::TOO_MANY_REQUESTS,
                "max_runs",
                format!(
                    "{} concurrent runs already (DEN_MAX_RUNS={})",
                    children.len(),
                    st.max_runs
                ),
            );
        }
        if children.contains_key(&sid) {
            return err_json(
                StatusCode::CONFLICT,
                "session_busy",
                "a run is live on this session — GET /v1/runs/:id or kill it first",
            );
        }
    }

    // One live process per session, enforced by an flock held for the
    // child's lifetime (pattern: backup.rs watchers). API-created sessions
    // may not have a dir yet — the sessions root must exist for the lock.
    let lock = {
        let root = match sessions_root() {
            Ok(r) => r,
            Err(e) => {
                return err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "lock_path",
                    format!("{e:#}"),
                )
            }
        };
        if let Err(e) = std::fs::create_dir_all(&root) {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_path",
                format!("{e}"),
            );
        }
        let path = root.join(format!("{sid}.lock"));
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                return err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "lock_open",
                    format!("{e}"),
                )
            }
        }
    };
    // SAFETY: flock with a valid fd; LOCK_NB makes contention fail, not hang.
    let flock_rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if flock_rc != 0 {
        let e = std::io::Error::last_os_error();
        let code = if e.kind() == std::io::ErrorKind::WouldBlock {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return err_json(code, "session_busy", format!("session lock: {e}"));
    }

    // Pre-run snapshot for the post-run delta. A session that does not exist
    // yet starts from empty — the child creates + seeds it.
    let before = match take_snapshot(&sid).await {
        Ok(s) => s,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot",
                format!("{e:#}"),
            )
        }
    };

    let run_id = format!("r-{}", random_suffix(5));
    // Run logs live in the platform state dir, NOT the session dir: a
    // session dir can be recreated wholesale by a config change
    // (drop_stale_session) — run history must survive that.
    let runs_dir: std::path::PathBuf = match platform_db_path().and_then(|db| {
        db.parent()
            .map(|p| p.join("runs").join(&sid))
            .context("platform state dir")
    }) {
        Ok(d) => d,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runs_dir",
                format!("{e:#}"),
            )
        }
    };
    if let Err(e) = std::fs::create_dir_all(&runs_dir) {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runs_dir",
            format!("{e}"),
        );
    }
    let log_path = runs_dir.join(format!("{run_id}.log"));
    let log_file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_open",
                format!("{e}"),
            )
        }
    };
    let log_path_str = log_path.to_string_lossy().to_string();
    let log_clone = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "log_fd", format!("{e}")),
    };
    let nr = NewRun {
        id: run_id.clone(),
        sid: sid.clone(),
        profile: sess.profile.clone(),
        prompt: Some(req.prompt.clone()),
        argv_json: None,
    };
    if let Err(e) = reg(&st.reg, move |r| {
        r.insert_run(&nr, registry::R_QUEUED, Some(&log_path_str))
    })
    .await
    {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        );
    }

    // Child argv: `den <profile> [--seed …] <headless turn>`. The child is a
    // plain den run — it reuses the session (DEN_SESSION), stays quiet (the
    // delta is computed here), and logs everything to the run log.
    let mut argv = match headless_argv(&sess.profile, &sid, &req.prompt) {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "argv", format!("{e:#}")),
    };
    let tail = argv.split_off(1); // [--session, path, -p, prompt] (or [flags, prompt])

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "exe", format!("{e}")),
    };
    let mut cmd = Command::new(exe);
    cmd.arg(&sess.profile)
        .args(seed_into_args(sess.seed_json.as_deref(), &sid))
        .args(&tail)
        .env("DEN_SESSION", &sid)
        .env_remove("DEN_NEW")
        .env("DEN_QUIET", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_clone))
        .stderr(Stdio::from(log_file))
        .process_group(0);
    let spawned = cmd.spawn();
    let child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let _ = reg(&st.reg, {
                let run_id = run_id.clone();
                move |r| r.finish_run(&run_id, registry::R_FAILED, Some(-1), None)
            })
            .await;
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "spawn", format!("{e}"));
        }
    };
    let pid = child.id().unwrap_or(0);
    let rid = run_id.clone();
    if let Err(e) = reg(&st.reg, move |r| r.set_run_pid(&rid, pid as i32)).await {
        // child is live but untracked — still fine; the reap task finishes it
        eprintln!("den serve: registry pid update failed: {e:#}");
    }
    let childh = Arc::new(Child {
        run_id: run_id.clone(),
        pid,
        killed: AtomicBool::new(false),
        _lock: lock,
    });
    let _ = reg(&st.reg, {
        let sid = sid.clone();
        move |r| r.set_session_status(&sid, registry::S_RUNNING)
    })
    .await;
    st.children
        .lock()
        .unwrap()
        .insert(sid.clone(), childh.clone());
    tokio::spawn(reap(
        st.clone(),
        sid.clone(),
        run_id.clone(),
        child,
        childh,
        before,
    ));
    (
        StatusCode::ACCEPTED,
        Json(json!({"run_id": run_id, "status": "running"})),
    )
        .into_response()
}

/// Seed spec -> child args, applied only when the session DB does not exist
/// yet (seed spec from create; applied at first run per platform-api.md §8).
fn seed_into_args(seed_json: Option<&str>, sid: &str) -> Vec<String> {
    let db_ok = session_db_path(sid).map(|p| p.exists()).unwrap_or(false);
    let Some(s) = seed_json else { return vec![] };
    if db_ok {
        return vec![];
    }
    let Ok(v) = serde_json::from_str::<Value>(s) else {
        return vec![];
    };
    let Some(dir) = v.get("dir").and_then(|d| d.as_str()) else {
        return vec![];
    };
    let mut out = vec!["--seed".to_string(), dir.to_string()];
    if let Some(d) = v.get("dirty").and_then(|d| d.as_str()) {
        out.push("--seed-dirty".into());
        out.push(d.to_string());
    }
    out
}

/// Pre-run snapshot for diff_run_snap: layered sessions snapshot their
/// delta, legacy/absent sessions the (empty) whole FS.
async fn take_snapshot(sid: &str) -> Result<crate::RunSnap> {
    match open_session(sid).await? {
        Some(agent) => {
            if session_base_db(sid)?.is_some() {
                Ok(crate::RunSnap::Layered(delta_snapshot(&agent).await?))
            } else {
                Ok(crate::RunSnap::Legacy(snapshot_fs(&agent).await))
            }
        }
        None => Ok(crate::RunSnap::Legacy(HashMap::new())),
    }
}

/// The supervisor task: reap the child, diff the delta, close the registry
/// row, release the flock.
async fn reap(
    st: Arc<ServeState>,
    sid: String,
    run_id: String,
    mut child: tokio::process::Child,
    childh: Arc<Child>,
    before: crate::RunSnap,
) {
    let st_run = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("den serve: wait failed for {run_id}: {e}");
            let _ = reg(&st.reg, {
                let run_id = run_id.clone();
                move |r| r.finish_run(&run_id, registry::R_FAILED, None, None)
            })
            .await;
            let _ = reg(&st.reg, {
                let sid = sid.clone();
                move |r| r.set_session_status(&sid, registry::S_FAILED)
            })
            .await;
            st.children.lock().unwrap().remove(&sid);
            return;
        }
    };
    let killed = childh.killed.load(Ordering::SeqCst);
    let status = match (st_run.code(), st_run.signal()) {
        (Some(0), _) => registry::R_EXITED,
        (Some(_), _) if killed => registry::R_KILLED,
        (Some(_), _) => registry::R_FAILED,
        (None, _) if killed => registry::R_KILLED,
        (None, _) => registry::R_FAILED,
    };
    let exit_code = st_run.code().map(|c| c as i64);
    // delta: open the session the child just persisted and diff it
    let delta_json = match open_session(&sid).await {
        Ok(Some(agent)) => match diff_run_snap(&sid, &agent, &before).await {
            Ok(d) => serde_json::to_string(&d).ok(),
            Err(e) => {
                eprintln!("den serve: delta diff failed for {run_id}: {e:#}");
                None
            }
        },
        _ => None, // vanished or unreadable — no delta this time
    };
    let _ = reg(&st.reg, {
        let run_id = run_id.clone();
        let status = status.to_string();
        move |r| r.finish_run(&run_id, &status, exit_code, delta_json.as_deref())
    })
    .await;
    let sess_status = match status {
        registry::R_EXITED => registry::S_EXITED,
        registry::R_KILLED => registry::S_FAILED,
        _ => registry::S_FAILED,
    };
    let s2 = sid.clone();
    let _ = reg(&st.reg, move |r| r.set_session_status(&s2, sess_status)).await;
    st.children.lock().unwrap().remove(&sid);
    // the child is reaped and the flock released — tidy the lock file
    if let Ok(p) = session_lock_path(&sid) {
        let _ = std::fs::remove_file(p);
    }
}

async fn get_run(State(st): State<Arc<ServeState>>, AxPath(rid): AxPath<String>) -> Response {
    match reg(&st.reg, move |r| r.get_run(&rid)).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "unknown_run", "no such run"),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

/// Full run log, text/plain. Tails past 1 MiB so a runaway agent can't
/// balloon an API response.
async fn run_log(State(st): State<Arc<ServeState>>, AxPath(rid): AxPath<String>) -> Response {
    let Some(row) = (match reg(&st.reg, move |r| r.get_run(&rid)).await {
        Ok(r) => r,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registry",
                format!("{e:#}"),
            )
        }
    }) else {
        return err_json(StatusCode::NOT_FOUND, "unknown_run", "no such run");
    };
    let Some(path) = row.log_path else {
        return err_json(StatusCode::NOT_FOUND, "no_log", "run has no log file");
    };
    match std::fs::read(&path) {
        Ok(mut bytes) => {
            let mut note = String::new();
            if bytes.len() > 1_000_000 {
                bytes.drain(..bytes.len() - 1_000_000);
                while !bytes.is_empty() && bytes[0] != b'\n' {
                    bytes.remove(0);
                }
                note = format!("[den: log truncated to the last 1 MiB of {}]\n", path);
            }
            let mut body = note.into_bytes();
            body.extend_from_slice(&bytes);
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                body,
            )
                .into_response()
        }
        Err(e) => err_json(StatusCode::NOT_FOUND, "log_unreadable", format!("{e}")),
    }
}

async fn kill_run(State(st): State<Arc<ServeState>>, AxPath(rid): AxPath<String>) -> Response {
    // find the live child by run id
    let child = {
        let map = st.children.lock().unwrap();
        map.values().find(|c| c.run_id == rid).cloned()
    };
    let Some(child) = child else {
        let known = reg(&st.reg, move |r| r.get_run(&rid)).await;
        return match known {
            Ok(Some(row)) if row.status == registry::R_RUNNING => err_json(
                StatusCode::CONFLICT,
                "no_child",
                "run is registered but no live child — restarting serve?",
            ),
            Ok(Some(_)) => err_json(StatusCode::CONFLICT, "not_running", "run is not live"),
            _ => err_json(StatusCode::NOT_FOUND, "unknown_run", "no such run"),
        };
    };
    child.killed.store(true, Ordering::SeqCst);
    // SIGTERM the whole process group (the sandbox chain shares pgid);
    // escalation to SIGKILL after 10s.
    let pgid = child.pid as i32;
    // SAFETY: kill on a pgid we own.
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        if pid_alive(child.pid as i32) {
            // SAFETY: SIGKILL on a pgid we own; reap task notices the exit.
            unsafe { libc::kill(-(child.pid as i32), libc::SIGKILL) };
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"killed": true, "run_id": rid})),
    )
        .into_response()
}

// ---- entry -----------------------------------------------------------------

/// `den serve` — boot sweep, then serve until killed.
pub fn cmd_serve() -> Result<()> {
    let token = std::env::var("DEN_API_TOKEN").unwrap_or_default();
    if token.is_empty() {
        bail!("DEN_API_TOKEN is required — den serve executes agent CLIs on this host; refusing to listen unauthenticated");
    }
    let bind: std::net::SocketAddr = std::env::var("DEN_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8520".into())
        .parse()
        .context("DEN_BIND (use [host:]port, default 127.0.0.1:8520)")?;
    let max_runs: usize = std::env::var("DEN_MAX_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let reg = Registry::open(&platform_db_path()?)?;
    let moved = reg.sweep_orphans()?;
    if moved > 0 {
        eprintln!("den serve: marked {moved} run(s) orphaned from a previous serve");
    }
    let st = Arc::new(ServeState {
        reg: Arc::new(reg),
        token,
        max_runs,
        children: Mutex::new(HashMap::new()),
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("bind {bind}"))?;
        eprintln!("den serve: listening on {bind} (max_runs={max_runs})");
        axum::serve(listener, router(st)).await?;
        anyhow::Ok(())
    })
}
