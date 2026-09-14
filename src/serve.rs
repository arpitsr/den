//! den serve — the platform API (docs/platform-api.md).
//!
//! A supervisor, not a sandbox host: every session is a direct child
//! process (`den <profile> …`), spawned with its own process group and
//! reaped here. The sandbox's fork chain stays untouched; the registry
//! (platform.db) is bookkeeping — fs.db is the truth.
//!
//! Env: DEN_API_TOKEN (required — no token, no server), DEN_BIND
//! (default 127.0.0.1:8520), DEN_MAX_RUNS (default 8).

use crate::registry::{self, NewRun, NewSession, Registry, SessionRow};
use crate::{
    bin_found, cmd_rm, delta_snapshot, diff_run_snap, open_session, push, random_suffix,
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
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::process::Command;

/// Per-profile headless invocation (platform-api.md §10): how a profile
/// takes a prompt without a TTY, and how a follow-up turn resumes the same
/// conversation. Serve builds agent argv from here instead of inheriting a
/// TTY. Unknown profiles get the prompt bare — documented "unproven
/// headless" (a CLI that autodetects piped stdio still works).
///
/// dex pre-assigns its journal inside the session VFS
/// (`~/.local/share/dex/sessions/<cwd-slug>/den-<sid>.jsonl`) —
/// Session::open_or_continue creates or resumes it, so turn N+1 continues
/// turn N with no capture step. Other profiles keep a bare turn here;
/// capture-based resume (`<sid>/agent-session` + `claude --resume <id>`,
/// `codex exec resume <id>`) is Phase 2 (platform-build-plan.md).
fn headless_argv(profile_name: &str, sid: &str, prompt: &str) -> Result<Vec<String>> {
    let p = crate::profile(profile_name);
    let mut v = p.cmd.clone();
    let turn: &[&str] = match profile_name {
        "claude" | "gemini" | "dex" => &["-p"],
        "codex" => &["exec"],
        "opencode" => &["run"],
        _ => &[],
    };
    if profile_name == "dex" {
        v.push("--session".into());
        v.push(dex_journal_path(sid));
    }
    v.extend(turn.iter().map(|s| s.to_string()));
    v.push(prompt.to_string());
    Ok(v)
}

/// The dex journal for a den session, inside the session VFS (so it is
/// durable + replicable with fs.db and survives daemon-less turn runs).
fn dex_journal_path(sid: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!(
        "{home}/.local/share/dex/sessions/{}/den-{sid}.jsonl",
        crate::slug(&crate::cwd_string())
    )
}

/// platform.db sits next to the sessions root: ~/.den/platform.db
fn platform_db_path() -> Result<std::path::PathBuf> {
    Ok(sessions_root()?
        .parent()
        .context("den state dir")?
        .join("platform.db"))
}

/// The runtime binary the control plane spawns. `DEN_RUNTIME_BIN` exists so
/// the control plane and the runtime can become separate binaries without
/// touching call sites (default: this process's own executable).
fn runtime_bin() -> Result<std::path::PathBuf> {
    match std::env::var("DEN_RUNTIME_BIN") {
        Ok(p) if !p.is_empty() => Ok(PathBuf::from(p)),
        _ => std::env::current_exe().context("current exe"),
    }
}

/// Lock file for a session's live child, next to the session dir.
fn session_lock_path(sid: &str) -> Result<std::path::PathBuf> {
    Ok(sessions_root()?.join(format!("{sid}.lock")))
}

/// Delete a session's lock file after the child is gone (keep the tree tidy).
struct Child {
    run_id: String,
    owner: String,
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

/// Who the request is for: `root` = DEN_API_TOKEN (sees everything, mints
/// keys); anything else is a minted `dk_…` key scoped to its owner.
#[derive(Clone)]
struct AuthContext {
    owner: String,
    root: bool,
    /// Per-key concurrent-run cap from the minted key row (None = root or
    /// unlimited). Checked at run start in addition to the global DEN_MAX_RUNS.
    max_concurrent: Option<i64>,
}

fn key_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn auth_mw(
    State(st): State<Arc<ServeState>>,
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(token) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
    else {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        );
    };
    let ctx = if ct_eq(&token, &st.token) {
        AuthContext {
            owner: "root".into(),
            root: true,
            max_concurrent: None,
        }
    } else {
        let hash = key_hash(&token);
        match reg(&st.reg, move |r| r.find_key(&hash)).await {
            Ok(Some(k)) if k.revoked_at.is_none() => {
                // Caps never escalate: a key row can't raise the serve-wide
                // limit, only lower it for that key.
                AuthContext {
                    owner: k.owner,
                    root: false,
                    max_concurrent: k
                        .max_concurrent
                        .map(|c| c.min(st.max_runs as i64))
                        .filter(|c| *c >= 0),
                }
            }
            _ => {
                return err_json(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "unknown or revoked key",
                )
            }
        }
    };
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

// ---- routes ----------------------------------------------------------------

fn router(st: Arc<ServeState>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/sessions", post(create_session).get(list_sessions))
        .route("/sessions/{sid}", get(get_session).delete(delete_session))
        .route("/sessions/{sid}/attach", post(attach_session))
        .route("/sessions/{sid}/stop", post(stop_session))
        .route("/sessions/{sid}/files", get(session_files))
        .route("/sessions/{sid}/push", post(push_session_route))
        .route("/keys", post(create_key).get(list_keys))
        .route("/keys/{key_id}/revoke", post(revoke_key))
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
    /// turn | daemon
    kind: Option<String>,
    profile: String,
    seed_dir: Option<String>,
    /// git URL — cloned to a temp dir at first run and seeded from it
    /// (den-side, so host git credentials never enter the session)
    seed_git: Option<String>,
    seed_dirty: Option<String>,
}

async fn create_session(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    Json(req): Json<CreateReq>,
) -> Response {
    let sid = match &req.sid {
        Some(s) => match valid_sid(s) {
            Ok(()) => s.clone(),
            Err(e) => return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e),
        },
        None => format!("s-{}", random_suffix(5)),
    };
    let seed_json = match (&req.seed_dir, &req.seed_git, &req.seed_dirty) {
        (Some(_), Some(_), _) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_seed",
                "seed_dir and seed_git are exclusive",
            )
        }
        (None, None, Some(_)) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_seed",
                "seed_dirty without a seed source",
            )
        }
        (None, None, None) => None,
        (Some(dir), None, dirty) => {
            Some(json!({"dir": dir, "dirty": dirty.as_deref().unwrap_or("ask")}).to_string())
        }
        (None, Some(url), dirty) => {
            Some(json!({"git": url, "dirty": dirty.as_deref().unwrap_or("ask")}).to_string())
        }
    };
    let ns = NewSession {
        sid: sid.clone(),
        kind: req.kind.unwrap_or_else(|| "turn".into()),
        profile: req.profile.clone(),
        seed_json,
        owner: Some(ctx.owner.clone()),
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
    ctx: axum::Extension<AuthContext>,
    AxPath(sid): AxPath<String>,
) -> Response {
    if let Err(resp) = authorize(&st, &ctx, &sid).await {
        return resp;
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

/// Owner check for every session-scoped route: root sees all, a minted
/// key only its own sessions. Returns the row or an error response.
// Response<Body> is bulky; boxing the error would touch every call site.
#[allow(clippy::result_large_err)]
async fn authorize(
    st: &Arc<ServeState>,
    ctx: &AuthContext,
    sid: &str,
) -> Result<SessionRow, Response> {
    let got = reg(&st.reg, {
        let sid = sid.to_string();
        move |r| r.get_session(&sid)
    })
    .await;
    match got {
        Ok(Some(s)) if ctx.root || s.owner.as_deref() == Some(ctx.owner.as_str()) => Ok(s),
        Ok(Some(_)) => Err(err_json(
            StatusCode::NOT_FOUND,
            "unknown_session",
            "no such session",
        )),
        Ok(None) => Err(err_json(
            StatusCode::NOT_FOUND,
            "unknown_session",
            "no such session",
        )),
        Err(e) => Err(err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        )),
    }
}

// ---- keys (root only; platform-api.md §17) ---------------------------------

#[derive(Deserialize)]
struct CreateKeyReq {
    owner: Option<String>,
    name: Option<String>,
    max_concurrent: Option<i64>,
}

async fn create_key(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    Json(req): Json<CreateKeyReq>,
) -> Response {
    if !ctx.root {
        return err_json(
            StatusCode::FORBIDDEN,
            "root_only",
            "keys are minted by the root token",
        );
    }
    let owner = req.owner.unwrap_or_else(|| "default".into());
    // Key material from the OS CSPRNG (urandom), base64url — not the
    // alphanumeric session-suffix helper, whose 36-char alphabet would cap
    // a 32-char key at ~166 bits of effective entropy and bias 12 bits/char.
    let raw = {
        let mut buf = [0u8; 32];
        if let Err(e) = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf))
        {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "entropy",
                format!("read /dev/urandom: {e}"),
            );
        }
        let hex: String = buf
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .concat();
        format!("dk_{hex}")
        // Collision with an existing key is astronomically unlikely and the
        // unique(key_hash) insert would fail loudly if it ever happened.
    };
    let nk = crate::registry::NewKey {
        key_hash: key_hash(&raw),
        key_id: format!("k-{}", random_suffix(8)),
        owner: owner.clone(),
        name: req.name.clone(),
        max_concurrent: req.max_concurrent,
    };
    let key_id = nk.key_id.clone();
    if let Err(e) = reg(&st.reg, move |r| r.create_key(&nk)).await {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({"key_id": key_id, "key": raw, "owner": owner})),
    )
        .into_response()
}

async fn list_keys(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
) -> Response {
    if !ctx.root {
        return err_json(
            StatusCode::FORBIDDEN,
            "root_only",
            "keys are root-visible only",
        );
    }
    match reg(&st.reg, |r| r.list_keys()).await {
        Ok(rows) => Json(json!({"keys": rows})).into_response(),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry",
            format!("{e:#}"),
        ),
    }
}

async fn revoke_key(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(key_id): AxPath<String>,
) -> Response {
    if !ctx.root {
        return err_json(
            StatusCode::FORBIDDEN,
            "root_only",
            "keys are root-managed only",
        );
    }
    let key_id2 = key_id.clone();
    match reg(&st.reg, move |r| r.revoke_key(&key_id2)).await {
        Ok(()) => Json(json!({"revoked": key_id})).into_response(),
        Err(e) => {
            let msg = format!("{e:#}");
            let code = if msg.contains("no live key") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            err_json(code, "revoke_failed", msg)
        }
    }
}

// ---- files (read-only SDK access; platform-api.md §8) ----------------------

/// GET /sessions/:sid/files?path=/x — file (base64) or directory listing.
#[derive(Deserialize)]
struct FilesQuery {
    path: String,
    /// Max file bytes returned inline; larger files list size only.
    #[serde(default = "default_file_cap")]
    max_bytes: usize,
}
fn default_file_cap() -> usize {
    1_000_000
}

async fn session_files(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(sid): AxPath<String>,
    axum::extract::Query(q): axum::extract::Query<FilesQuery>,
) -> Response {
    let sess = match authorize(&st, &ctx, &sid).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let _ = sess;
    // path hygiene: absolute, no .., collapsed
    let path = q.path.trim().to_string();
    if path.is_empty() || !path.starts_with('/') || path.split('/').any(|c| c == "..") {
        return err_json(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "path must be absolute without '..'",
        );
    }
    let owned_sid = sid.clone();
    let max_bytes = q.max_bytes;
    let res = tokio::task::spawn_blocking(move || {
        crate::block_on(async move {
            let agent = match open_session(&owned_sid).await? {
                Some(a) => a,
                None => anyhow::bail!("no session DB"),
            };
            let st = agent.fs.lstat(&path).await?;
            let Some(st) = st else {
                anyhow::bail!("path-not-found")
            };
            let mode = st.mode;
            let size = st.size;
            if st.is_file() {
                if size as usize > max_bytes {
                    anyhow::Ok(json!({
                        "path": path, "kind": "file", "size": size,
                        "mode": format!("{mode:o}"), "truncated": true,
                    }))
                } else {
                    let bytes = agent.fs.read_file(&path).await?.unwrap_or_default();
                    let mut b64 = String::new();
                    {
                        use std::io::Write as _;
                        Base64Writer::new(&mut b64).write_all(&bytes)?;
                    }
                    anyhow::Ok(json!({
                        "path": path, "kind": "file", "size": size,
                        "mode": format!("{mode:o}"), "encoding": "base64", "content": b64,
                    }))
                }
            } else {
                let entries = agent.fs.readdir_plus(st.ino).await?.unwrap_or_default();
                let list: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "name": e.name,
                            "kind": if e.stats.is_file() { "file" } else { "dir" },
                            "size": e.stats.size,
                            "mode": format!("{}", e.stats.mode & 0o7777),
                        })
                    })
                    .collect();
                anyhow::Ok(json!({
                    "path": path, "kind": "dir", "entries": list,
                }))
            }
        })
    })
    .await;
    let payload = match res {
        Ok(Ok(Ok(v))) => v,
        Ok(Ok(Err(e))) => {
            let msg = format!("{e:#}");
            let code = if msg.contains("path-not-found") || msg.contains("no session DB") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return err_json(code, "files", msg);
        }
        Ok(Err(e)) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "files_task",
                format!("{e:#}"),
            )
        }
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "files_task",
                format!("{e}"),
            )
        }
    };
    Json(payload).into_response()
}

/// Minimal std/base64 encoder (no extra dep: base64 without padding is 3
/// lines; keep it dependency-free like the rest of den).
struct Base64Writer<'a> {
    out: &'a mut String,
    buf: [u8; 3],
    len: usize,
}
impl<'a> Base64Writer<'a> {
    fn new(out: &'a mut String) -> Self {
        Base64Writer {
            out,
            buf: [0; 3],
            len: 0,
        }
    }
}
impl<'a> std::io::Write for Base64Writer<'a> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for &b in data {
            self.buf[self.len] = b;
            self.len += 1;
            if self.len == 3 {
                let n = ((self.buf[0] as u32) << 16)
                    | ((self.buf[1] as u32) << 8)
                    | (self.buf[2] as u32);
                let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
                for i in idx {
                    self.out.push(TABLE[i as usize] as char);
                }
                self.len = 0;
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> Drop for Base64Writer<'a> {
    fn drop(&mut self) {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if self.len == 1 {
            let n = (self.buf[0] as u32) << 16;
            let idx = [(n >> 18) & 63, (n >> 12) & 63];
            for i in idx {
                self.out.push(TABLE[i as usize] as char);
            }
            self.out.push_str("==");
        } else if self.len == 2 {
            let n = ((self.buf[0] as u32) << 16) | ((self.buf[1] as u32) << 8);
            let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63];
            for i in idx {
                self.out.push(TABLE[i as usize] as char);
            }
            self.out.push('=');
        }
    }
}

// ---- push (lands the delta as a git branch; runs on the host) --------------

#[derive(Deserialize)]
struct PushReq {
    branch: Option<String>,
    message: Option<String>,
    dry_run: bool,
    keep: bool,
}

async fn push_session_route(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(sid): AxPath<String>,
    Json(req): Json<PushReq>,
) -> Response {
    if let Err(resp) = authorize(&st, &ctx, &sid).await {
        return resp;
    }
    let opts = push::PushOpts {
        branch: req.branch,
        to: None,
        remote: None,
        message: req.message,
        dry_run: req.dry_run,
        keep: req.keep,
        pr: false,
    };
    let res = tokio::task::spawn_blocking(move || {
        crate::block_on(async move {
            let sdir = sessions_root()?.join(&sid);
            push::push_session(&sid, &sdir, &opts).await
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(out))) => Json(json!({
            "changed": out.changed,
            "deleted": out.deleted,
            "ignored": out.ignored,
            "dropped": out.dropped,
            "status": out.status,
            "pushed": out.pushed,
            "branch": out.branch,
            "repo": out.repo.to_string_lossy(),
            "worktree": out.worktree.as_ref().map(|w| w.to_string_lossy()),
            "push_note": out.push_note,
        }))
        .into_response(),
        Ok(Ok(Err(e))) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "push_failed",
            format!("{e:#}"),
        ),
        Ok(Err(e)) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "push_failed",
            format!("{e:#}"),
        ),
        Err(e) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "push_task",
            format!("{e}"),
        ),
    }
}

// ---- daemon sessions (attachable; platform-api.md §3) ----------------------

/// `<platform>/attach/<sid>.json` — port + session-scoped token written by
/// /attach so `den attach <sid>` and API reconnects can find the daemon.
/// Lives in the platform dir, NOT the session dir: a session dir is
/// recreated wholesale by drop_stale_session (den core) — attach info must
/// survive that, like the run logs.
pub(crate) fn attach_info_path(sid: &str) -> Result<std::path::PathBuf> {
    let db = platform_db_path()?;
    let dir = db
        .parent()
        .context("platform state dir")?
        .join("attach")
        .join(sid);
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("attach.json"))
}

async fn attach_session(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(sid): AxPath<String>,
) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
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
    if sess.kind != "daemon" {
        return err_json(
            StatusCode::BAD_REQUEST,
            "wrong_kind",
            format!(
                "session kind '{}' has no daemon — create a kind=daemon session",
                sess.kind
            ),
        );
    }
    if sess.profile != "dex" {
        return err_json(
            StatusCode::BAD_REQUEST,
            "unsupported_daemon",
            format!(
                "profile '{}' has no daemon mode yet (bridge: platform-api.md §3)",
                sess.profile
            ),
        );
    }
    // Live child -> idempotent reconnect: hand back the same port + token.
    if st.children.lock().unwrap().contains_key(&sid) {
        let info = attach_info_path(&sid)
            .and_then(|p| std::fs::read_to_string(p).map_err(anyhow::Error::from));
        return match info
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(anyhow::Error::from))
        {
            Ok(v) => Json(json!({
                "attach_url": format!("http://127.0.0.1:{}", v["port"]),
                "attach_token": v["token"],
            }))
            .into_response(),
            Err(e) => err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "attach_info",
                format!("live daemon but no attach info: {e}"),
            ),
        };
    }

    // One live process per session — same flock rule as turn runs.
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
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join(format!("{sid}.lock")))
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
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        let code = if e.kind() == std::io::ErrorKind::WouldBlock {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return err_json(code, "session_busy", format!("session lock: {e}"));
    }

    // The host listener: bound here (no window for a port squatter), then
    // handed into the sandboxed dex daemon via fd inheritance — CLOEXEC is
    // cleared so it survives den's exec chain, and dex re-arms CLOEXEC on
    // adoption so agent-spawned tools never see it (platform-api.md §3).
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "bind", format!("{e}")),
    };
    let fd = listener.as_raw_fd();
    // SAFETY: clear CLOEXEC on the fd we own so it crosses exec into dex.
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    let port = match listener.local_addr() {
        Ok(a) => a.port() as i64,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "bind", format!("{e}")),
    };
    let token = format!("dxt-{}", random_suffix(32));

    // Persist attach info for `den attach` and API reconnects (platform
    // dir — survives the child's drop_stale_session recreating <sid>/).
    {
        let info_path = match attach_info_path(&sid) {
            Ok(p) => p,
            Err(e) => {
                return err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attach_info",
                    format!("{e:#}"),
                )
            }
        };
        if let Err(e) = std::fs::write(info_path, json!({"port": port, "token": token}).to_string())
        {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "attach_info",
                format!("{e}"),
            );
        }
    }

    // Child: `den dex serve --fd <n>` — a plain den run that joins the
    // session and execs the dex daemon inside the sandbox; the fd rides
    // along through the fork chain (nothing in it closes foreign fds).
    let exe = match runtime_bin() {
        Ok(e) => e,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "exe", format!("{e}")),
    };
    let daemon_log_dir = match platform_db_path() {
        Ok(db) => match db.parent() {
            Some(p) => p.join("runs").join(&sid),
            None => {
                return err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "runs_dir",
                    "platform state dir missing",
                )
            }
        },
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runs_dir",
                format!("{e:#}"),
            )
        }
    };
    if let Err(e) = std::fs::create_dir_all(&daemon_log_dir) {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runs_dir",
            format!("{e}"),
        );
    }
    let log_path = daemon_log_dir.join("daemon.log");
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
    let log_clone = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "log_fd", format!("{e}")),
    };
    let mut cmd = Command::new(exe);
    cmd.args(["exec", "--session", &sid])
        .arg("--")
        .arg(&sess.profile)
        .args(["serve", "--fd", &fd.to_string()])
        .env("DEN_SESSION", &sid)
        .env("DEX_DAEMON_TOKEN", &token)
        .env("DEN_QUIET", "1")
        .env_remove("DEN_NEW")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_clone))
        .stderr(Stdio::from(log_file))
        .process_group(0);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "spawn", format!("{e}"));
        }
    };
    let pid = child.id().unwrap_or(0);
    let childh = Arc::new(Child {
        run_id: "daemon".into(),
        owner: ctx.owner.clone(),
        pid,
        killed: AtomicBool::new(false),
        _lock: lock,
    });
    let _ = reg(&st.reg, {
        let sid = sid.clone();
        move |r| r.set_attach_port(&sid, port)
    })
    .await;
    let _ = reg(&st.reg, {
        let sid = sid.clone();
        move |r| r.set_session_status(&sid, registry::S_ATTACHED)
    })
    .await;
    st.children
        .lock()
        .unwrap()
        .insert(sid.clone(), childh.clone());
    tokio::spawn(reap_daemon(st.clone(), sid.clone(), child, childh));
    Json(json!({
        "attach_url": format!("http://127.0.0.1:{port}"),
        "attach_token": token,
    }))
    .into_response()
}

/// Daemon-kind reap: no per-run delta (dex owns its turns); a clean exit or
/// a stop returns the session to `idle`, a crash to `failed`.
async fn reap_daemon(
    st: Arc<ServeState>,
    sid: String,
    mut child: tokio::process::Child,
    childh: Arc<Child>,
) {
    let st_run = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("den serve: daemon wait failed for {sid}: {e}");
            let _ = reg(&st.reg, {
                let sid = sid.clone();
                move |r| r.set_session_status(&sid, registry::S_FAILED)
            })
            .await;
            st.children.lock().unwrap().remove(&sid);
            return;
        }
    };
    let status = match (
        st_run.code(),
        st_run.signal(),
        childh.killed.load(Ordering::SeqCst),
    ) {
        (Some(0), _, _) => registry::S_IDLE,
        (_, Some(_), true) => registry::S_IDLE, // stopped by us
        _ => registry::S_FAILED,
    };
    let _ = reg(&st.reg, {
        let sid = sid.clone();
        move |r| r.set_session_status(&sid, status)
    })
    .await;
    st.children.lock().unwrap().remove(&sid);
    if let Ok(p) = attach_info_path(&sid) {
        let _ = std::fs::remove_file(p); // port is gone; a reattach relaunches
    }
    if let Ok(p) = session_lock_path(&sid) {
        let _ = std::fs::remove_file(p);
    }
}

/// Stop a live daemon session: SIGTERM the process group, SIGKILL after 10s.
async fn stop_session(State(st): State<Arc<ServeState>>, AxPath(sid): AxPath<String>) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    let child = st.children.lock().unwrap().get(&sid).cloned();
    let Some(child) = child else {
        return err_json(
            StatusCode::CONFLICT,
            "not_running",
            "no live daemon on this session",
        );
    };
    child.killed.store(true, Ordering::SeqCst);
    let pgid = child.pid as i32;
    // SAFETY: SIGTERM to a process group we own.
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        if pid_alive(child.pid as i32) {
            // SAFETY: SIGKILL to the same process group.
            unsafe { libc::kill(-(child.pid as i32), libc::SIGKILL) };
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"stopped": true, "sid": sid})),
    )
        .into_response()
}

// ---- runs ------------------------------------------------------------------

#[derive(Deserialize)]
struct LaunchReq {
    prompt: String,
}

async fn launch_run(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(sid): AxPath<String>,
    Json(req): Json<LaunchReq>,
) -> Response {
    if let Err(e) = valid_sid(&sid) {
        return err_json(StatusCode::BAD_REQUEST, "invalid_sid", e);
    }
    if req.prompt.trim().is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "invalid_prompt", "prompt is empty");
    }
    let sess = match authorize(&st, &ctx, &sid).await {
        Ok(s) => s,
        Err(resp) => return resp,
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
        // global ceiling first, then the calling key's own cap (root: none)
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
        if let Some(cap) = ctx.0.max_concurrent {
            let mine = children.values().filter(|c| c.owner == ctx.owner).count();
            if mine >= cap as usize {
                return err_json(
                    StatusCode::TOO_MANY_REQUESTS,
                    "key_quota",
                    format!(
                        "{} concurrent runs for '{}' (key cap {cap})",
                        mine, ctx.owner
                    ),
                );
            }
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

    let exe = match runtime_bin() {
        Ok(e) => e,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "exe", format!("{e}")),
    };
    let mut cmd = Command::new(exe);
    cmd.args(["exec", "--session", &sid])
        .args(seed_into_args(sess.seed_json.as_deref(), &sid))
        .arg("--")
        .arg(&sess.profile)
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
        owner: ctx.owner.clone(),
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
    if let Some(git) = v.get("git").and_then(|g| g.as_str()) {
        let mut out = vec!["--seed-git".to_string(), git.to_string()];
        if let Some(d) = v.get("dirty").and_then(|d| d.as_str()) {
            out.push("--seed-dirty".into());
            out.push(d.to_string());
        }
        return out;
    }
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

async fn get_run(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(rid): AxPath<String>,
) -> Response {
    let row = match reg(&st.reg, move |r| r.get_run(&rid)).await {
        Ok(Some(row)) => row,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "unknown_run", "no such run"),
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registry",
                format!("{e:#}"),
            )
        }
    };
    if let Err(resp) = authorize(&st, &ctx, &row.sid).await {
        return resp;
    }
    Json(row).into_response()
}

/// Full run log, text/plain. Tails past 1 MiB so a runaway agent can't
/// balloon an API response.
async fn run_log(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(rid): AxPath<String>,
) -> Response {
    let row = match reg(&st.reg, move |r| r.get_run(&rid)).await {
        Ok(Some(row)) => row,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "unknown_run", "no such run"),
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registry",
                format!("{e:#}"),
            )
        }
    };
    if let Err(resp) = authorize(&st, &ctx, &row.sid).await {
        return resp;
    }
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

async fn kill_run(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(rid): AxPath<String>,
) -> Response {
    if !ctx.root {
        // cheap pre-check: the run must belong to this key's session
        if let Ok(Some(row)) = reg(&st.reg, {
            let rid = rid.clone();
            move |r| r.get_run(&rid)
        })
        .await
        {
            if let Err(resp) = authorize(&st, &ctx, &row.sid).await {
                return resp;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// env vars are process-global (dex_journal_path reads HOME)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn seed_into_args_routes_git_vs_dir() {
        // git spec -> --seed-git
        let a = seed_into_args(Some(r#"{"git":"https://github.com/x/y"}"#), "nosuch");
        assert_eq!(a, vec!["--seed-git", "https://github.com/x/y"]);

        // git + dirty
        let b = seed_into_args(
            Some(r#"{"git":"https://github.com/x/y","dirty":"head"}"#),
            "nosuch",
        );
        assert_eq!(
            b,
            vec![
                "--seed-git",
                "https://github.com/x/y",
                "--seed-dirty",
                "head"
            ]
        );

        // dir spec unchanged
        let c = seed_into_args(Some(r#"{"dir":"/tmp/proj"}"#), "nosuch");
        assert_eq!(c, vec!["--seed", "/tmp/proj"]);

        // none / garbage / missing key -> no args
        assert!(seed_into_args(None, "nosuch").is_empty());
        assert!(seed_into_args(Some("not json"), "nosuch").is_empty());
        assert!(seed_into_args(Some("{}"), "nosuch").is_empty());
    }

    #[test]
    fn headless_argv_known_profiles() {
        // flags + prompt assembly; path details stay out (cwd-dependent)
        let codex = headless_argv("codex", "s1", "touch /hello.txt").unwrap();
        assert_eq!(codex[0], "codex");
        assert_eq!(codex[1], "exec");
        assert_eq!(codex[codex.len() - 1], "touch /hello.txt");

        for (name, flag) in [("claude", "-p"), ("gemini", "-p"), ("opencode", "run")] {
            let v = headless_argv(name, "s1", "hi").unwrap();
            assert_eq!(v[0], name);
            assert!(v.contains(&flag.to_string()), "{name}: {v:?}");
            assert_eq!(v[v.len() - 1], "hi");
        }
    }

    #[test]
    fn headless_argv_dex_preassigns_journal() {
        let _g = ENV_LOCK.lock().unwrap();
        let v = headless_argv("dex", "sess-42", "explain this repo").unwrap();
        assert_eq!(v[0], "dex");
        // journal path sits between --session and the -p flag; it must land
        // inside the session VFS and carry the den session id
        assert_eq!(v[1], "--session");
        let jp = &v[2];
        assert!(jp.contains("/.local/share/dex/sessions/"), "{jp}");
        assert!(jp.ends_with("den-sess-42.jsonl"), "{jp}");
        assert_eq!(v[3], "-p");
        assert_eq!(v[v.len() - 1], "explain this repo");
    }

    #[test]
    fn headless_argv_unknown_profile_runs_prompt_bare() {
        let v = headless_argv("some-future-agent", "s1", "do the thing").unwrap();
        assert_eq!(v, vec!["some-future-agent", "do the thing"]);
    }
}
