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
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
pub(crate) fn platform_db_path() -> Result<std::path::PathBuf> {
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
    runner: std::sync::Arc<dyn crate::runner::Runner>,
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

fn bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        // An empty credential ("Bearer " with nothing after) is not a
        // token: treat it as absent so it can't ride the root-token
        // compare below.
        .filter(|s| !s.is_empty())
}

/// Token -> context, shared by both transports. Root token = DEN_API_TOKEN;
/// anything else must be a live minted `dk_...` key.
// Response<Body> is bulky; boxing the error would touch every call site.
#[allow(clippy::result_large_err)]
async fn authorize_token(st: &Arc<ServeState>, token: &str) -> Result<AuthContext, Response> {
    // Root match requires a non-empty token on both sides: a socket-only
    // daemon has no root token, and an empty bearer must never match it —
    // any peer who can reach the socket could otherwise mint root.
    if !token.is_empty() && !st.token.is_empty() && ct_eq(token, &st.token) {
        return Ok(AuthContext {
            owner: "root".into(),
            root: true,
            max_concurrent: None,
        });
    }
    let hash = key_hash(token);
    match reg(&st.reg, move |r| r.find_key(&hash)).await {
        Ok(Some(k)) if k.revoked_at.is_none() => {
            // Caps never escalate: a key row can't raise the serve-wide
            // limit, only lower it for that key.
            Ok(AuthContext {
                owner: k.owner,
                root: false,
                // create_key validates >= 0; a corrupt legacy row fails
                // closed (cap < mine ⇒ every run refused), not open.
                max_concurrent: k.max_concurrent.map(|c| c.min(st.max_runs as i64)),
            })
        }
        _ => Err(err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "unknown or revoked key",
        )),
    }
}

async fn auth_mw(
    State(st): State<Arc<ServeState>>,
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(token) = bearer_token(&req) else {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        );
    };
    let ctx = match authorize_token(&st, &token).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

/// Local-socket middleware: SO_PEERCRED creds were injected per-connection
/// by serve_unix() (docs/socket-daemon.md). Same-uid peers are root; a
/// presented bearer key is honored first and may narrow the context.
async fn auth_mw_socket(
    State(st): State<Arc<ServeState>>,
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    // A bearer key, explicitly presented, narrows the peercred context. An
    // unknown or empty token is NOT a hard 401: on the socket the ground
    // truth is the peer uid (TCP keeps bearer-strict), so a failed bearer
    // falls through to the peercred check. That also keeps a CLI carrying
    // DEN_API_TOKEN for remote use working against a socket-only daemon,
    // whose registry has no such root token.
    if let Some(token) = bearer_token(&req) {
        if let Ok(ctx) = authorize_token(&st, &token).await {
            req.extensions_mut().insert(ctx);
            return next.run(req).await;
        }
    }
    let creds = req.extensions().get::<tokio::net::unix::UCred>().copied();
    match creds {
        Some(c) if c.uid() == unsafe { libc::geteuid() } => {
            req.extensions_mut().insert(AuthContext {
                owner: "root".into(),
                root: true,
                max_concurrent: None,
            });
            next.run(req).await
        }
        Some(_) => err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "socket peer is another user",
        ),
        None => err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "no peer credentials",
        ),
    }
}

// ---- routes ----------------------------------------------------------------

fn api_routes() -> Router<Arc<ServeState>> {
    Router::new()
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
        .route("/runs/{rid}/stream", get(run_stream))
        .route("/runs/{rid}/kill", post(kill_run))
}

/// TCP transport: bearer auth required (docs/socket-daemon.md §2).
fn router(st: Arc<ServeState>) -> Router {
    let api = api_routes()
        .layer(axum::middleware::from_fn_with_state(st.clone(), auth_mw))
        .with_state(st);
    Router::new().nest("/v1", api)
}

/// Local transport: SO_PEERCRED is the default context (same uid = root);
/// a bearer token, if presented, is honored and may narrow it.
fn socket_router(st: Arc<ServeState>) -> Router {
    let api = api_routes()
        .layer(axum::middleware::from_fn_with_state(
            st.clone(),
            auth_mw_socket,
        ))
        .with_state(st);
    Router::new().nest("/v1", api)
}

async fn health(State(st): State<Arc<ServeState>>) -> Response {
    let running = st.children.lock().unwrap().len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
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
    if let Some(n) = req.max_concurrent {
        if n < 0 {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_cap",
                format!("max_concurrent {n} is negative"),
            );
        }
    }
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
    let child = match st.runner.launch(crate::runner::Launch {
        exe: exe.to_string_lossy().into_owned(),
        args: vec![
            "exec".into(),
            "--session".into(),
            sid.clone(),
            "--".into(),
            sess.profile.clone(),
            "serve".into(),
            "--fd".into(),
            fd.to_string(),
        ],
        sid: sid.clone(),
        env: vec![
            ("DEX_DAEMON_TOKEN".into(), token.clone()),
            ("DEN_QUIET".into(), "1".into()),
        ],
        env_remove: vec!["DEN_NEW".into()],
        stdout: Stdio::from(log_clone),
        stderr: Stdio::from(log_file),
    }) {
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
    let child = match st.runner.launch(crate::runner::Launch {
        exe: exe.to_string_lossy().into_owned(),
        args: {
            let mut a = vec!["exec".into(), "--session".into(), sid.clone()];
            a.extend(seed_into_args(sess.seed_json.as_deref(), &sid));
            a.push("--".into());
            a.push(sess.profile.clone());
            a.extend(tail);
            a
        },
        sid: sid.clone(),
        env: vec![("DEN_QUIET".into(), "1".into())],
        env_remove: vec!["DEN_NEW".into()],
        stdout: Stdio::from(log_clone),
        stderr: Stdio::from(log_file),
    }) {
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

// ---- run log streaming -----------------------------------------------------

/// One stream frame: `event <len>\n<len bytes>\n` — length-prefixed so agent
/// output with embedded newlines (or non-UTF8 bytes) survives the hop.
fn frame(event: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = format!("{event} {}\n", payload.len()).into_bytes();
    v.extend_from_slice(payload);
    v.push(b'\n');
    v
}

/// Stream adapter: the producer task pushes encoded frames into an mpsc
/// channel; this impl feeds them to axum's chunked response body.
/// UnboundedReceiver::poll_recv is public — no tokio-stream dep needed.
struct Frames(tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>);

impl futures_core::Stream for Frames {
    type Item = Result<axum::body::Bytes, std::convert::Infallible>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0
            .poll_recv(cx)
            .map(|opt| opt.map(|b| Ok(axum::body::Bytes::from(b))))
    }
}

/// GET /v1/runs/{rid}/stream — live run log, pushed as length-prefixed
/// frames: `log` events as the log grows, a `ping` keepalive during quiet
/// stretches, and a terminal `done` event carrying
/// {"status","exit_code","delta_json"}. Server-side tailing replaces the
/// CLI's whole-file re-polling: O(log bytes) on the wire, ~150 ms delivery.
async fn run_stream(
    State(st): State<Arc<ServeState>>,
    ctx: axum::Extension<AuthContext>,
    AxPath(rid): AxPath<String>,
) -> Response {
    let spawn_rid = rid.clone();
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
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(stream_producer(path.into(), st, spawn_rid, tx));
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        axum::body::Body::from_stream(Frames(rx)),
    )
        .into_response()
}

/// Tail the run log and push frames until the run reaches a terminal
/// status, then send `done` and exit. Exits early when the client hangs up
/// (send fails — receiver dropped).
async fn stream_producer(
    log_path: PathBuf,
    st: Arc<ServeState>,
    rid: String,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut offset: u64 = 0;
    let mut idle_since = tokio::time::Instant::now();
    loop {
        // tail new bytes since the last pass (the log only ever grows)
        if let Ok(mut f) = std::fs::File::open(&log_path) {
            if let Ok(md) = f.metadata() {
                if md.len() > offset && f.seek(SeekFrom::Start(offset)).is_ok() {
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                        offset += buf.len() as u64;
                        idle_since = tokio::time::Instant::now();
                        if tx.send(frame("log", &buf)).is_err() {
                            return; // client hung up
                        }
                    }
                }
            }
        }
        match reg(&st.reg, {
            let rid = rid.clone();
            move |r| r.get_run(&rid)
        })
        .await
        {
            Ok(Some(row)) if row.status != "running" && row.status != "queued" => {
                let done = json!({
                    "status": row.status,
                    "exit_code": row.exit_code,
                    "delta_json": row.delta_json,
                });
                let _ = tx.send(frame("done", done.to_string().as_bytes()));
                return;
            }
            Ok(None) => {
                // run row vanished (session deleted under us) — say so
                let _ = tx.send(frame("done", br#"{"status":"gone"}"#.as_slice()));
                return;
            }
            _ => {} // queued/running, or a registry hiccup: keep streaming
        }
        // keepalive so a quiet run (long tool call, no output) doesn't trip
        // the client's read timeout
        if idle_since.elapsed() > std::time::Duration::from_secs(5) {
            idle_since = tokio::time::Instant::now();
            if tx.send(frame("ping", b"")).is_err() {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

// ---- entry -----------------------------------------------------------------

/// `den serve` — boot sweep, then serve until killed (`den serve stop`,
/// Ctrl+C, or an external SIGTERM).
///
/// Transports (docs/socket-daemon.md): `--socket PATH` (or DEN_SOCKET) adds
/// the local unix socket with peercred auth; DEN_API_TOKEN enables the TCP
/// listener on DEN_BIND. Socket-only mode needs no token; TCP always needs
/// one — the two are independent.
pub fn cmd_serve(rest: &[String]) -> Result<()> {
    let mut socket_arg: Option<PathBuf> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--socket" {
            socket_arg = Some(PathBuf::from(it.next().context("--socket needs a path")?));
        } else {
            bail!("unknown argument to den serve: {a}");
        }
    }
    let socket: Option<PathBuf> = socket_arg.or_else(|| {
        std::env::var("DEN_SOCKET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    });
    let token = std::env::var("DEN_API_TOKEN").unwrap_or_default();
    if socket.is_none() && token.is_empty() {
        bail!("DEN_API_TOKEN is required (or pass --socket) — den serve executes agent CLIs on this host; refusing to listen unauthenticated");
    }
    let bind_env = std::env::var("DEN_BIND").ok().filter(|s| !s.is_empty());
    if bind_env.is_some() && token.is_empty() {
        bail!("DEN_BIND requires DEN_API_TOKEN — TCP has no peercred, refusing to listen unauthenticated");
    }
    let bind: Option<std::net::SocketAddr> = if token.is_empty() {
        None
    } else {
        Some(
            bind_env
                .unwrap_or_else(|| "127.0.0.1:8520".into())
                .parse()
                .context("DEN_BIND (use [host:]port, default 127.0.0.1:8520)")?,
        )
    };
    let max_runs: usize = std::env::var("DEN_MAX_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    // Registry backend: DEN_REGISTRY_URL (default: the local SQLite
    // platform.db). External DB adapters plug in via Registry::open_url.
    let reg = match std::env::var("DEN_REGISTRY_URL") {
        Ok(url) => Registry::open_url(&url)?,
        Err(_) => Registry::open(&platform_db_path()?)?,
    };
    let moved = reg.sweep_orphans()?;
    if moved > 0 {
        eprintln!("den serve: marked {moved} run(s) orphaned from a previous serve");
    }
    let st = Arc::new(ServeState {
        reg: Arc::new(reg),
        runner: crate::runner::runner()?,
        token,
        max_runs,
        children: Mutex::new(HashMap::new()),
    });
    // Stop bookkeeping: the pid file pairs this daemon with its socket so
    // `den serve stop` can signal the right process without a host-wide
    // pkill.
    let pid_file = socket.as_ref().map(|p| pid_file_path(p));
    if let Some(pf) = &pid_file {
        if let Some(dir) = pf.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(pf, format!("{}\n", std::process::id())) {
            eprintln!("den serve: pid file {}: {e}", pf.display());
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let cleanup_socket = socket.clone();
    let res = rt.block_on(async move {
        let tcp = {
            let st = st.clone();
            async move {
                if let Some(addr) = bind {
                    let listener = tokio::net::TcpListener::bind(addr)
                        .await
                        .with_context(|| format!("bind {addr}"))?;
                    eprintln!("den serve: listening on {addr} (max_runs={max_runs})");
                    axum::serve(listener, router(st)).await?;
                }
                anyhow::Ok(())
            }
        };
        let sk = {
            let st = st.clone();
            async move {
                match socket {
                    Some(path) => serve_unix(st, path).await,
                    None => anyhow::Ok(()),
                }
            }
        };
        // SIGTERM (`den serve stop`) or SIGINT (Ctrl+C) shuts down cleanly;
        // in-flight connection tasks drop with the runtime right after.
        tokio::select! {
            r = async { tokio::try_join!(tcp, sk) } => r.map(|_| ()),
            _ = wait_stop_signal() => Ok(()),
        }
    });
    // The daemon owned the socket from boot until now; the connect() check
    // covers the narrow race where a replacement serve bound it during
    // shutdown — never unlink a socket someone else owns.
    if let Some(path) = &cleanup_socket {
        if path.exists() && std::os::unix::net::UnixStream::connect(path).is_err() {
            let _ = std::fs::remove_file(path);
        }
    }
    if let Some(pf) = &pid_file {
        remove_own_pid_file(pf);
    }
    res
}

/// `den serve stop [--socket PATH]` — graceful stop of the daemon on the
/// given socket: SIGTERM, 10 s grace, then SIGKILL. The daemon removes its
/// socket + pid file on the way down; the SIGKILL path cleans up here.
/// Parse `--socket PATH` — the only flag `stop`/`restart` accept — and
/// resolve it the way the CLI does everywhere: --socket, DEN_SOCKET, then
/// the standard dir chain (XDG_RUNTIME_DIR → XDG_STATE_HOME → $HOME).
fn resolved_socket(rest: &[String], cmd: &str) -> Result<PathBuf> {
    let mut socket: Option<PathBuf> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--socket" {
            socket = Some(PathBuf::from(it.next().context("--socket needs a path")?));
        } else {
            bail!("unknown argument to {cmd}: {a}");
        }
    }
    Ok(socket
        .or_else(|| {
            std::env::var("DEN_SOCKET")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(crate::client::socket_path))
}

pub fn cmd_serve_stop(rest: &[String]) -> Result<()> {
    let path = resolved_socket(rest, "den serve stop")?;
    match stop_daemon_at(&path)? {
        Some(pid) => println!("den serve: stopped pid {pid} ({})", path.display()),
        None => bail!("den serve: not running on {}", path.display()),
    }
    Ok(())
}

/// Signal, wait for, and clean up after the daemon on `path`. Returns the
/// stopped pid, or None when nothing was running — a dead socket/pid file
/// pair is tidied either way. Bails on a self-referential or foreign pid.
fn stop_daemon_at(path: &Path) -> Result<Option<i32>> {
    let sp = path.to_path_buf();
    let pid_file = pid_file_path(&sp);

    let mut pid = std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok());
    if pid.is_none() {
        // Daemon from before the pid file existed: health carries the pid.
        pid = crate::client::request(&sp, "GET", "/v1/health", None, None)
            .ok()
            .and_then(|(_, h)| h.get("pid").and_then(|p| p.as_u64()).map(|p| p as i32));
    }
    let Some(pid) = pid else {
        // Nothing to signal — still tidy a dead socket/pid file pair.
        if sp.exists() && std::os::unix::net::UnixStream::connect(&sp).is_err() {
            let _ = std::fs::remove_file(&sp);
        }
        let _ = std::fs::remove_file(&pid_file);
        return Ok(None);
    };
    if pid == std::process::id() as i32 {
        bail!(
            "pid file {} names this process — refusing",
            pid_file.display()
        );
    }
    if !is_den_serve(pid) {
        // Stale pid, reused by something else — drop the file, not the
        // innocent process.
        let _ = std::fs::remove_file(&pid_file);
        bail!("pid {pid} is not `den serve` — stale pid file removed");
    }
    // SAFETY: SIGTERM to a pid verified to be a den serve daemon.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while daemon_alive(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if daemon_alive(pid) {
        // SAFETY: force-kill of a daemon that ignored SIGTERM for 10 s.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        for _ in 0..20 {
            if !daemon_alive(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    // The SIGKILL path skips the daemon's own cleanup — finish the job.
    if sp.exists() && std::os::unix::net::UnixStream::connect(&sp).is_err() {
        let _ = std::fs::remove_file(&sp);
    }
    if std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        == Some(pid)
    {
        let _ = std::fs::remove_file(&pid_file);
    }
    Ok(Some(pid))
}

/// `den serve restart [--socket PATH]` — stop the daemon if one is running,
/// then boot a fresh daemon on the same socket and wait for /v1/health.
/// In-flight runs are orphaned by the stop and swept as such at the next boot.
pub fn cmd_serve_restart(rest: &[String]) -> Result<()> {
    let path = resolved_socket(rest, "den serve restart")?;
    if let Some(pid) = stop_daemon_at(&path)? {
        println!("den serve: stopped pid {pid}");
    } // none running — starting fresh
    crate::client::spawn_daemon_at(&path, false)?;
    let mut health = None;
    let mut last_err = String::new();
    for _ in 0..60 {
        match crate::client::try_daemon_at(&path) {
            Ok(h) => {
                health = Some(h);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let h = health.with_context(|| {
        format!(
            "den daemon did not come up at {} ({}; log: {})",
            path.display(),
            last_err,
            crate::client::daemon_log_path().display()
        )
    })?;
    let pid = h.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);
    println!("den serve: restarted pid {pid} ({})", path.display());
    Ok(())
}

/// pid-reuse guard: confirm the process is really a `den serve`. Hosts
/// without /proc (macOS) skip the check — the pid file is fresh there.
fn is_den_serve(pid: i32) -> bool {
    let cmd = match std::fs::read_to_string(format!("/proc/{pid}/cmdline")) {
        Ok(c) => c,
        Err(_) => return true,
    };
    let mut args = cmd.split('\0').filter(|s| !s.is_empty());
    let exe_is_den = args
        .next()
        .map(|a| {
            std::path::Path::new(a)
                .file_name()
                .map(|f| f == "den")
                .unwrap_or(false)
        })
        .unwrap_or(false);
    exe_is_den && args.any(|a| a == "serve")
}

/// True if the pid exists and is not a zombie: a background-started daemon
/// lingers as a zombie until its parent shell reaps it, and that is
/// "stopped" for our purposes (kill(0) alone would call it alive and stall
/// the stop loop for the full grace period).
fn daemon_alive(pid: i32) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // state is the first field after the (comm) parens — comm may
        // contain spaces, so rsplit on the last ')'
        Ok(s) => match s.rsplit_once(')') {
            Some((_, rest)) => !rest.trim_start().starts_with('Z'),
            None => true,
        },
        Err(_) => true, // no /proc — fall back to kill(0)
    }
}

/// `<socket>.pid` — the daemon's pid, written at boot, removed at shutdown.
/// (Not with_extension: that would turn "den.sock" into "den.pid".)
fn pid_file_path(socket: &std::path::Path) -> PathBuf {
    let mut s = socket.as_os_str().to_owned();
    s.push(".pid");
    PathBuf::from(s)
}

/// Drop the pid file only if it still names this process — never clobber
/// the file a newer daemon rewrote.
fn remove_own_pid_file(pf: &std::path::Path) {
    let mine = std::fs::read_to_string(pf)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    if mine.is_none() || mine == Some(std::process::id()) {
        let _ = std::fs::remove_file(pf);
    }
}

/// SIGTERM (`den serve stop`) or SIGINT (Ctrl+C) → graceful shutdown.
async fn wait_stop_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).context("signal handler")?;
    let mut int = signal(SignalKind::interrupt()).context("signal handler")?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
}

/// Local transport: accept loop with per-connection hyper http1 service.
/// Peer credentials are fetched at accept time and injected as request
/// extensions — auth_mw_socket consumes them (axum has no public
/// connect-info extractor for unix listeners).
async fn serve_unix(st: Arc<ServeState>, path: PathBuf) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create socket dir {}", dir.display()))?;
    }
    if path.exists() {
        // Live daemon already there? Refuse rather than steal the socket.
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            bail!("den serve already listening on {}", path.display());
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("remove stale socket {}", path.display()))?;
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("bind {}", path.display()))?;
    // 0600 (docs/socket-daemon.md §2): peercred is the real boundary, but
    // the file mode keeps other local users from even connecting.
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("den serve: chmod 0600 {}: {e}", path.display());
    }
    eprintln!("den serve: listening on {}", path.display());
    let base = socket_router(st);
    loop {
        let (stream, _) = listener.accept().await?;
        let creds = stream.peer_cred().ok();
        let base = base.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(
                move |req: axum::http::Request<hyper::body::Incoming>| {
                    let mut svc = base.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let mut req =
                            axum::http::Request::from_parts(parts, axum::body::Body::new(body));
                        if let Some(c) = creds {
                            req.extensions_mut().insert(c);
                        }
                        use tower::Service as _;
                        match svc.call(req).await {
                            Ok(resp) => Ok::<_, std::convert::Infallible>(resp),
                            Err(e) => match e {}, // Router error type is Infallible
                        }
                    }
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// env vars are process-global (dex_journal_path reads HOME)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn pid_file_sits_next_to_the_socket() {
        assert_eq!(
            pid_file_path(std::path::Path::new("/run/user/7/den.sock")),
            PathBuf::from("/run/user/7/den.sock.pid")
        );
    }

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
