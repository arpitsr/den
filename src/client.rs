//! den ↔ den-serve local client (docs/socket-daemon.md).
//!
//! The daemon is `den serve` with a unix socket (`DEN_SOCKET` or
//! `$XDG_RUNTIME_DIR/den/den.sock`). The CLI is an opportunistic client:
//! if the socket answers, lifecycle commands proxy to it; if not, the CLI
//! either autospawns a daemon (`den up`) or falls back to the in-process
//! solo path (everything else). Transport is plain HTTP/1.1 over the
//! socket — the server is axum, so responses are ordinary HTTP; auth over
//! the local socket is SO_PEERCRED (same-uid = root), a bearer token is
//! optional and only ever narrows (never widens) the context.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Where serve listens and the CLI looks. Order: DEN_SOCKET, then
/// XDG_RUNTIME_DIR (per-user tmpfs, gone on reboot — no stale-socket
/// hygiene), then XDG_STATE_HOME (cron/CI without a runtime dir).
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("DEN_SOCKET") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("den").join("den.sock");
        }
    }
    let state = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local").join("state"));
    state.join("den").join("den.sock")
}

fn home() -> PathBuf {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Log file for autospawned daemons (stdout+stderr).
fn daemon_log_path() -> PathBuf {
    socket_path()
        .parent()
        .map(|p| p.join("daemon.log"))
        .unwrap_or_else(|| home().join("den-daemon.log"))
}

// ---- minimal HTTP/1.1 over the unix socket ---------------------------------

/// One request, one response, connection closed after (Connection: close).
/// Returns (status, raw body bytes).
pub fn request_raw(
    socket: &PathBuf,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<(u16, Vec<u8>)> {
    let payload = body.map(|b| b.to_string());
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    // Long read timeout: proxied run waits can hold the connection.
    stream.set_read_timeout(Some(std::time::Duration::from_secs(600)))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: den\r\nConnection: close\r\n");
    if let Some(t) = token {
        req += &format!("Authorization: Bearer {t}\r\n");
    }
    if let Some(b) = &payload {
        req += "Content-Type: application/json\r\n";
        req += &format!("Content-Length: {}\r\n", b.len());
    }
    req += "\r\n";
    stream.write_all(req.as_bytes())?;
    if let Some(b) = &payload {
        stream.write_all(b.as_bytes())?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let (head, body) = split_http(&raw).context("malformed http response from den serve")?;
    let status = parse_status(head).context("malformed http status line")?;
    Ok((status, body.to_vec()))
}

/// JSON-flavored request: `{}` for empty bodies.
pub fn request(
    socket: &PathBuf,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<(u16, Value)> {
    let (status, body) = request_raw(socket, method, path, body, token)?;
    if body.iter().all(|&b| b.is_ascii_whitespace()) {
        return Ok((status, json!({})));
    }
    let v = serde_json::from_slice(&body).context("non-JSON response body")?;
    Ok((status, v))
}

fn split_http(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let idx = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((&raw[..idx], &raw[idx + 4..]))
}

fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let tok = std::str::from_utf8(line).ok()?.split_whitespace().nth(1)?;
    tok.parse().ok()
}

// ---- daemon discovery / autospawn ------------------------------------------

/// Health of a live daemon, if one answers on the socket. Never spawns.
pub fn try_health() -> Result<Value> {
    let sp = socket_path();
    let (_, h) = request(&sp, "GET", "/v1/health", None, None)?;
    Ok(h)
}

/// Connect to the running daemon; error (not autospawn) if absent.
pub fn try_daemon() -> Result<Value> {
    let h = try_health()?;
    check_version(&h)?;
    Ok(h)
}

/// Connect, autospawning a detached `den serve --socket` if none is up.
/// DEN_AUTOSPAWN=0 (or a failed spawn) errors instead.
pub fn ensure_daemon() -> Result<()> {
    if try_daemon().is_ok() {
        return Ok(());
    }
    if std::env::var("DEN_AUTOSPAWN").as_deref() == Ok("0") {
        bail!(
            "no den daemon at {} (DEN_AUTOSPAWN=0)",
            socket_path().display()
        );
    }
    spawn_daemon()?;
    for _ in 0..60 {
        if try_daemon().is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    bail!(
        "den daemon did not come up at {} (log: {})",
        socket_path().display(),
        daemon_log_path().display()
    );
}

/// Detached spawn, serialized by an flock-ed lock file so parallel first
/// calls don't race: the winner spawns, losers just wait for the socket.
fn spawn_daemon() -> Result<()> {
    let sp = socket_path();
    let lock_path = sp.with_extension("autospawn.lock");
    if let Some(dir) = lock_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let lock = std::fs::File::create(&lock_path)?;
    // SAFETY: flock with LOCK_EX on a file we own; released on exit.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!("flock autospawn lock {}", lock_path.display());
    }
    // Re-check: the lock holder may have finished spawning already.
    if try_daemon().is_ok() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(daemon_log_path())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve")
        .arg("--socket")
        .arg(&sp)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    cmd.spawn().context("spawn den serve (autospawn)")?;
    // Drop nothing: `lock` held until return → flock released, other waiters
    // proceed; the child outlives us (process group, parent exits).
    Ok(())
}

fn check_version(h: &Value) -> Result<()> {
    let v = h.get("version").and_then(|x| x.as_str()).unwrap_or("?");
    let mine = env!("CARGO_PKG_VERSION");
    if v != mine {
        bail!("den daemon is v{v}, this CLI is v{mine} — restart it: den serve restart");
    }
    Ok(())
}

// ---- proxied operations -----------------------------------------------------

/// Bearer token for proxied calls: optional over the local socket (peercred
/// is the default context); a minted key narrows the caller explicitly.
fn token() -> Option<String> {
    std::env::var("DEN_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

/// POST /v1/sessions → 201 SessionRow ({"sid", ...}).
fn create_session(profile: &str, seed_dir: Option<&str>) -> Result<String> {
    let sp = socket_path();
    let body = match seed_dir {
        Some(d) => json!({"profile": profile, "seed_dir": d}),
        None => json!({"profile": profile}),
    };
    let (_, v) = request(&sp, "POST", "/v1/sessions", Some(&body), token().as_deref())?;
    v.get("sid")
        .and_then(|x| x.as_str())
        .map(String::from)
        .context("create session: no sid in response")
}

/// POST /v1/sessions/{sid}/runs → 202 {"run_id", "status"}.
fn launch_run(sid: &str, prompt: &str) -> Result<String> {
    let sp = socket_path();
    let (_, v) = request(
        &sp,
        "POST",
        &format!("/v1/sessions/{sid}/runs"),
        Some(&json!({"prompt": prompt})),
        token().as_deref(),
    )?;
    v.get("run_id")
        .and_then(|x| x.as_str())
        .map(String::from)
        .context("launch run: no run_id in response")
}

/// Create + launch; returns (sid, rid).
pub fn create_and_launch(
    profile: &str,
    prompt: &str,
    seed_dir: Option<&str>,
) -> Result<(String, String)> {
    let sid = create_session(profile, seed_dir)?;
    let rid = launch_run(&sid, prompt)?;
    Ok((sid, rid))
}

/// `den up`: create + launch, return (sid, rid) without streaming.
pub fn up(profile: &str, prompt: &str, seed_dir: Option<&str>) -> Result<(String, String)> {
    create_and_launch(profile, prompt, seed_dir)
}

/// GET /v1/sessions → {"sessions": [SessionRow]}.
pub fn sessions_list() -> Result<Value> {
    let sp = socket_path();
    let (_, v) = request(&sp, "GET", "/v1/sessions", None, token().as_deref())?;
    Ok(v.get("sessions").cloned().unwrap_or(json!([])))
}

/// Stream a run's log to stdout until it finishes. Returns delta_json (what
/// the agent changed) when the run captured one.
pub fn stream_run(rid: &str) -> Result<Option<String>> {
    let sp = socket_path();
    let mut printed = 0usize;
    loop {
        let (_, log) = request_raw(
            &sp,
            "GET",
            &format!("/v1/runs/{rid}/log"),
            None,
            token().as_deref(),
        )?;
        if log.len() > printed {
            print!("{}", String::from_utf8_lossy(&log[printed..]));
            let _ = std::io::Write::flush(&mut std::io::stdout());
            printed = log.len();
        }
        let (_, status) = request(
            &sp,
            "GET",
            &format!("/v1/runs/{rid}"),
            None,
            token().as_deref(),
        )?;
        let st = status
            .get("status")
            .and_then(|x| x.as_str())
            .unwrap_or("running");
        if st != "running" && st != "queued" {
            return Ok(status
                .get("delta_json")
                .and_then(|x| x.as_str())
                .map(String::from));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_prefers_env_then_runtime_dir() {
        std::env::set_var("DEN_SOCKET", "/tmp/x.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/x.sock"));
        std::env::remove_var("DEN_SOCKET");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/42");
        assert_eq!(socket_path(), PathBuf::from("/run/user/42/den/den.sock"));
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_STATE_HOME", "/state");
        assert_eq!(socket_path(), PathBuf::from("/state/den/den.sock"));
        std::env::remove_var("XDG_STATE_HOME");
    }

    #[test]
    fn http_parse_status_and_body() {
        let raw =
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"sid\":\"s-1\"}";
        let (head, body) = split_http(raw).unwrap();
        assert_eq!(parse_status(head).unwrap(), 201);
        let v: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(v["sid"], "s-1");
        // empty body → {} (204-style responses)
        let raw2 = b"HTTP/1.1 204 No Content\r\n\r\n";
        let (h2, b2) = split_http(raw2).unwrap();
        assert_eq!(parse_status(h2).unwrap(), 204);
        assert!(b2.iter().all(|&b| b.is_ascii_whitespace()));
    }
}
