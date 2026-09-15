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
pub(crate) fn daemon_log_path() -> PathBuf {
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
    if !(200..300).contains(&status) {
        bail!("den serve returned {status}: {}", error_message(&body));
    }
    if body.iter().all(|&b| b.is_ascii_whitespace()) {
        return Ok((status, json!({})));
    }
    let v = serde_json::from_slice(&body).context("non-JSON response body")?;
    Ok((status, v))
}

/// Best-effort human message from a non-2xx body: the daemon's
/// `{"error":{"code","message"}}` text when present, the raw body otherwise.
/// Without this, a 400/409 from the daemon surfaces as "no sid in response"
/// instead of what actually went wrong.
fn error_message(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    let s = s.trim();
    if s.is_empty() {
        return "(no body)".into();
    }
    serde_json::from_str::<Value>(s)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| s.to_string())
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

/// Connect to the running daemon; error (not autospawn) if absent.
pub fn try_daemon() -> Result<Value> {
    try_daemon_at(&socket_path())
}

/// Same health+version check against an exact socket path (`den serve
/// restart` waits on the socket it (re)spawned, not the default chain).
pub(crate) fn try_daemon_at(sp: &PathBuf) -> Result<Value> {
    let (_, h) = request(sp, "GET", "/v1/health", None, None)?;
    check_version(&h)?;
    Ok(h)
}

/// Connect, autospawning a detached `den serve --socket` if none is up.
/// DEN_AUTOSPAWN=0 (or a failed spawn) errors instead.
pub fn ensure_daemon() -> Result<()> {
    match try_daemon() {
        Ok(_) => return Ok(()),
        // A live but wrong-version daemon is not an autospawn situation:
        // a new spawn would refuse the live socket and the wait would
        // time out. Propagate the typed error with the restart hint.
        Err(e) if e.downcast_ref::<VersionMismatch>().is_some() => return Err(e),
        Err(_) => {}
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
    spawn_daemon_at(&socket_path(), true)
}

/// Spawn a daemon on an exact socket path — `den serve restart` uses this so
/// a `--socket` override survives the stop/start round trip.
///
/// `local_only` (autospawn) strips the TCP env: an autospawned daemon is a
/// local convenience, not a listener. Carrying DEN_API_TOKEN through would
/// silently open a bearer-auth'd TCP port, and DEN_BIND without a token
/// would fail boot. Restart keeps the env, so an explicitly-run TCP daemon
/// restarts as one.
pub(crate) fn spawn_daemon_at(sp: &PathBuf, local_only: bool) -> Result<()> {
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
    if try_daemon_at(sp).is_ok() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        // Truncate, not append: an append-mode daemon log grows forever
        // across boot cycles, and the previous daemon's output is not
        // worth keeping around (run logs live under the registry tree).
        .truncate(true)
        .open(daemon_log_path())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve")
        .arg("--socket")
        .arg(sp)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if local_only {
        cmd.env_remove("DEN_API_TOKEN").env_remove("DEN_BIND");
    }
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

/// The daemon's version differs from this CLI's. Callers must NOT treat
/// this as "no daemon" and silently fall back to the solo path — the socket
/// still answers, but its view of the world (daemon-created sessions, live
/// runs) differs. Recover: `den serve restart`.
#[derive(Debug)]
pub struct VersionMismatch {
    /// The running daemon's semver.
    pub daemon: String,
}

impl std::fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "den daemon is v{}, this CLI is v{} — restart it: den serve restart",
            self.daemon,
            env!("CARGO_PKG_VERSION")
        )
    }
}

impl std::error::Error for VersionMismatch {}

fn check_version(h: &Value) -> Result<()> {
    let v = h.get("version").and_then(|x| x.as_str()).unwrap_or("?");
    if v != env!("CARGO_PKG_VERSION") {
        return Err(anyhow::Error::new(VersionMismatch { daemon: v.into() }));
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

/// POST /v1/sessions → 201 SessionRow ({"sid", ...}). The seed spec passes
/// through untouched (dir/git are exclusive — the API rejects a mixed POST);
/// a silently-dropped seed flag here would leave the user's agent without
/// code while they believe it was seeded.
fn create_session(
    profile: &str,
    seed_dir: Option<&str>,
    seed_git: Option<&str>,
    seed_dirty: Option<&str>,
) -> Result<String> {
    let sp = socket_path();
    let mut body = json!({"profile": profile});
    if let Some(d) = seed_dir {
        body["seed_dir"] = json!(d);
    }
    if let Some(u) = seed_git {
        body["seed_git"] = json!(u);
    }
    if let Some(m) = seed_dirty {
        body["seed_dirty"] = json!(m);
    }
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
    seed_git: Option<&str>,
    seed_dirty: Option<&str>,
) -> Result<(String, String)> {
    let sid = create_session(profile, seed_dir, seed_git, seed_dirty)?;
    let rid = launch_run(&sid, prompt)?;
    Ok((sid, rid))
}

/// `den up`: create + launch, return (sid, rid) without streaming.
pub fn up(
    profile: &str,
    prompt: &str,
    seed_dir: Option<&str>,
    seed_git: Option<&str>,
    seed_dirty: Option<&str>,
) -> Result<(String, String)> {
    create_and_launch(profile, prompt, seed_dir, seed_git, seed_dirty)
}

/// GET /v1/sessions → {"sessions": [SessionRow]}.
pub fn sessions_list() -> Result<Value> {
    let sp = socket_path();
    let (_, v) = request(&sp, "GET", "/v1/sessions", None, token().as_deref())?;
    Ok(v.get("sessions").cloned().unwrap_or(json!([])))
}

/// Outcome of the push-style stream reader.
enum StreamOut {
    /// Terminal `done` frame arrived — the run is over.
    Done(Option<String>),
    /// The daemon predates /v1/runs/:id/stream — caller should poll.
    NoRoute,
}

/// Stream a run's log to stdout until it finishes. Returns delta_json (what
/// the agent changed) when the run captured one.
pub fn stream_run(rid: &str) -> Result<Option<String>> {
    match stream_run_push(rid) {
        Ok(out) => Ok(match out {
            StreamOut::Done(d) => d,
            StreamOut::NoRoute => stream_run_poll(rid)?,
        }),
        Err(e) => Err(e),
    }
}

/// Push flavor: one held connection, the daemon tails the log file and
/// pushes frames (`log <len>\n<bytes>\n`, a `ping` keepalive, terminal
/// `done <len>\n<json>\n`). O(log bytes) on the wire, ~150 ms delivery —
/// versus the poll flavor's whole-file re-download every 500 ms.
fn stream_run_push(rid: &str) -> Result<StreamOut> {
    let sp = socket_path();
    let mut stream =
        UnixStream::connect(&sp).with_context(|| format!("connect {}", sp.display()))?;
    // Long read timeout: a quiet run (long tool call) must not kill the
    // stream — the daemon pings every 5 s anyway.
    stream.set_read_timeout(Some(std::time::Duration::from_secs(600)))?;
    let req =
        format!("GET /v1/runs/{rid}/stream HTTP/1.1\r\nHost: den\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;

    // Read the header block incrementally — a streamed body never ends on
    // its own, so read_to_end would hang forever.
    let mut raw = Vec::new();
    let hdr_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            bail!("daemon closed the connection before responding");
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if raw.len() > 64 * 1024 {
            bail!("run stream header block too large");
        }
    };
    let status = parse_status(&raw[..hdr_end]).context("malformed http status line")?;
    if status == 404 {
        return Ok(StreamOut::NoRoute); // old daemon without /stream
    }
    if status != 200 {
        let msg = String::from_utf8_lossy(&raw[hdr_end + 4..]);
        bail!("run stream returned {status}: {}", msg.trim());
    }
    let chunked = raw[..hdr_end]
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"chunked"));

    let mut de = Dechunker::default();
    let mut frames = FrameBuf::default();
    let mut delta: Option<String> = None;
    let mut handle = |ev: &str, payload: &[u8]| -> Result<bool> {
        match ev {
            "log" => {
                print!("{}", String::from_utf8_lossy(payload));
                use std::io::Write as _;
                let _ = std::io::stdout().flush();
            }
            "ping" => {}
            "done" => {
                let v: Value = serde_json::from_slice(payload).unwrap_or(Value::Null);
                delta = v
                    .get("delta_json")
                    .and_then(|x| x.as_str())
                    .map(String::from);
                return Ok(false); // run is over — stop reading
            }
            // Forward-compat: a newer daemon may add frame types. Skip
            // them instead of tearing the stream down — the "done" frame
            // is what actually terminates this loop.
            _ => {}
        }
        Ok(true)
    };
    // Bytes that arrived with the header read may already hold body data.
    let keep = if chunked {
        frames.feed(&de.push(&raw[hdr_end + 4..])?, &mut handle)?
    } else {
        frames.feed(&raw[hdr_end + 4..], &mut handle)?
    };
    let mut keep = keep;
    while keep {
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            bail!("run stream ended without a done frame");
        }
        let decoded = if chunked {
            de.push(&chunk[..n])?
        } else {
            chunk[..n].to_vec()
        };
        keep = frames.feed(&decoded, &mut handle)?;
    }
    Ok(StreamOut::Done(delta))
}

/// Poll flavor (fallback for daemons from before /stream existed):
/// re-download the log, print the delta, 500 ms cadence.
fn stream_run_poll(rid: &str) -> Result<Option<String>> {
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

/// Incremental HTTP chunked-body decoder — the daemon streams responses
/// with `Transfer-Encoding: chunked` (body length is unknown up front).
#[derive(Default)]
struct Dechunker {
    state: ChunkState,
    line: Vec<u8>,
}

#[derive(Default)]
enum ChunkState {
    #[default]
    Size,
    Body(usize),
    /// after a body chunk: consume the exact CRLF before the next size line
    Cr,
    Lf,
    /// after the terminal 0 chunk: trailers until close — discarded
    Trailers,
}

impl Dechunker {
    /// Feed raw wire bytes; returns the decoded body bytes seen so far.
    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            match self.state {
                ChunkState::Size => {
                    if b == b'\n' {
                        let s = String::from_utf8(std::mem::take(&mut self.line))
                            .context("chunk size line not utf8")?;
                        let hex = s.trim().split(';').next().unwrap_or("");
                        let n = usize::from_str_radix(hex, 16).context("bad chunk size")?;
                        if n > MAX_STREAM_CHUNK {
                            bail!("chunk of {n} bytes exceeds the cap");
                        }
                        self.state = if n == 0 {
                            ChunkState::Trailers
                        } else {
                            ChunkState::Body(n)
                        };
                    } else {
                        if self.line.len() > 16 {
                            bail!("chunk size line too long");
                        }
                        self.line.push(b);
                    }
                }
                ChunkState::Body(rem) => {
                    out.push(b);
                    self.state = if rem == 1 {
                        ChunkState::Cr
                    } else {
                        ChunkState::Body(rem - 1)
                    };
                }
                ChunkState::Cr => {
                    if b == b'\r' {
                        self.state = ChunkState::Lf;
                    } else {
                        bail!("missing CR after chunk body");
                    }
                }
                ChunkState::Lf => {
                    if b == b'\n' {
                        self.state = ChunkState::Size;
                    } else {
                        bail!("missing LF after chunk body");
                    }
                }
                ChunkState::Trailers => {} // discard until the connection closes
            }
        }
        Ok(out)
    }
}

/// Extracts length-prefixed stream frames from a byte stream. Frame:
/// `event <len>\n<len bytes>\n` — matches serve's `frame()` encoder.
#[derive(Default)]
struct FrameBuf {
    buf: Vec<u8>,
}

impl FrameBuf {
    /// Feed bytes; calls `f` per complete frame. `f` returning false stops
    /// parsing (the terminal `done` frame) — further feeds become no-ops
    /// until the caller stops calling.
    fn feed(
        &mut self,
        data: &[u8],
        f: &mut dyn FnMut(&str, &[u8]) -> Result<bool>,
    ) -> Result<bool> {
        self.buf.extend_from_slice(data);
        loop {
            let Some(nl) = self.buf.iter().position(|&b| b == b'\n') else {
                return Ok(true);
            };
            if nl > 64 {
                bail!("stream frame header too long");
            }
            let head = String::from_utf8_lossy(&self.buf[..nl]).into_owned();
            let mut it = head.split(' ');
            let ev = it.next().unwrap_or("");
            let len: usize = it
                .next()
                .unwrap_or("")
                .parse()
                .context("bad stream frame length")?;
            if len > MAX_STREAM_CHUNK {
                bail!("stream frame of {len} bytes exceeds the {MAX_STREAM_CHUNK}-byte cap");
            }
            let total = nl + 1 + len + 1; // header line + payload + trailer LF
            if self.buf.len() < total {
                return Ok(true);
            }
            let payload = self.buf[nl + 1..nl + 1 + len].to_vec();
            self.buf.drain(..total);
            if !f(ev, &payload)? {
                return Ok(false);
            }
        }
    }
}

/// Upper bound for one decoded frame or chunk. Log frames are file chunks;
/// an unbounded declared length would let a stream balloon our buffer (the
/// peer is a same-uid local daemon, so this is hygiene, not a hardening
/// boundary).
const MAX_STREAM_CHUNK: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_mismatch_is_a_typed_error() {
        let e = check_version(&json!({"version": "9.9.9"})).unwrap_err();
        let vm = e
            .downcast_ref::<VersionMismatch>()
            .expect("mismatch downcasts to VersionMismatch");
        assert_eq!(vm.daemon, "9.9.9");
        assert!(e.to_string().contains("den serve restart"));
        // Same version must pass.
        check_version(&json!({"version": env!("CARGO_PKG_VERSION")})).unwrap();
    }

    #[test]
    fn error_message_prefers_the_daemons_text() {
        assert_eq!(
            error_message(br#"{"error":{"code":"max_runs","message":"session busy"}}"#),
            "session busy"
        );
        assert_eq!(
            error_message(b"plain text rejection"),
            "plain text rejection"
        );
        assert_eq!(error_message(b""), "(no body)");
    }

    #[test]
    fn dechunker_decodes_incremental_chunks() {
        let mut d = Dechunker::default();
        let mut out = d.push(b"5\r\nhello\r\n").unwrap();
        out.extend(d.push(b"6\r\n world\r\n2").unwrap());
        out.extend(d.push(b"\r\nab\r\n0\r\n\r\n").unwrap());
        assert_eq!(&out, b"hello worldab");
    }

    #[test]
    fn framebuf_extracts_framed_events_incrementally() {
        let mut f = FrameBuf::default();
        let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
        // incomplete frame stays buffered
        let keep1 = {
            let mut push = |ev: &str, p: &[u8]| -> Result<bool> {
                seen.push((ev.to_string(), p.to_vec()));
                Ok(true)
            };
            f.feed(b"log 5\nhello", &mut push).unwrap()
        };
        assert!(keep1);
        assert!(seen.is_empty());
        // completion + two more frames, one per event type
        let keep2 = {
            let mut push = |ev: &str, p: &[u8]| -> Result<bool> {
                seen.push((ev.to_string(), p.to_vec()));
                Ok(true)
            };
            f.feed(b"\nping 0\n\ndone 7\n{\"a\":1}\n", &mut push)
                .unwrap()
        };
        assert!(keep2);
        assert_eq!(
            seen,
            vec![
                ("log".to_string(), b"hello".to_vec()),
                ("ping".to_string(), b"".to_vec()),
                ("done".to_string(), b"{\"a\":1}".to_vec()),
            ]
        );
    }

    #[test]
    fn framebuf_stops_after_a_false_callback() {
        // the frame that returned false is fully delivered first; parsing
        // stops with anything after it still buffered
        let mut f = FrameBuf::default();
        let mut seen: Vec<String> = Vec::new();
        let keep = {
            let mut stop_after_two = |ev: &str, _p: &[u8]| -> Result<bool> {
                seen.push(ev.to_string());
                Ok(seen.len() < 2)
            };
            f.feed(b"log 5\nhello\ndone 2\nhi\n", &mut stop_after_two)
                .unwrap()
        };
        assert!(!keep);
        assert_eq!(seen, vec!["log".to_string(), "done".to_string()]);
    }

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
