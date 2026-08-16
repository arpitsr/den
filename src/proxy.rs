//! Host-side allowlist HTTP proxy for the sandbox (PIT_NET=proxy).
//!
//! M binds a listener on 127.0.0.1:<ephemeral> and spawns `pit proxy` with
//! the listener on fd 3. The sandbox reaches it at 10.0.2.2 (slirp's alias
//! for the host loopback); nft inside the sandbox allows TCP to 10.0.2.2 and
//! nothing else, so all egress funnels through here.
//!
//! Supports CONNECT (the bulk of agent traffic) and absolute-form HTTP.
//! Hosts are checked against the egress policy (see policy.rs: built-in
//! defaults + PIT_PROXY_POLICY yaml + PIT_PROXY_ALLOW). If
//! PIT_PROXY_UPSTREAM is set (the host's own proxy), requests chain
//! through it.

use crate::policy::{self, EgressPolicy};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::FromRawFd;

/// Exit immediately on termination signals (async-signal-safe).
extern "C" fn proxy_exit(_sig: libc::c_int) {
    // SAFETY: _exit is async-signal-safe.
    unsafe { libc::_exit(0) }
}

/// Run the proxy. `listen_fd` carries the bound listener (dup2'd by M).
pub fn run(listen_fd: libc::c_int) -> Result<()> {
    // SAFETY: sigaction with a valid struct and an async-signal-safe handler.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = proxy_exit as *const () as usize;
        for sig in [libc::SIGTERM, libc::SIGINT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    // SAFETY: fd 3 was dup2'd by the parent before exec. PIT_PROXY_LISTEN_PORT
    // is a debug/testing override that binds internally instead.
    let listener = match std::env::var("PIT_PROXY_LISTEN_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(p) => TcpListener::bind(("127.0.0.1", p))?,
            Err(_) => unsafe { TcpListener::from_raw_fd(listen_fd) },
        },
        Err(_) => unsafe { TcpListener::from_raw_fd(listen_fd) },
    };
    listener.set_nonblocking(false)?;

    let source = policy::local();
    let upstream = std::env::var("PIT_PROXY_UPSTREAM").ok();

    for conn in listener.incoming() {
        match conn {
            Ok(c) => {
                // Fail closed: no policy, no egress.
                let policy = match source.policy() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("proxy: policy: {}", e);
                        let _ = (&c).write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        continue;
                    }
                };
                let upstream = upstream.clone();
                // SAFETY: detached threads own their sockets.
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(c, &policy, upstream.as_deref()) {
                        eprintln!("proxy: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("proxy: accept: {}", e),
        }
    }
    Ok(())
}

fn handle_connection(client: TcpStream, policy: &EgressPolicy, upstream: Option<&str>) -> Result<()> {
    let mut reader = BufReader::new(client.try_clone()?);
    let head = read_head(&mut reader)?;
    let first = head.lines().next().context("empty request")?.to_string();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method == "CONNECT" {
        handle_connect(target, reader, client, policy, upstream)
    } else if target.starts_with("http://") {
        handle_http(method, target, &head, reader, client, policy, upstream)
    } else {
        bail!("unsupported request: {}", first)
    }
}

/// Reduce a proxy URL ("http://host:port/path") to "host:port" for
/// TcpStream::connect.
fn upstream_hostport(up: &str) -> &str {
    let rest = up.rsplit_once("://").map(|(_, r)| r).unwrap_or(up);
    rest.split('/').next().unwrap_or(rest)
}

/// CONNECT host:port — policy check, then a raw TCP tunnel. Chains
/// through the upstream proxy if one is configured.
fn handle_connect(
    target: String,
    mut reader: BufReader<TcpStream>,
    mut client: TcpStream,
    policy: &EgressPolicy,
    upstream: Option<&str>,
) -> Result<()> {
    let (host, port) = parse_authority(&target)?;
    if let Err(e) = check_allowed(&host, policy) {
        let _ = client.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        bail!("{}", e);
    }

    // (reader, writer) over the upstream socket; the chained path's reader
    // may hold bytes buffered past the CONNECT response head, so the relay
    // below must copy FROM it, not from a fresh socket clone.
    let (mut upstream_r, upstream_w) = if let Some(up) = upstream {
        let mut u = TcpStream::connect(upstream_hostport(up))
            .with_context(|| format!("upstream {}", up))?;
        u.write_all(
            format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target).as_bytes(),
        )?;
        let mut ureader = BufReader::new(u.try_clone()?);
        let resp = read_head(&mut ureader)?;
        let ok = resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200");
        if !ok {
            bail!(
                "upstream refused CONNECT {}: {}",
                target,
                resp.lines().next().unwrap_or("")
            );
        }
        (ureader, u)
    } else {
        let u = TcpStream::connect((host.as_str(), port))
            .with_context(|| format!("connect {}", target))?;
        (BufReader::new(u.try_clone()?), u)
    };

    // 200 to the client, then blind relay both ways.
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    let mut client2 = client.try_clone()?;
    let mut upstream_w2 = upstream_w.try_clone()?;
    // SAFETY: threads own disjoint halves (clones share the socket; each
    // direction uses its own pair — the kernel arbitrates).
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut upstream_w2);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut upstream_r, &mut client2);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

/// Absolute-form HTTP request: policy check, rebuild in origin-form (or
/// keep absolute-form for the upstream), single request per connection.
fn handle_http(
    method: String,
    target: String,
    head: &str,
    reader: BufReader<TcpStream>,
    mut client: TcpStream,
    policy: &EgressPolicy,
    upstream: Option<&str>,
) -> Result<()> {
    let url = parse_absolute_url(&target)?;
    if let Err(e) = check_allowed(&url.host, policy) {
        let _ = client.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        bail!("{}", e);
    }

    if let Some(up) = upstream {
        // Upstream proxies expect absolute-form; forward the (stripped) head.
        let mut u = TcpStream::connect(upstream_hostport(up))
            .with_context(|| format!("upstream {}", up))?;
        let first = head.lines().next().unwrap_or("").to_string();
        let rebuilt = strip_proxy_headers(head, Some(&first), None);
        u.write_all(rebuilt.as_bytes())?;
        relay_response(reader, client, u)
    } else {
        let origin = format!("{} {} HTTP/1.1", method, url.path);
        let rebuilt = strip_proxy_headers(head, Some(&origin), Some(&url.host_with_port()));
        let mut c = TcpStream::connect((url.host.as_str(), url.port))
            .with_context(|| format!("connect {}", target))?;
        c.write_all(rebuilt.as_bytes())?;
        relay_response(reader, client, c)
    }
}

/// Copy the upstream response back to the client, then close.
fn relay_response(
    mut reader: BufReader<TcpStream>,
    mut client: TcpStream,
    mut upstream: TcpStream,
) -> Result<()> {
    let mut up2 = upstream.try_clone()?;
    // SAFETY: threads own disjoint sockets.
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up2, &mut client);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut upstream);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

/// Rewrite a request head: drop Proxy-*/Connection/Keep-Alive headers, fix
/// the request line and Host, force Connection: close.
fn strip_proxy_headers(head: &str, request_line: Option<&str>, host: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(rl) = request_line {
        out.push_str(rl);
        out.push_str("\r\n");
    }
    let mut has_host = false;
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-")
            || lower.starts_with("connection:")
            || lower.starts_with("keep-alive:")
            || lower.starts_with("proxy-connection:")
        {
            continue;
        }
        if lower.starts_with("host:") {
            has_host = true;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !has_host {
        if let Some(h) = host {
            out.push_str(&format!("Host: {}\r\n", h));
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

/// Read a request/response head (up to `\r\n\r\n`), capped at 64 KiB.
fn read_head(reader: &mut BufReader<TcpStream>) -> Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.len() > 65536 {
            bail!("request head too large");
        }
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&line);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// "host:port" (port required for CONNECT; default 443 otherwise).
fn parse_authority(authority: &str) -> Result<(String, u16)> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>()),
        None => (authority.to_string(), Ok(443)),
    };
    let port = port.map_err(|_| anyhow::anyhow!("bad port in {}", authority))?;
    if host.is_empty() || host.contains('/') || host.contains(char::is_whitespace) {
        bail!("bad authority: {}", authority);
    }
    Ok((host, port))
}

struct Url {
    host: String,
    port: u16,
    path: String,
}

impl Url {
    fn host_with_port(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Parse "http://host[:port]/path".
fn parse_absolute_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("not an http URL: {}", url))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| anyhow::anyhow!("bad port in {}", url))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() || host.contains('/') {
        bail!("bad URL: {}", url);
    }
    Ok(Url { host, port, path })
}

/// Policy check with a 403-able error naming the escape hatches.
fn check_allowed(host: &str, policy: &EgressPolicy) -> Result<()> {
    if policy.allows(host) {
        Ok(())
    } else {
        bail!(
            "host {} denied by egress policy (extend: PIT_PROXY_ALLOW=comma,list or PIT_PROXY_POLICY=allow-deny.yaml)",
            host
        )
    }
}
