//! Virtual-FS sandbox using FUSE and Linux namespaces — ported from the
//! agentfs CLI (`cli/src/sandbox/linux.rs`, MIT) so den no longer shells out.
//!
//! The session's SQLite DB (~/.den/sessions/<sid>/fs.db) IS the filesystem:
//! a FUSE mount serving it is placed on a hidden dir (~/.den/sessions/<sid>/mnt),
//! then a child with its own user+mount namespace bind-mounts it onto the cwd.
//! Everything else is remounted read-only except an allowlist. New sessions
//! start empty (or seeded via --seed in main.rs); resumed sessions open the
//! DB and nothing else — the host tree under the mount is hidden and
//! irrelevant. The SDK reads the DB back for the touched-this-run diff.
//!
//! The FUSE mount at ~/.den/sessions/<sid>/mnt lives in *this* process's
//! namespace, so a second `den` invocation with the same sid joins it —
//! multiple terminals share one session's fs.db.
//!
//! Process tree (DEN_NET != full):
//!
//!   M (den, init userns, host netns)
//!    ├─ P (den proxy: host-side allowlist HTTP proxy, fd 3 = listener)
//!    └─ N (sandbox userns — maps "0 <host-uid> 1" so exec keeps root caps;
//!         still in the host netns, so it can spawn slirp4netns which
//!         setns()es into U's netns to create tap0)
//!        └─ U (mount/pid/ipc/uts/net namespaces, in-ns root:
//!             fresh /dev, /tmp, /run, /var/tmp; nft egress rules; hides)
//!           └─ A (agent, pid 1 of the pid ns: /proc remount, rlimits,
//!                no_new_privs, seccomp, exec)
//!
//! Sync pipes:  M<->N  uid_map handshake (same protocol as before)
//!              U ->N  "netns ready" (U unshared its netns; N may spawn slirp)
//!              N ->U  "net ready"   (slirp's --ready-fd: tap0 up + configured)
//!              U ->N  agent pid (4 bytes, after A forks)
//!
//! Network (DEN_NET=proxy, the default): N runs
//!   slirp4netns --configure --userns-path=/proc/U/ns/user \
//!               --netns-type=path /proc/U/ns/net --ready-fd=FD tap0
//! giving eth0 10.0.2.100/24. 10.0.2.2 = host loopback (the proxy P),
//! 10.0.2.3 = DNS forwarder (resolv.conf is overridden to it). U then applies
//! nft rules: allow lo, allow DNS to 10.0.2.3, allow TCP to 10.0.2.2 (the
//! proxy), drop everything else — egress is impossible outside the proxy,
//! and the proxy itself enforces an allowlist. DEN_NET=none keeps the netns
//! but no slirp/nft; DEN_NET=full keeps the legacy behaviour (host network).

use crate::layer::LayeredFS;
use crate::mount::{mount_fs, MountOpts};
use crate::run_dir;
use agentfs_sdk::filesystem::FileSystem;
use agentfs_sdk::{AgentFS, AgentFSOptions};
use anyhow::{bail, Context, Result};
use std::cmp::Reverse;
use std::ffi::CString;
use std::fs;
use std::io::BufRead;
use std::net::TcpListener;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicI32, Ordering};

/// Network isolation mode (DEN_NET).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetMode {
    /// netns + slirp4netns + nft egress policy + local allowlist proxy
    /// (default, falls back to Full with a warning when tools are missing)
    Proxy,
    /// netns only: no network inside (fast DNS failure, no proxy)
    None,
    /// legacy: shared host network
    Full,
}

impl NetMode {
    pub fn from_env() -> NetMode {
        match std::env::var("DEN_NET").as_deref() {
            Ok("none") => NetMode::None,
            Ok("full") => NetMode::Full,
            Ok("proxy") => NetMode::Proxy,
            Ok(other) => {
                eprintln!(
                    "warning: unknown DEN_NET={} (proxy|none|full), using proxy",
                    other
                );
                NetMode::Proxy
            }
            Err(_) => {
                // Nested runs (a subagent's den inside the sandbox, §7.4):
                // no egress by default — `none` skips slirp + proxy entirely.
                if crate::nested_run() {
                    return NetMode::None;
                }
                if bin_found("slirp4netns") && bin_found("nft") {
                    NetMode::Proxy
                } else {
                    eprintln!(
                        "warning: slirp4netns and/or nft not found on PATH — falling back to \
                         DEN_NET=full (shared host network, no egress policy)"
                    );
                    NetMode::Full
                }
            }
        }
    }
}

/// Is a binary on PATH? (dumb but adequate)
fn bin_found(bin: &str) -> bool {
    match std::env::var("PATH") {
        Ok(path) => path.split(':').any(|dir| {
            let p = Path::new(dir).join(bin);
            p.is_file()
        }),
        Err(_) => false,
    }
}

/// Global child PID for signal forwarding (set by the parent): N, plus the
/// host-side proxy P.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);
static PROXY_PID: AtomicI32 = AtomicI32::new(0);

/// First termination signal forwards to child; the second sends SIGUSR1
/// (which the chain escalates to SIGKILL).
static TERM_SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// In N: the agent's pid (pid 1 of the sandbox pid ns). Unknown until U forks.
static AGENT_PID: AtomicI32 = AtomicI32::new(0);
static N_SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// Exit code when exec fails (shell convention for "command not found").
const EXIT_COMMAND_NOT_FOUND: i32 = 127;

/// Timeout for waiting for the FUSE mount to become ready.
const FUSE_MOUNT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Timeout for slirp4netns --ready-fd.
const SLIRP_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Virtual filesystems that must remain writable for system operation.
const SKIP_MOUNT_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/tmp", "/run", "/var/tmp"];

/// Default directories allowed to be writable (common agent config/cache dirs).
const DEFAULT_ALLOWED_DIRS: &[&str] = &[
    ".amp",         // Amp config
    ".cache",       // XDG cache directory (corepack, pip, etc.)
    ".claude",      // Claude Code config
    ".claude.json", // Claude Code config file
    ".codex",       // OpenAI Codex config
    ".ak",          // ak agent config
    ".gemini",      // Gemini CLI config
    ".local",       // Local data directory
    ".npm",         // npm local registry
];

/// The four XDG base directories: `(env var, default subdir under $HOME)`.
/// `$VAR` wins when absolute; otherwise (unset, empty, or relative — a
/// relative XDG value is meaningless against a read-only `/`) the default
/// subdir is used. Empty HOME yields relative paths; callers must skip those.
const XDG_BASES: &[(&str, &str)] = &[
    ("XDG_CONFIG_HOME", ".config"),     // ~/.config
    ("XDG_DATA_HOME", ".local/share"),  // ~/.local/share
    ("XDG_STATE_HOME", ".local/state"), // ~/.local/state
    ("XDG_CACHE_HOME", ".cache"),       // ~/.cache
];

/// Secrets hidden from the agent by default: shadowed by an empty tmpfs
/// (dirs) or a /dev/null bind (files). DEN_NO_HIDE=~/.ssh restores.
const DEFAULT_HIDE: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".netrc",
    ".git-credentials",
    ".config/gcloud",
    ".config/gh",
];

/// Field index for mount point in /proc/self/mountinfo.
/// Format: ID PARENT_ID MAJOR:MINOR ROOT MOUNT_POINT OPTIONS ...
const MOUNTINFO_MOUNT_POINT_FIELD: usize = 4;

/// Signal handler forwarding termination signals to the sandboxed child (N)
/// and the proxy P. First signal forwards as-is; the second escalates:
/// SIGUSR1 to N (which SIGKILLs the agent) and SIGKILL to P.
///
/// SAFETY: async-signal-safe only (kill + atomics).
extern "C" fn forward_signal_to_child(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    let ppid = PROXY_PID.load(Ordering::SeqCst);
    let count = TERM_SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
    // SAFETY: kill() is async-signal-safe
    unsafe {
        if count == 0 {
            if pid > 0 {
                libc::kill(pid, sig);
            }
            if ppid > 0 {
                libc::kill(ppid, sig);
            }
        } else {
            if pid > 0 {
                libc::kill(pid, libc::SIGUSR1);
            }
            if ppid > 0 {
                libc::kill(ppid, libc::SIGKILL);
            }
        }
    }
}

/// In N: forward signals to the agent. First signal as-is, second (or
/// SIGUSR1 from M) is SIGKILL.
///
/// SAFETY: async-signal-safe only (kill + atomics).
extern "C" fn forward_signal_to_agent(sig: libc::c_int) {
    let pid = AGENT_PID.load(Ordering::SeqCst);
    if pid > 0 {
        let count = N_SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        // SAFETY: kill() is async-signal-safe
        unsafe {
            if sig == libc::SIGUSR1 || count > 0 {
                libc::kill(pid, libc::SIGKILL);
            } else {
                libc::kill(pid, sig);
            }
        }
    }
}

/// Install a handler for `sig` (async-signal-safe handler fn).
fn install_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY: sigaction with a valid struct and async-signal-safe handler.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            eprintln!(
                "warning: failed to install signal handler: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Install SIGTERM/SIGINT handlers that forward to N and P.
fn install_signal_handlers() {
    TERM_SIGNAL_COUNT.store(0, Ordering::SeqCst);
    // SAFETY: sigset operations are always safe.
    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGTERM);
        libc::sigaddset(&mut sigset, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &sigset, std::ptr::null_mut());
    }
    install_handler(libc::SIGTERM, forward_signal_to_child);
    install_handler(libc::SIGINT, forward_signal_to_child);
}

/// One sandboxed run: mount the overlay (or join the existing session), fork
/// the M→N→U→A chain in fresh namespaces with the rest of the FS read-only,
/// exec `command`, then clean up and return its exit code.
pub async fn run_cmd(
    allow: Vec<String>,
    session_id: String,
    command: PathBuf,
    args: Vec<String>,
) -> Result<i32> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    if std::env::var("DEN_SANDBOX_DEBUG").is_ok() {
        eprintln!("sandbox: cwd={} sid={}", cwd.display(), session_id);
    }
    let allowed_paths = build_allowed_paths(&allow)?;

    let session = setup_run_directory(&session_id)?;

    // A crashed earlier run can leave a FUSE mount whose daemon is gone:
    // every access through it fails with ENOTCONN ("Transport endpoint is
    // not connected"), and is_mountpoint can't even see it. Drop the corpse
    // so this run mounts fresh instead of erroring out.
    if crate::mount::is_dead_mount(&session.fuse_mountpoint) {
        eprintln!(
            "den: dead FUSE mount at {} (daemon gone) — unmounting",
            session.fuse_mountpoint.display()
        );
        if let Err(e) = crate::mount::unmount_fuse(&session.fuse_mountpoint, true) {
            eprintln!("den: failed to unmount dead mount: {e:#}");
        }
    }

    // Same layout as agentfs: if the FUSE mountpoint is already mounted, join
    // the running session instead of starting a second overlay.
    if crate::mount::is_mountpoint(&session.fuse_mountpoint) {
        if std::env::var("DEN_SANDBOX_DEBUG").is_ok() {
            eprintln!("sandbox: joining existing session");
        }
        let overlay_base = std::fs::read_to_string(&session.base_path_file)
            .context("Failed to read session base path")?;
        let overlay_base = PathBuf::from(overlay_base.trim());
        return run_in_existing_session(
            &overlay_base,
            &session.fuse_mountpoint,
            &allowed_paths,
            command,
            args,
            &session_id,
        );
    }

    // The session DB IS the whole filesystem (full-vfs model): no HostFS
    // base, no copy-on-write overlay. Mount agentfs.fs directly — an empty
    // DB presents an empty dir, a seeded/resumed one its stored tree.
    let db_path_str = session
        .db_path
        .to_str()
        .context("Database path contains non-UTF8 characters")?;
    let delta = AgentFS::open(AgentFSOptions::with_path(db_path_str.to_string()))
        .await
        .context("Failed to open session AgentFS")?;

    let cwd_str = cwd
        .to_str()
        .context("Current directory path contains non-UTF8 characters")?;

    // Write the cwd for session joining (bind-mount target)
    fs::write(&session.base_path_file, cwd_str).context("Failed to write session base path")?;

    let mount_opts = MountOpts {
        mountpoint: session.fuse_mountpoint.clone(),
        fsname: format!("agentfs:{}", session_id),
        allow_other: false,
        allow_root: false,
        auto_unmount: false,
        lazy_unmount: true,
        timeout: FUSE_MOUNT_TIMEOUT,
    };

    // Layered sessions (docs/layered-sessions.md §3): a shared read-only
    // base DB + this session's sparse delta, merged by LayeredFS. Legacy
    // sessions (no `base` pointer) mount fs.db directly — full-vfs model,
    // exactly the old behavior.
    let delta_fs = delta.fs.clone();
    let fs: std::sync::Arc<tokio::sync::Mutex<dyn FileSystem + Send>> =
        match crate::session_base_db(&session_id)? {
            Some(base_db) => {
                let base = AgentFS::open(AgentFSOptions::with_path(
                    base_db.to_string_lossy().to_string(),
                ))
                .await
                .with_context(|| format!("open base {}", base_db.display()))?;
                let layered = LayeredFS::open(Some(base.fs.clone()), delta_fs).await?;
                std::sync::Arc::new(tokio::sync::Mutex::new(layered))
            }
            None => std::sync::Arc::new(tokio::sync::Mutex::new(delta_fs)),
        };

    let mount_handle = mount_fs(fs, mount_opts).await?;

    let net = NetMode::from_env();
    let exit_code = run_chain(
        &cwd,
        &session.fuse_mountpoint,
        &allowed_paths,
        command,
        args,
        &session_id,
        net,
    );

    // Drop the mount handle to unmount. Drop chdir's to "/" first (unmount
    // EBUSY guard), so restore the caller's cwd after — den lives on for the
    // next run, unlike the agentfs CLI which exits here.
    drop(mount_handle);
    if std::env::set_current_dir(&cwd).is_err() {
        eprintln!("Warning: failed to restore cwd to {}", cwd.display());
    }

    // Clean up the FUSE mountpoint dir (keep the fs.db).
    if let Err(e) = fs::remove_dir_all(&session.fuse_mountpoint) {
        eprintln!(
            "Warning: Failed to clean up mountpoint {}: {}",
            session.fuse_mountpoint.display(),
            e
        );
    }

    Ok(exit_code)
}

/// Run a command in an already-mounted session (join path).
fn run_in_existing_session(
    cwd: &Path,
    fuse_mountpoint: &Path,
    allowed_paths: &[PathBuf],
    command: PathBuf,
    args: Vec<String>,
    session_id: &str,
) -> Result<i32> {
    let net = NetMode::from_env();
    Ok(run_chain(
        cwd,
        fuse_mountpoint,
        allowed_paths,
        command,
        args,
        session_id,
        net,
    ))
}

/// Shared M-side of the N→U→A chain: pipes, proxy spawn, uid_map handshake,
/// signal forwarding, reaping. Used by both fresh runs and session joins.
fn run_chain(
    cwd: &Path,
    fuse_mountpoint: &Path,
    allowed_paths: &[PathBuf],
    command: PathBuf,
    args: Vec<String>,
    session_id: &str,
    net: NetMode,
) -> i32 {
    // SAFETY: getuid/getgid are always safe
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Host-side proxy (P): bound to 127.0.0.1:<ephemeral>, reached from the
    // sandbox at 10.0.2.2:<port>. The listener fd is passed on fd 3.
    let mut proxy_pid: libc::pid_t = 0;
    if net == NetMode::Proxy {
        match spawn_proxy() {
            Ok(pid) => proxy_pid = pid,
            Err(e) => {
                eprintln!(
                    "warning: failed to start proxy, continuing without egress: {}",
                    e
                );
            }
        }
    }

    // resolv.conf override for the sandbox (nameserver 10.0.2.3).
    let mut resolv_path: Option<PathBuf> = None;
    if net == NetMode::Proxy {
        let run = run_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
        let p = run.join(session_id).join("resolv.conf");
        if fs::write(&p, "nameserver 10.0.2.3\n").is_ok() {
            resolv_path = Some(p);
        }
    }

    let (map_to_child, map_to_parent) = create_sync_pipes().expect("pipe");
    let netns = pipe2();
    let netready = pipe2();
    let apid = pipe2();
    let (netns_r, netns_w) = (netns[0], netns[1]);
    let (netready_r, netready_w) = (netready[0], netready[1]);
    let (apid_r, apid_w) = (apid[0], apid[1]);

    // SAFETY: fork() from a single-threaded context; the child closes unused
    // fds and execs after namespace setup without touching async state.
    let n_pid = unsafe { libc::fork() };
    if n_pid < 0 {
        eprintln!("Failed to fork: {}", std::io::Error::last_os_error());
        return 1;
    }

    if n_pid == 0 {
        // N: keeps every sync fd — U is forked later, so N must hold U's
        // ends too (netns_w, netready_r, apid_w) to hand them across.
        run_ns_holder(
            cwd,
            fuse_mountpoint,
            allowed_paths,
            command,
            args,
            session_id,
            map_to_child[0],
            map_to_parent[1],
            netns_r,
            netns_w,
            netready_r,
            netready_w,
            apid_r,
            apid_w,
            net,
            resolv_path.as_deref(),
        );
    }

    // M continues: close everything we don't use anymore.
    unsafe {
        libc::close(map_to_child[0]);
        libc::close(map_to_parent[1]);
        libc::close(netns_r);
        libc::close(netns_w);
        libc::close(netready_r);
        libc::close(netready_w);
        libc::close(apid_r);
        libc::close(apid_w);
    }

    // Wait for N to signal that it has called unshare.
    if !wait_for_pipe_signal(map_to_parent[0]) {
        eprintln!("Error: Failed to read sync signal from child process");
        abort_child(map_to_child[1], n_pid);
    }

    write_namespace_mappings(n_pid, uid, gid, map_to_child[1]);

    // Signal N that mappings are done.
    // SAFETY: writing to and closing valid pipe fds.
    unsafe {
        libc::write(map_to_child[1], b"x".as_ptr() as *const libc::c_void, 1);
        libc::close(map_to_child[1]);
        libc::close(map_to_parent[0]);
    }

    CHILD_PID.store(n_pid, Ordering::SeqCst);
    PROXY_PID.store(proxy_pid, Ordering::SeqCst);
    install_signal_handlers();
    let exit_code = wait_for_child(n_pid);

    // Stop the proxy (P).
    if proxy_pid > 0 {
        // SAFETY: kill + waitpid on a valid child pid.
        unsafe {
            libc::kill(proxy_pid, libc::SIGTERM);
            let mut status: libc::c_int = 0;
            libc::waitpid(proxy_pid, &mut status, 0);
        }
    }

    exit_code
}

/// N: the sandbox user-namespace holder. Unshares the userns (maps
/// "0 <host-uid> 1" — in-ns root so exec keeps its caps, the standard
/// rootless-sandbox pattern), forks U, spawns slirp4netns once U's netns
/// exists, waits for the agent pid, forwards signals, reaps everything.
// Arity is intentional: N's setup plumbing mirrors the fork/exec boundary,
// bundling it into a struct would just add indirection at every use site.
#[allow(clippy::too_many_arguments)]
fn run_ns_holder(
    cwd: &Path,
    fuse_mountpoint: &Path,
    allowed_paths: &[PathBuf],
    command: PathBuf,
    args: Vec<String>,
    session_id: &str,
    map_read: libc::c_int,
    map_write: libc::c_int,
    netns_read: libc::c_int,
    netns_write: libc::c_int,
    netready_read: libc::c_int,
    netready_write: libc::c_int,
    apid_read: libc::c_int,
    apid_write: libc::c_int,
    net: NetMode,
    resolv: Option<&Path>,
) -> ! {
    // Forwarder installed early (agent pid unknown yet → no-op) so a signal
    // in the setup window can't kill N and orphan the sandbox.
    N_SIGNAL_COUNT.store(0, Ordering::SeqCst);
    install_handler(libc::SIGTERM, forward_signal_to_agent);
    install_handler(libc::SIGINT, forward_signal_to_agent);
    install_handler(libc::SIGUSR1, forward_signal_to_agent);

    // Step 1: new user namespace (maps are written by M).
    // SAFETY: unshare() with valid flags; error handled.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        child_exit(&format!(
            "Failed to unshare user namespace: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 2: signal M so it writes uid_map/gid_map.
    // SAFETY: writing to and closing valid pipe fds.
    unsafe {
        libc::write(map_write, b"x".as_ptr() as *const libc::c_void, 1);
        libc::close(map_write);
    }

    // Step 3: wait for the mappings.
    if !wait_for_pipe_signal(map_read) {
        child_exit("Failed to read sync signal from parent: pipe closed unexpectedly");
    }
    // SAFETY: closing a valid fd.
    unsafe { libc::close(map_read) };

    // Step 4: fork U (the mount/pid/ipc/uts/net namespace setup).
    // SAFETY: fork() in a single-threaded child.
    let upid = unsafe { libc::fork() };
    if upid < 0 {
        child_exit(&format!(
            "Failed to fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if upid == 0 {
        // U: keep the U-side ends (netns_write, netready_read, apid_write).
        unsafe {
            libc::close(netns_read);
            libc::close(netready_write);
            libc::close(apid_read);
        }
        run_sandbox_child(
            cwd,
            fuse_mountpoint,
            allowed_paths,
            command,
            args,
            session_id,
            netns_write,
            netready_read,
            apid_write,
            net,
            resolv,
        );
    }

    // N continues: close the U-side ends it doesn't need.
    unsafe {
        libc::close(netns_write);
        libc::close(netready_read);
        libc::close(apid_write);
    }

    // Step 5: once U's netns exists, spawn slirp4netns (proxy mode only).
    let mut slirp: Option<Child> = None;
    if net == NetMode::Proxy {
        if !wait_for_pipe_signal(netns_read) {
            child_exit("U failed to signal netns ready");
        }
        // SAFETY: closing a valid fd.
        unsafe { libc::close(netns_read) };

        let ready = pipe2();
        let (ready_r, ready_w) = (ready[0], ready[1]);
        slirp = match spawn_slirp(upid, ready_w) {
            Ok(c) => Some(c),
            Err(e) => child_exit(&format!("failed to spawn slirp4netns: {}", e)),
        };
        // SAFETY: closing the child's ready fd in N; CLOEXEC was cleared via
        // pre_exec so it stays open across exec in slirp.
        unsafe { libc::close(ready_w) };

        if !wait_slirp_ready(ready_r) {
            if let Some(mut s) = slirp.take() {
                let _ = s.kill();
                let _ = s.wait();
            }
            child_exit("slirp4netns failed to configure the network (see its output above)");
        }
        // SAFETY: closing a valid fd.
        unsafe { libc::close(ready_r) };

        // Step 6: tell U the network is up.
        // SAFETY: writing to and closing valid pipe fds.
        unsafe {
            libc::write(netready_write, b"x".as_ptr() as *const libc::c_void, 1);
            libc::close(netready_write);
        }
    } else {
        unsafe {
            libc::close(netns_read);
            libc::close(netready_write);
        }
    }

    // Step 7: wait for U to report the agent's pid, then forward signals.
    let agent_pid = read_pid(apid_read);
    // SAFETY: closing a valid fd.
    unsafe { libc::close(apid_read) };
    if agent_pid <= 0 {
        child_exit("U failed to fork the agent");
    }
    AGENT_PID.store(agent_pid, Ordering::SeqCst);

    // Step 8: reap U, then stop slirp, exit with U's code.
    let code = wait_for_child(upid);
    if let Some(mut s) = slirp {
        // SAFETY: killing and waiting a child of N.
        unsafe {
            libc::kill(s.id() as libc::pid_t, libc::SIGTERM);
        }
        let _ = s.wait();
    }
    // SAFETY: _exit in a forked child.
    unsafe { libc::_exit(code) }
}

/// Spawn `den proxy` with the listener on fd 3. Returns its pid.
fn spawn_proxy() -> Result<libc::pid_t> {
    // Chain to the host's own proxy if one is set (e.g. a mitm wrapper).
    let host_proxy = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .find_map(|v| std::env::var(v).ok());
    if let Some(u) = host_proxy {
        std::env::set_var("DEN_PROXY_UPSTREAM", u);
    }

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let fd = listener.as_raw_fd();
    let port = listener.local_addr()?.port();
    let exe = std::env::current_exe().context("Failed to get den executable path")?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("proxy");
    if let Ok(upstream) = std::env::var("DEN_PROXY_UPSTREAM") {
        cmd.env("DEN_PROXY_UPSTREAM", upstream);
    }
    if let Ok(extra) = std::env::var("DEN_PROXY_ALLOW") {
        cmd.env("DEN_PROXY_ALLOW", extra);
    }
    // Pass the listener on fd 3 (dup2 clears CLOEXEC there).
    // SAFETY: pre_exec runs in the child before exec; dup2/fcntl are safe.
    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(fd, libc::F_SETFD, 0);
            libc::dup2(fd, 3);
            Ok(())
        });
    }
    let child = cmd.spawn().context("Failed to spawn proxy")?;

    // The sandbox reaches the proxy at 10.0.2.2 (slirp's host loopback alias).
    std::env::set_var("DEN_PROXY_URL", format!("http://10.0.2.2:{}", port));
    Ok(child.id() as libc::pid_t)
}

/// N: spawn slirp4netns to create+configure tap0 inside U's netns.
/// `ready_w` is slirp's --ready-fd: it writes a byte once the tap exists,
/// is configured, and the forwarder is live.
fn spawn_slirp(upid: libc::pid_t, ready_w: libc::c_int) -> Result<Child> {
    let userns_path = format!("/proc/{}/ns/user", upid);
    let netns_path = format!("/proc/{}/ns/net", upid);

    let mut cmd = std::process::Command::new("slirp4netns");
    cmd.args([
        "--configure",
        "--mtu=65520",
        "--userns-path",
        &userns_path,
        "--netns-type=path",
        &netns_path,
        "--ready-fd",
        &ready_w.to_string(),
        "tap0",
    ]);
    // SAFETY: pre_exec runs in the child before exec; fcntl is safe.
    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(ready_w, libc::F_SETFD, 0);
            Ok(())
        });
    }
    cmd.spawn().context("Failed to spawn slirp4netns")
}

/// Wait for slirp's ready byte (or slirp dying, or timeout).
fn wait_slirp_ready(ready_r: libc::c_int) -> bool {
    let mut fds = [libc::pollfd {
        fd: ready_r,
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: poll on a valid fd with a valid struct.
    let rc = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            1,
            SLIRP_READY_TIMEOUT.as_millis() as libc::c_int,
        )
    };
    if rc <= 0 {
        return false; // timeout or error
    }
    let mut buf = [0u8; 1];
    // SAFETY: reading into a valid buffer from a valid fd.
    unsafe { libc::read(ready_r, buf.as_mut_ptr() as *mut libc::c_void, 1) > 0 }
}

/// U: the deep sandbox. New mount/pid/ipc/uts/net namespaces, fresh tmpfs
/// trees (/tmp, /run, /var/tmp, /dev), nft egress policy (proxy mode), the
/// RO sweep, secret hides, then fork A (pid 1 of the pid ns) and reap it.
// Same as above: U's setup plumbing mirrors the fork/exec boundary.
#[allow(clippy::too_many_arguments)]
fn run_sandbox_child(
    cwd: &Path,
    fuse_mountpoint: &Path,
    allowed_paths: &[PathBuf],
    command: PathBuf,
    args: Vec<String>,
    session_id: &str,
    netns_write: libc::c_int,
    netready_read: libc::c_int,
    apid_write: libc::c_int,
    net: NetMode,
    resolv: Option<&Path>,
) -> ! {
    // U ignores termination signals: A (in the pid ns) receives group
    // signals directly, and A resets its own dispositions before exec.
    // SAFETY: sigaction with SIG_IGN.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = libc::SIG_IGN;
        for sig in [libc::SIGTERM, libc::SIGINT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    // Step 1: private network namespace (everything except full mode).
    // This is split from the other namespaces on purpose: the first fork
    // after unshare(CLONE_NEWPID) becomes pid 1 (init) of the sandbox pidns,
    // and if that init exits the pidns denies every later fork (ENOMEM). The
    // slirp4netns/nft subprocesses spawned below must therefore run in the
    // *host* pid namespace, and the agent must be the first fork after the
    // pidns exists.
    // SAFETY: unshare() with valid flags; error handled.
    if net != NetMode::Full {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            child_exit(&format!(
                "Failed to unshare network namespace: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Tell N the netns exists (it may spawn slirp now), then wait for
        // slirp to become ready and apply the egress policy. Only in proxy
        // mode: elsewhere N closes its end early, and writing would SIGPIPE
        // us, so skip the handshake entirely.
        if net == NetMode::Proxy {
            // SAFETY: writing to and closing valid pipe fds.
            unsafe {
                libc::write(netns_write, b"x".as_ptr() as *const libc::c_void, 1);
            }
            if !wait_for_pipe_signal(netready_read) {
                child_exit("network setup failed (slirp4netns did not become ready)");
            }
            if let Err(e) = apply_nft_rules() {
                child_exit(&format!("failed to apply nft egress rules: {}", e));
            }
        }
    }
    // SAFETY: closing a valid fd.
    unsafe { libc::close(netns_write) };

    // Step 2: mount/pid/ipc/uts namespaces. The agent is forked after this
    // point, so it becomes pid 1 of the new pid namespace.
    // SAFETY: unshare() with valid flags; error handled.
    if unsafe {
        libc::unshare(
            libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS,
        )
    } != 0
    {
        child_exit(&format!(
            "Failed to unshare namespaces: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 3: hostname + private mounts.
    let hn = CString::new("den").unwrap();
    // SAFETY: sethostname with a valid buffer.
    unsafe {
        libc::sethostname(hn.as_ptr() as *const libc::c_char, 3);
    }
    let root = CString::new("/").unwrap();
    // SAFETY: mount() with MS_PRIVATE on "/" only affects this namespace.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        child_exit(&format!(
            "Failed to make mounts private: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Resolve the resolv.conf target BEFORE /run is replaced by a tmpfs
    // (it usually canonicalizes into /run/systemd/resolve/...).
    let resolv_target = if resolv.is_some() {
        Some(
            fs::canonicalize("/etc/resolv.conf")
                .unwrap_or_else(|_| PathBuf::from("/etc/resolv.conf")),
        )
    } else {
        None
    };

    // Step 4: fresh tmpfs trees for /tmp, /var/tmp, /run (writes there are
    // invisible to the host). Skipped when they'd swallow the cwd itself.
    for (dir, mode) in [
        ("/tmp", "mode=1777"),
        ("/var/tmp", "mode=1777"),
        ("/run", "mode=755"),
    ] {
        if cwd == Path::new(dir) {
            continue;
        }
        let dir_cstr = CString::new(dir).unwrap();
        // SAFETY: mount tmpfs over an existing mountpoint.
        if unsafe {
            libc::mount(
                CString::new("tmpfs").unwrap().as_ptr(),
                dir_cstr.as_ptr(),
                CString::new("tmpfs").unwrap().as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                CString::new(mode).unwrap().as_ptr() as *const libc::c_void,
            )
        } != 0
        {
            child_exit(&format!(
                "Failed to mount tmpfs on {}: {}",
                dir,
                std::io::Error::last_os_error()
            ));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let _ = fs::create_dir_all(&xdg);
    }

    // Step 5: fresh /dev (mknod whitelist instead of the host's devices).
    setup_dev();

    // Step 6: the cwd may sit under a freshly-tmpfs'd tree; recreate it.
    if let Err(e) = fs::create_dir_all(cwd) {
        child_exit(&format!("Failed to recreate cwd {}: {}", cwd.display(), e));
    }

    // Step 7: override resolv.conf (proxy mode).
    if let (Some(src), Some(target)) = (resolv, &resolv_target) {
        if let Some(parent) = target.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }
        // The target usually lives under /run (e.g. systemd's
        // stub-resolv.conf), which step 4 just replaced with an empty
        // tmpfs: the parents were recreated above but the file itself is
        // gone, and bind-mounting onto a missing path fails with ENOENT.
        // Touch the path first without truncating it, but only when it
        // lives on one of the private tmpfs trees mounted in step 4
        // (/run, /tmp, /var/tmp): there the touch is invisible to the
        // host. Anything else (e.g. a regular /etc/resolv.conf on
        // non-systemd hosts, same filesystem and still writable here)
        // must already exist — never create it, just let the bind below
        // report the real error. If the touch fails the bind below
        // reports the real error.
        if !target.exists()
            && (target.starts_with("/run")
                || target.starts_with("/tmp")
                || target.starts_with("/var/tmp"))
        {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(target);
        }
        let src_cstr = path_to_cstring(src, "resolv.conf path");
        let dst_cstr = path_to_cstring(target, "resolv.conf target");
        // SAFETY: bind-mount a regular file onto the resolv.conf target.
        if unsafe {
            libc::mount(
                src_cstr.as_ptr(),
                dst_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            child_exit(&format!(
                "Failed to bind resolv.conf: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Step 8: bind-mount the FUSE overlay (from the temp dir) onto the cwd.
    let fuse_cstr = path_to_cstring(fuse_mountpoint, "FUSE mountpoint path");
    let cwd_cstr = path_to_cstring(cwd, "working directory path");
    // SAFETY: mount() with MS_BIND and valid paths.
    if unsafe {
        libc::mount(
            fuse_cstr.as_ptr(),
            cwd_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        child_exit(&format!(
            "Failed to bind mount FUSE overlay: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 9: chdir to cwd so we're using the overlay.
    if std::env::set_current_dir(cwd).is_err() {
        child_exit("Failed to change to working directory");
    }

    // Step 10: close the netready pipe (already consumed during the netns
    // setup in step 1; the read end must be closed before the agent is
    // forked so it cannot block on it).

    // Step 11: remount everything else read-only.
    if let Err(e) = remount_all_readonly_except(cwd, allowed_paths) {
        child_exit(&format!("Failed to remount filesystems read-only: {}", e));
    }

    // Step 12: hide secrets from the agent.
    apply_hides(cwd);

    // Step 13: fork the agent (pid 1 of the pid namespace).
    if std::env::var("DEN_SANDBOX_DEBUG").is_ok() {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if line.starts_with("VmSize")
                    || line.starts_with("VmRSS")
                    || line.starts_with("VmData")
                {
                    eprintln!("sandbox-U: {}", line);
                }
            }
        }
        eprintln!(
            "sandbox-U: map count = {}",
            std::fs::read_to_string("/proc/self/maps")
                .map(|m| m.lines().count())
                .unwrap_or(0)
        );
    }
    // SAFETY: fork() in a single-threaded child.
    let apid = unsafe { libc::fork() };
    if apid < 0 {
        child_exit(&format!(
            "Failed to fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if apid == 0 {
        run_agent(command, args, session_id);
    }

    // Step 14: report A's pid to N (signal forwarding), then reap A.
    // SAFETY: writing to and closing valid pipe fds.
    unsafe {
        libc::write(
            apid_write,
            &apid.to_le_bytes() as *const [u8; 4] as *const libc::c_void,
            4,
        );
        libc::close(apid_write);
    }
    let code = wait_for_child(apid);
    // SAFETY: _exit in a forked child.
    unsafe { libc::_exit(code) }
}

/// A: pid 1 of the sandbox pid ns. Reset signal dispositions, remount /proc
/// (its own pid-ns view), apply rlimits, no_new_privs, seccomp, exec.
/// A: pid 1 of the sandbox pid ns — a tiny init/reaper. The kernel marks
/// pidns init SIGNAL_UNKILLABLE: it only receives signals it *catches*
/// (signal.c: sig_task_ignored), so the init installs INT/TERM/USR1
/// handlers and forwards them to the agent (its child). The first
/// INT/TERM forwards as-is; SIGUSR1 (escalation from N) or a second
/// signal SIGKILLs the agent.
fn run_agent(command: PathBuf, args: Vec<String>, session_id: &str) -> ! {
    static INIT_AGENT_PID: AtomicI32 = AtomicI32::new(0);
    static INIT_SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);
    extern "C" fn init_forward(sig: libc::c_int) {
        let pid = INIT_AGENT_PID.load(Ordering::SeqCst);
        if pid > 0 {
            let count = INIT_SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
            // SAFETY: kill() is async-signal-safe.
            unsafe {
                if sig == libc::SIGUSR1 || count > 0 {
                    libc::kill(pid, libc::SIGKILL);
                } else {
                    libc::kill(pid, sig);
                }
            }
        }
    }
    // U ignored INT/TERM; SIG_IGN survives fork, so install fresh handlers.
    install_handler(libc::SIGTERM, init_forward);
    install_handler(libc::SIGINT, init_forward);
    install_handler(libc::SIGUSR1, init_forward);

    // SAFETY: fork() in a single-threaded child.
    let apid = unsafe { libc::fork() };
    if apid < 0 {
        child_exit(&format!(
            "Failed to fork the agent: {}",
            std::io::Error::last_os_error()
        ));
    }
    if apid == 0 {
        run_agent_exec(command, args, session_id);
    }
    INIT_AGENT_PID.store(apid, Ordering::SeqCst);
    let code = wait_for_child(apid);
    // SAFETY: _exit in a forked child.
    unsafe { libc::_exit(code) }
}

/// The agent itself (pid 2 of the sandbox pid ns): reset signal
/// dispositions (caught handlers die on exec, but cover the setup window),
/// remount /proc, apply rlimits, no_new_privs, seccomp, exec.
fn run_agent_exec(command: PathBuf, args: Vec<String>, session_id: &str) -> ! {
    // The init's handlers were caught; exec resets caught handlers to DFL,
    // but reset now too so the seccomp/setup window is well-defined.
    // SAFETY: sigaction with SIG_DFL (0).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = libc::SIG_DFL;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    // Remount /proc: the inherited mount shows the HOST pid ns.
    // SAFETY: mount("proc", "/proc", ...) with valid C strings.
    let proc_cstr = CString::new("/proc").unwrap();
    let procfs_cstr = CString::new("proc").unwrap();
    if unsafe {
        libc::mount(
            procfs_cstr.as_ptr(),
            proc_cstr.as_ptr(),
            procfs_cstr.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } != 0
    {
        child_exit(&format!(
            "Failed to remount /proc: {}",
            std::io::Error::last_os_error()
        ));
    }

    apply_rlimits();

    // SAFETY: prctl with plain integer args.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        child_exit("Failed to set no_new_privs");
    }

    if std::env::var("DEN_SECCOMP").as_deref() != Ok("0") {
        if let Err(e) = install_seccomp() {
            child_exit(&format!("Failed to install seccomp filter: {}", e));
        }
    }

    exec_command(command, args, session_id);
}

/// Fresh /dev: tmpfs with host char devices bind-mounted in, host pts and
/// /dev/net/tun bind-mounted in, /dev/shm as tmpfs. Sources are opened BEFORE
/// the tmpfs shadows them (via /proc/self/fd).
fn setup_dev() {
    // Open the host char devices before the tmpfs mount on /dev hides them.
    // mknod in a user namespace is unreliable on newer kernels (the tmpfs
    // mount ends up nodev and the kernel rejects/creates regular files),
    // so bind-mounting the host devices is the robust path.
    let devices: &[(&str, u32, u32)] = &[
        ("/dev/null", 1, 3),
        ("/dev/zero", 1, 5),
        ("/dev/full", 1, 7),
        ("/dev/random", 1, 8),
        ("/dev/urandom", 1, 9),
        ("/dev/tty", 5, 0),
    ];
    let mut dev_fds: Vec<(&str, Option<fs::File>)> = Vec::new();
    for (path, major, minor) in devices {
        dev_fds.push((path, fs::File::open(path).ok()));
        let _ = (major, minor); // keep the original major/minor as documentation
    }
    let pts_fd = fs::File::open("/dev/pts").ok();
    let tun_fd = fs::File::open("/dev/net/tun").ok();
    // /dev/fuse lets a nested den (§7) mount its own session — without it
    // the inner FUSE daemon fails with ENODEV.
    let fuse_fd = fs::File::open("/dev/fuse").ok();

    // SAFETY: mount tmpfs over /dev.
    let dev_cstr = CString::new("/dev").unwrap();
    let tmpfs_cstr = CString::new("tmpfs").unwrap();
    if unsafe {
        libc::mount(
            tmpfs_cstr.as_ptr(),
            dev_cstr.as_ptr(),
            tmpfs_cstr.as_ptr(),
            libc::MS_NOSUID,
            CString::new("mode=755").unwrap().as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        child_exit(&format!(
            "Failed to mount tmpfs on /dev: {}",
            std::io::Error::last_os_error()
        ));
    }

    for dir in ["/dev/pts", "/dev/shm", "/dev/net"] {
        let _ = fs::create_dir_all(dir);
    }

    // Bind the host char devices in, through the pre-opened fds.
    for (path, fd) in &dev_fds {
        if let Some(f) = fd {
            bind_mount_fd(f.as_raw_fd(), path);
        }
    }
    // Bind the host's pts (terminal devices) in, through the pre-opened fd.
    if let Some(f) = &pts_fd {
        bind_mount_fd(f.as_raw_fd(), "/dev/pts");
    }
    // Same for /dev/net/tun if the host has it.
    if let Some(f) = &tun_fd {
        bind_mount_fd(f.as_raw_fd(), "/dev/net/tun");
    }
    // Same for /dev/fuse if the host has it (nested den mounts, §7).
    if let Some(f) = &fuse_fd {
        bind_mount_fd(f.as_raw_fd(), "/dev/fuse");
    }

    // /dev/shm as tmpfs.
    // SAFETY: mount tmpfs with mode data.
    let shm_cstr = CString::new("/dev/shm").unwrap();
    unsafe {
        libc::mount(
            tmpfs_cstr.as_ptr(),
            shm_cstr.as_ptr(),
            tmpfs_cstr.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            CString::new("mode=1777").unwrap().as_ptr() as *const libc::c_void,
        );
    }

    // Symlinks.
    let links: &[(&str, &str)] = &[
        ("/dev/ptmx", "/dev/pts/ptmx"),
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ];
    for (link, target) in links {
        // SAFETY: symlink with valid C strings.
        unsafe {
            libc::symlink(
                CString::new(*target).unwrap().as_ptr(),
                CString::new(*link).unwrap().as_ptr(),
            );
        }
    }
}

/// Bind-mount the file referenced by `fd` onto `dst`. The destination is a
/// regular file; the bind mount replaces it with the fd's underlying device.
fn bind_mount_fd(fd: libc::c_int, dst: &str) {
    let src = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let dst_cstr = CString::new(dst).unwrap();
    // Create a placeholder file so the bind mount has a target (without
    // truncating an existing file).
    if !Path::new(dst).exists() {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dst);
    }
    // SAFETY: bind-mount with valid fd path and destination path.
    unsafe {
        let _ = libc::mount(
            src.as_ptr(),
            dst_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        );
    }
}

/// nft egress policy (proxy mode): lo + DNS via 10.0.2.3 + TCP to 10.0.2.2
/// (the proxy) are allowed; everything else drops at the netns boundary.
fn apply_nft_rules() -> Result<()> {
    let rules = "table inet den {
  chain input { type filter hook input priority 0; policy drop; iifname \"lo\" accept; ct state established,related accept; }
  chain output { type filter hook output priority 0; policy drop; oifname \"lo\" accept; udp dport 53 ip daddr 10.0.2.3 accept; tcp dport 53 ip daddr 10.0.2.3 accept; ip daddr 10.0.2.2 accept; }
  chain forward { type filter hook forward priority 0; policy drop; }
}
";
    let path = format!("/tmp/den-nft-{}.rules", std::process::id());
    fs::write(&path, rules).context("Failed to write nft rules")?;
    let status = std::process::Command::new("nft")
        .arg("-f")
        .arg(&path)
        .status()
        .context("Failed to run nft")?;
    let _ = fs::remove_file(&path);
    if !status.success() {
        bail!("nft rejected the egress rules");
    }
    Ok(())
}

/// Hide secrets from the agent: dirs are shadowed by an empty tmpfs, files
/// by a /dev/null bind. Paths containing the cwd are skipped (they'd break
/// the overlay).
fn apply_hides(cwd: &Path) {
    for h in effective_hides() {
        if cwd.starts_with(&h) {
            eprintln!(
                "warning: not hiding {} (contains the working directory)",
                h.display()
            );
            continue;
        }
        hide_one(&h, cwd);
        hide_aliases(&h, cwd);
    }
}

/// Mount a tmpfs (dir) or /dev/null bind (file) over `target`.
fn hide_one(target: &Path, cwd: &Path) {
    if cwd.starts_with(target) {
        return;
    }
    let Ok(meta) = fs::metadata(target) else {
        return;
    };
    let t_cstr = match CString::new(target.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return,
    };
    // SAFETY: mount tmpfs (dirs) or bind /dev/null (files) onto the path.
    unsafe {
        if meta.is_dir() {
            libc::mount(
                CString::new("tmpfs").unwrap().as_ptr(),
                t_cstr.as_ptr(),
                CString::new("tmpfs").unwrap().as_ptr(),
                libc::MS_NOSUID,
                CString::new("mode=000,size=64k").unwrap().as_ptr() as *const libc::c_void,
            );
        } else {
            libc::mount(
                CString::new("/dev/null").unwrap().as_ptr(),
                t_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            );
        }
    }
}

/// Cover alias paths exposing the same files: the same (dev, ino) tree is
/// often reachable through several mountpoints (e.g. /var/home/user and
/// /home/user on btrfs subvol layouts). For every mountpoint whose root
/// matches an ancestor of `h`, hide `mountpoint/<rel>` too.
fn hide_aliases(h: &Path, cwd: &Path) {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return;
    };
    let mountpoints: Vec<PathBuf> = mounts
        .lines()
        .filter_map(|l| {
            // /proc/self/mounts: "dev mountpoint fstype ..." — field 2.
            let m = l.split_whitespace().nth(1)?;
            Some(PathBuf::from(unescape_mount_path(m)))
        })
        .collect();
    let mut anc = h.to_path_buf();
    loop {
        for m in &mountpoints {
            if *m == anc {
                continue; // same path — already hidden
            }
            let Ok(rel) = h.strip_prefix(&anc) else {
                continue;
            };
            if rel.as_os_str().is_empty() {
                continue;
            }
            let (Ok(ms), Ok(as_)) = (fs::metadata(m), fs::metadata(&anc)) else {
                continue;
            };
            use std::os::unix::fs::MetadataExt;
            if ms.dev() == as_.dev() && ms.ino() == as_.ino() {
                hide_one(&m.join(rel), cwd);
            }
        }
        match anc.parent() {
            Some(p) if p != anc => anc = p.to_path_buf(),
            _ => break,
        }
    }
}

/// Decode \040 / \011 / \012 / \134 escapes in /proc/self/mounts paths.
fn unescape_mount_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('0') if chars.clone().next() == Some('4') => {
                    chars.next();
                    out.push(' ');
                }
                Some('1') if chars.clone().next() == Some('1') => {
                    chars.next();
                    out.push('\t');
                }
                Some('1') if chars.clone().next() == Some('2') => {
                    chars.next();
                    out.push('\n');
                }
                Some('1') if chars.clone().next() == Some('3') => {
                    chars.next();
                    out.push('\\');
                }
                Some(other) => {
                    out.push(other);
                }
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The effective hide list: DEFAULT_HIDE + DEN_HIDE - DEN_NO_HIDE, resolved
/// against HOME ("~/x" or relative → HOME, absolute kept as-is).
fn effective_hides() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut hides: Vec<PathBuf> = Vec::new();
    let mut add = |p: &str| {
        let pb = if let Some(rest) = p.strip_prefix("~/") {
            Path::new(&home).join(rest)
        } else if p.starts_with('/') {
            PathBuf::from(p)
        } else if !home.is_empty() {
            Path::new(&home).join(p)
        } else {
            return;
        };
        if !hides.contains(&pb) {
            hides.push(pb);
        }
    };
    for d in DEFAULT_HIDE {
        add(d);
    }
    if let Ok(extra) = std::env::var("DEN_HIDE") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            add(p);
        }
    }
    if let Ok(no) = std::env::var("DEN_NO_HIDE") {
        for p in no.split(':').filter(|s| !s.is_empty()) {
            let pb = if let Some(rest) = p.strip_prefix("~/") {
                Path::new(&home).join(rest)
            } else if p.starts_with('/') {
                PathBuf::from(p)
            } else {
                Path::new(&home).join(p)
            };
            hides.retain(|h| h != &pb);
        }
    }
    hides
}

/// Spec-resolved XDG base dirs, in (var, dir) order. Shared by the writable
/// defaults (build_allowed_paths) and the child env pin (setup_env_vars) so
/// the agent writes exactly where den granted writes.
pub(crate) fn xdg_base_dirs() -> Vec<(&'static str, PathBuf)> {
    let home = std::env::var("HOME").unwrap_or_default();
    let base = Path::new(&home);
    XDG_BASES
        .iter()
        .map(|(var, sub)| {
            let dir = match std::env::var(var) {
                Ok(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
                _ => base.join(sub),
            };
            (*var, dir)
        })
        .collect()
}

/// Remount all filesystems read-only except the overlay and allowed paths.
///
/// Correct order: bind-mount each allowed path to itself (rw), lock it with
/// `rw,bind`, THEN remount everything else read-only — bind mounts established
/// before the ro remount retain their own mount options.
fn remount_all_readonly_except(
    writable_path: &Path,
    allowed_paths: &[PathBuf],
) -> std::io::Result<()> {
    // Step 1: bind-mount allowed paths to themselves FIRST (independent
    // mountpoints that survive the ro remount).
    for allowed in allowed_paths {
        let path_cstr = match CString::new(allowed.as_os_str().as_bytes()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // SAFETY: mount() with valid paths.
        let bind_result = unsafe {
            libc::mount(
                path_cstr.as_ptr(),
                path_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if bind_result == 0 {
            // SAFETY: mount() with valid path.
            let _ = unsafe {
                libc::mount(
                    std::ptr::null(),
                    path_cstr.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT,
                    std::ptr::null(),
                )
            };
        }
    }

    // Step 2: remount everything else read-only.
    let mountinfo = std::fs::File::open("/proc/self/mountinfo")?;
    let reader = std::io::BufReader::new(mountinfo);

    let mut mounts: Vec<PathBuf> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > MOUNTINFO_MOUNT_POINT_FIELD {
            let mount_point = unescape_mountinfo(fields[MOUNTINFO_MOUNT_POINT_FIELD]);
            mounts.push(PathBuf::from(mount_point));
        }
    }

    // Sort longest-first so nested mounts are handled correctly.
    mounts.sort_by_key(|b| Reverse(b.as_os_str().len()));

    let writable_canonical = writable_path
        .canonicalize()
        .unwrap_or_else(|_| writable_path.to_path_buf());

    let allowed_canonical: Vec<PathBuf> = allowed_paths
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect();

    for mount_point in &mounts {
        let mount_canonical = mount_point
            .canonicalize()
            .unwrap_or_else(|_| mount_point.clone());

        if mount_canonical == writable_canonical {
            continue;
        }
        if allowed_canonical.contains(&mount_canonical) {
            continue;
        }
        if skip_mount(mount_point) {
            continue;
        }

        let mount_cstr = match CString::new(mount_point.as_os_str().as_bytes()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Bind mount on itself to create a distinct mountpoint.
        // SAFETY: mount() with valid CString path; failures are expected and skipped.
        let bind_result = unsafe {
            libc::mount(
                mount_cstr.as_ptr(),
                mount_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if bind_result != 0 {
            continue;
        }

        // Remount the bind mount read-only (failures silently ignored — some
        // filesystems can't be remounted).
        // SAFETY: mount() with valid path.
        let _ = unsafe {
            libc::mount(
                std::ptr::null(),
                mount_cstr.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                std::ptr::null(),
            )
        };
    }

    Ok(())
}

/// Should this mount point be skipped during the read-only remount?
fn skip_mount(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    SKIP_MOUNT_PREFIXES
        .iter()
        .any(|prefix| path_str.starts_with(prefix))
}

/// Default allowed dirs under HOME + user-specified paths (canonicalized).
fn build_allowed_paths(user_allowed: &[String]) -> Result<Vec<PathBuf>> {
    let mut allowed = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        for dir in DEFAULT_ALLOWED_DIRS {
            let path = Path::new(&home).join(dir);
            if path.exists() {
                allowed.push(path);
            }
        }
    }

    // XDG base dirs (spec-resolved, created if missing): an XDG-following
    // agent persists config/state/logs/caches here with zero extra flags.
    // Relative resolutions (empty HOME) are skipped — never mkdir in the cwd.
    for (_, dir) in xdg_base_dirs() {
        if dir.is_relative() {
            continue;
        }
        if !dir.exists() {
            let _ = std::fs::create_dir_all(&dir);
        }
        if dir.exists() && !allowed.contains(&dir) {
            allowed.push(dir);
        }
    }

    for path in user_allowed {
        let canonical = Path::new(path).canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize allowed path '{}'. Does it exist?",
                path
            )
        })?;
        allowed.push(canonical);
    }

    Ok(allowed)
}

/// Unescape a mount point from mountinfo (spaces are \040, tabs \011, etc.).
fn unescape_mountinfo(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut octal = String::new();
            for _ in 0..3 {
                if let Some(&next) = chars.peek() {
                    if ('0'..='7').contains(&next) {
                        octal.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
            }
            if octal.len() == 3 {
                if let Ok(code) = u32::from_str_radix(&octal, 8) {
                    if code <= 255 {
                        result.push(code as u8 as char);
                        continue;
                    }
                }
            }
            result.push(c);
            result.push_str(&octal);
        } else {
            result.push(c);
        }
    }

    result
}

/// Exec the command, replacing the current process.
fn exec_command(command: PathBuf, args: Vec<String>, session_id: &str) -> ! {
    setup_env_vars(session_id);

    let cmd_cstr = match CString::new(command.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            child_exit_with_code(
                &format!("Invalid command (contains NUL byte): {}", command.display()),
                EXIT_COMMAND_NOT_FOUND,
            );
        }
    };

    let mut argv: Vec<CString> = vec![cmd_cstr.clone()];
    for arg in &args {
        match CString::new(arg.as_str()) {
            Ok(s) => argv.push(s),
            Err(_) => {
                child_exit_with_code(
                    &format!("Invalid argument (contains NUL byte): {}", arg),
                    EXIT_COMMAND_NOT_FOUND,
                );
            }
        }
    }

    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // SAFETY: argv_ptrs is a valid NUL-terminated argv for cmd_cstr.
    unsafe {
        libc::execvp(cmd_cstr.as_ptr(), argv_ptrs.as_ptr());
    }

    child_exit_with_code(
        &format!(
            "Failed to execute {}: {}",
            command.display(),
            std::io::Error::last_os_error()
        ),
        EXIT_COMMAND_NOT_FOUND,
    );
}

/// Environment variables for the sandboxed process.
fn setup_env_vars(session_id: &str) {
    std::env::set_var("AGENTFS", "1");
    std::env::set_var("AGENTFS_SANDBOX", "linux-namespace");
    std::env::set_var("AGENTFS_SESSION", session_id);

    // Pin the XDG base dirs to the absolute paths den granted writable
    // (build_allowed_paths): with a read-only `/`, a missing or relative
    // value would resolve inside the sandbox cwd and any agent state the
    // child writes there would pollute the session delta.
    for (var, dir) in xdg_base_dirs().iter().filter(|(_, d)| d.is_absolute()) {
        std::env::set_var(var, dir);
    }

    // Nested runs (§7): a subagent's den inherits this session's pinned
    // base DB (host path — readable, never written inside the sandbox).
    if let Ok(Some(base)) = crate::session_base_db(session_id) {
        std::env::set_var("DEN_BASE_DB", base.to_string_lossy().to_string());
    }
    std::env::set_var("PS1", "🤖 \\u@\\h:\\w\\$ ");

    // DEN_PROXY_UPSTREAM holds the host's own proxy URL (possibly with
    // credentials) — the den proxy's secret, not the agent's. The proxy
    // child gets it explicitly via env in spawn_proxy, so drop it here.
    std::env::remove_var("DEN_PROXY_UPSTREAM");

    // Proxy mode: route everything through the sandbox proxy at 10.0.2.2
    // (DEN_PROXY_URL is set by M before the fork; inherited down the chain).
    if let Ok(proxy_url) = std::env::var("DEN_PROXY_URL") {
        for v in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            std::env::remove_var(v);
        }
        for v in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            std::env::set_var(v, &proxy_url);
        }
        // Loopback stays direct: dex-style CLI→daemon health checks on
        // 127.0.0.1 must hit the sandbox's own loopback, not the egress
        // proxy (which would dial the *host's* loopback and prompt).
        std::env::set_var("NO_PROXY", "localhost,127.0.0.1,::1");
        std::env::set_var("no_proxy", "localhost,127.0.0.1,::1");
    }

    // Configure SSH to skip system config files: inside the user namespace,
    // root-owned files in /etc/ssh/ssh_config.d/ appear with unmapped uid,
    // causing ssh to reject them. If ~/.ssh is hidden (default), this also
    // falls back to /dev/null, keeping ssh from reading hidden keys.
    if let Ok(home) = std::env::var("HOME") {
        let user_ssh_config = Path::new(&home).join(".ssh/config");
        let config_path = if user_ssh_config.exists() {
            user_ssh_config.to_string_lossy().to_string()
        } else {
            "/dev/null".to_string()
        };
        std::env::set_var("GIT_SSH_COMMAND", format!("ssh -F {}", config_path));
    }
}

/// Wait for the child to exit, retrying on EINTR. Returns its exit code.
fn wait_for_child(child_pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid with a valid child pid.
        let result = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return 1;
        }
        break;
    }
    wait_status_to_exit_code(status)
}

/// Extract the exit code from a wait status.
fn wait_status_to_exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// A sandbox run session: fs.db path, FUSE mountpoint, base-path marker.
struct RunSession {
    db_path: PathBuf,
    fuse_mountpoint: PathBuf,
    base_path_file: PathBuf,
}

/// Create the run directory (~/.den/sessions/<sid>) with fs.db, mountpoint
/// and base-path marker.
fn setup_run_directory(session_id: &str) -> Result<RunSession> {
    let run_dir = run_dir()?;
    let run_dir = run_dir.join(session_id);
    fs::create_dir_all(&run_dir).context("Failed to create run directory")?;

    let db_path = run_dir.join("fs.db");
    let fuse_mountpoint = run_dir.join("mnt");
    let base_path_file = run_dir.join("base_path");
    fs::create_dir_all(&fuse_mountpoint).context("Failed to create FUSE mountpoint")?;

    Ok(RunSession {
        db_path,
        fuse_mountpoint,
        base_path_file,
    })
}

/// Create a pair of pipes for parent-child sync. Returns (child_pipe, parent_pipe),
/// each [read_fd, write_fd].
fn create_sync_pipes() -> Result<([libc::c_int; 2], [libc::c_int; 2])> {
    let mut child_pipe: [libc::c_int; 2] = [0; 2];
    let mut parent_pipe: [libc::c_int; 2] = [0; 2];

    if unsafe { libc::pipe(child_pipe.as_mut_ptr()) } != 0 {
        bail!("Failed to create pipe: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::pipe(parent_pipe.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(child_pipe[0]);
            libc::close(child_pipe[1]);
        }
        bail!("Failed to create pipe: {}", std::io::Error::last_os_error());
    }
    Ok((child_pipe, parent_pipe))
}

/// Create a plain pipe; returns [read_fd, write_fd].
fn pipe2() -> [libc::c_int; 2] {
    let mut fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        eprintln!("Failed to create pipe: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    fds
}

/// Wait for a single-byte sync signal on a pipe. True if received.
fn wait_for_pipe_signal(fd: libc::c_int) -> bool {
    let mut buf = [0u8; 1];
    // SAFETY: reading into a valid buffer from a valid fd.
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) > 0 }
}

/// Read a 4-byte little-endian pid from a pipe. 0 if the pipe closed.
fn read_pid(fd: libc::c_int) -> libc::pid_t {
    let mut buf = [0u8; 4];
    // SAFETY: reading into a valid buffer from a valid fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 4) };
    if n == 4 {
        libc::pid_t::from_le_bytes(buf)
    } else {
        0
    }
}

/// Abort child coordination and exit with failure.
fn abort_child(pipe_write_fd: libc::c_int, child_pid: libc::pid_t) -> ! {
    // SAFETY: closing a valid fd and waiting for a valid child pid.
    unsafe {
        libc::close(pipe_write_fd);
        let mut status: libc::c_int = 0;
        libc::waitpid(child_pid, &mut status, 0);
    }
    std::process::exit(1)
}

/// Write uid_map, gid_map, and setgroups for the child's user namespace.
/// Maps "0 <host-uid> 1": in-ns root keeps its caps across exec (the
/// standard rootless-sandbox pattern). Aborts the child on failure.
fn write_namespace_mappings(
    child_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    pipe_write_fd: libc::c_int,
) {
    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    let gid_map_path = format!("/proc/{}/gid_map", child_pid);
    let setgroups_path = format!("/proc/{}/setgroups", child_pid);

    if let Err(e) = fs::write(&uid_map_path, format!("0 {} 1\n", uid)) {
        eprintln!("Error: Could not write uid_map: {}", e);
        eprintln!("This may indicate missing unprivileged user namespace support.");
        abort_child(pipe_write_fd, child_pid);
    }
    if let Err(e) = fs::write(&setgroups_path, "deny") {
        eprintln!("Error: Could not write setgroups: {}", e);
        abort_child(pipe_write_fd, child_pid);
    }
    if let Err(e) = fs::write(&gid_map_path, format!("0 {} 1\n", gid)) {
        eprintln!("Error: Could not write gid_map: {}", e);
        abort_child(pipe_write_fd, child_pid);
    }
}

/// Convert a path to a CString, exiting the child on failure.
fn path_to_cstring(path: &Path, description: &str) -> CString {
    match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "Invalid {} (contains NUL byte): {}",
                description,
                path.display()
            );
            // SAFETY: in a forked child, _exit avoids atexit handlers and
            // stdio flushing that belong to the parent.
            unsafe { libc::_exit(1) }
        }
    }
}

/// Exit the child with an error message; _exit skips parent atexit handlers.
fn child_exit_with_code(msg: &str, code: i32) -> ! {
    eprintln!("{}", msg);
    // SAFETY: in a forked child, _exit() is the correct way to terminate.
    unsafe { libc::_exit(code) }
}

fn child_exit(msg: &str) -> ! {
    child_exit_with_code(msg, 1)
}

// ---------------------------------------------------------------------------
// rlimits (DEN_LIMIT_*)
// ---------------------------------------------------------------------------

/// What a DEN_LIMIT_* env var says.
enum Lim {
    Unset,
    Unlimited,
    Bytes(u64),
}

/// Parse "1234", "512M", "2G", "unlimited" (case-insensitive).
fn parse_limit(name: &str) -> Lim {
    let Ok(v) = std::env::var(name) else {
        return Lim::Unset;
    };
    let v = v.trim().to_ascii_lowercase();
    if v == "unlimited" || v == "inf" {
        return Lim::Unlimited;
    }
    let (num, mult) = match v.as_bytes().last() {
        Some(b'k') => (&v[..v.len() - 1], 1u64 << 10),
        Some(b'm') => (&v[..v.len() - 1], 1u64 << 20),
        Some(b'g') => (&v[..v.len() - 1], 1u64 << 30),
        _ => (v.as_str(), 1),
    };
    match num.trim().parse::<u64>() {
        Ok(n) => Lim::Bytes(n.saturating_mul(mult)),
        Err(_) => {
            eprintln!("warning: ignoring invalid {}", name);
            Lim::Unset
        }
    }
}

/// Resolve a DEN_LIMIT_* var: default when unset, None for "unlimited"
/// (leave the inherited limit alone).
fn lim_value(name: &str, default: u64) -> Option<u64> {
    match parse_limit(name) {
        Lim::Unset => Some(default),
        Lim::Unlimited => None,
        Lim::Bytes(n) => Some(n),
    }
}

/// Apply rlimits to the agent: hard defaults (core 0, fsize 8G, nofile 4096,
/// nproc 1024) overridable via DEN_LIMIT_FSIZE / _NOFILE / _NPROC / _AS /
/// _CPU ("unlimited" or K/M/G suffixed values).
fn apply_rlimits() {
    // SAFETY: setrlimit with a valid struct.
    unsafe {
        // core dumps: never (they'd leak sandbox memory to disk).
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &core);

        let apply = |res: libc::__rlimit_resource_t, v: Option<u64>| {
            if let Some(v) = v {
                let rl = libc::rlimit {
                    rlim_cur: v,
                    rlim_max: v,
                };
                libc::setrlimit(res, &rl);
            }
        };
        apply(libc::RLIMIT_FSIZE, lim_value("DEN_LIMIT_FSIZE", 8u64 << 30));
        apply(
            libc::RLIMIT_NOFILE,
            lim_value("DEN_LIMIT_NOFILE", 4096).map(|v| v.min(1048576)),
        );
        apply(
            libc::RLIMIT_NPROC,
            lim_value("DEN_LIMIT_NPROC", 1024).map(|v| v.min(1048576)),
        );
        // AS/CPU: only when explicitly set (default: inherited, i.e. unlimited).
        if let Lim::Bytes(n) = parse_limit("DEN_LIMIT_AS") {
            let rl = libc::rlimit {
                rlim_cur: n,
                rlim_max: n,
            };
            libc::setrlimit(libc::RLIMIT_AS, &rl);
        }
        if let Lim::Bytes(n) = parse_limit("DEN_LIMIT_CPU") {
            let rl = libc::rlimit {
                rlim_cur: n,
                rlim_max: n,
            };
            libc::setrlimit(libc::RLIMIT_CPU, &rl);
        }
    }
}

// ---------------------------------------------------------------------------
// seccomp (DEN_SECCOMP=0 disables)
// ---------------------------------------------------------------------------

/// Install a deny-list seccomp filter (x86_64): namespace/init-syscall
/// escapes (mount, unshare, setns, ...) plus raw sockets (AF_NETLINK,
/// AF_PACKET). Everything else is allowed. Requires no_new_privs (set by the
/// caller).
#[cfg(target_arch = "x86_64")]
fn install_seccomp() -> Result<()> {
    use libc::{sock_filter, sock_fprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};

    const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    /// x86_64 syscall numbers denied outright:
    /// mount/umount2, ptrace, process_vm_*, bpf, perf_event_open, keyctl,
    /// kexec/reboot/swap, module syscalls, setns/unshare, sethostname/
    /// setdomainname, pivot_root/chroot, iopl/ioperm, name_to_handle_at/
    /// open_by_handle_at, the new mount API (open_tree ... mount_setattr),
    /// userfaultfd, kcmp, process_madvise, process_mrelease, socket (below).
    const DENY: &[i64] = &[
        165, 166, 101, 310, 311, 321, 298, 250, 248, 249, 246, 320, 169, 167, 168, 175, 313, 176,
        308, 272, 170, 171, 155, 161, 172, 173, 304, 303, 428, 429, 430, 431, 432, 433, 442, 323,
        312, 440, 448,
    ];

    let mut ins: Vec<sock_filter> = Vec::new();
    let mut emit = |code: u16, jt: u8, jf: u8, k: u32| {
        ins.push(sock_filter { code, jt, jf, k });
    };

    // 0: load arch
    emit((BPF_LD | BPF_W | BPF_ABS) as u16, 0, 0, 4);
    // 1: arch match → skip the ENOSYS ret; mismatch → ENOSYS
    emit((BPF_JMP | BPF_JEQ | BPF_K) as u16, 1, 0, AUDIT_ARCH_X86_64);
    emit(
        (BPF_RET | BPF_K) as u16,
        0,
        0,
        SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
    );
    // 3: load syscall nr
    emit((BPF_LD | BPF_W | BPF_ABS) as u16, 0, 0, 0);

    // Deny chain: JEQ nr → deny, else next. Layout:
    //   0 LD arch, 1 JEQ arch, 2 RET ENOSYS, 3 LD nr,
    //   4..4+n jeq per deny nr,
    //   socket block: jeq 41 → LD args[0] → jeq 16 (netlink) → jeq 17 (packet),
    //   RET EPERM (deny), RET ALLOW.
    let n = DENY.len();
    let socket_jeq = 4 + n; // falls through to the args load
    let deny_ret = socket_jeq + 4; // jeq + LD + 2 family jeqs
    let allow_ret = deny_ret + 1;
    for (i, &nr) in DENY.iter().enumerate() {
        emit(
            (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            (deny_ret - (4 + i) - 1) as u8,
            0,
            nr as u32,
        );
    }
    // socket: only AF_NETLINK (16) and AF_PACKET (17) are denied; anything
    // else (including non-socket syscalls) jumps straight to ALLOW.
    emit(
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        0,
        (allow_ret - socket_jeq - 1) as u8,
        41, // socket
    );
    emit((BPF_LD | BPF_W | BPF_ABS) as u16, 0, 0, 16); // args[0] (domain)
    emit(
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        (deny_ret - (socket_jeq + 2) - 1) as u8,
        0,
        16, // AF_NETLINK
    );
    emit(
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        (deny_ret - (socket_jeq + 3) - 1) as u8,
        (allow_ret - (socket_jeq + 3) - 1) as u8,
        17, // AF_PACKET: match → deny, else → allow
    );

    // deny / allow terminators
    emit(
        (BPF_RET | BPF_K) as u16,
        0,
        0,
        SECCOMP_RET_ERRNO | libc::EPERM as u32,
    );
    emit((BPF_RET | BPF_K) as u16, 0, 0, SECCOMP_RET_ALLOW);

    let mut prog = sock_fprog {
        len: ins.len() as u16,
        filter: ins.as_mut_ptr(),
    };

    // SAFETY: prctl with a valid sock_fprog; the filter array lives in `ins`
    // for the whole call.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut prog,
            0,
            0,
        )
    } != 0
    {
        bail!(
            "prctl(PR_SET_SECCOMP) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn install_seccomp() -> Result<()> {
    eprintln!("warning: seccomp deny-list not implemented for this architecture");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::tests::HOME_LOCK;

    /// Env vars swapped below (HOME + XDG_* are process-global).
    const SWAPPED_ENV: &[&str] = &[
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
    ];

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("den-xdg-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn build_allowed_paths_defaults_to_xdg_base_dirs() {
        // HOME/XDG are process-global: serialize with the backup tests that
        // swap HOME too, and restore everything so later tests are unaffected.
        let _g = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved: Vec<(&str, Option<std::ffi::OsString>)> = SWAPPED_ENV
            .iter()
            .map(|v| (*v, std::env::var_os(v)))
            .collect();
        for v in SWAPPED_ENV {
            std::env::remove_var(v);
        }
        let home = temp_dir("home");
        std::env::set_var("HOME", &home);
        // fallback defaults are created and granted…
        let allows = build_allowed_paths(&[]).unwrap();
        for d in [".config", ".local/share", ".local/state", ".cache"] {
            assert!(allows.contains(&home.join(d)), "missing {d}");
        }
        // …an absolute XDG override wins…
        let cfg = temp_dir("cfg");
        std::env::set_var("XDG_CONFIG_HOME", &cfg);
        let allows = build_allowed_paths(&[]).unwrap();
        assert!(allows.contains(&cfg));
        assert!(!allows.contains(&home.join(".config")));
        // …and a relative XDG value falls back to the default subdir.
        std::env::set_var("XDG_CACHE_HOME", "relative/path");
        let allows = build_allowed_paths(&[]).unwrap();
        assert!(allows.contains(&home.join(".cache")));
        for (v, val) in saved {
            match val {
                Some(x) => std::env::set_var(v, x),
                None => std::env::remove_var(v),
            }
        }
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&cfg);
    }
}
