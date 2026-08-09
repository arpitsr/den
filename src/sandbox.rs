//! Overlay sandbox using FUSE and Linux namespaces — ported from the agentfs
//! CLI (`cli/src/sandbox/linux.rs`, MIT) so pit no longer shells out to it.
//!
//! The current working directory becomes a copy-on-write overlay: a FUSE
//! filesystem is mounted on a hidden temp dir (~/.agentfs/run/<sid>/mnt),
//! then a child with its own user+mount namespace bind-mounts that overlay
//! onto the cwd. Everything else is remounted read-only except an allowlist.
//! All writes land in the session's SQLite delta DB (~/.agentfs/run/<sid>/delta.db),
//! which the SDK then reads back (diff, whiteouts, tool timeline).
//!
//! To avoid a circular reference (FUSE serving from a directory it's mounted
//! on), we open a file descriptor to the cwd before mounting; HostFS accesses
//! the base layer through /proc/self/fd/N, bypassing the FUSE mount.
//!
//! The FUSE mount at ~/.agentfs/run/<sid>/mnt lives in *this* process's
//! namespace, so a second `pit` invocation with the same sid joins it —
//! multiple terminals share one session's delta layer.

use crate::mount::{mount_fs, MountOpts};
use crate::run_dir;
use agentfs_sdk::{AgentFS, AgentFSOptions, HostFS, OverlayFS};
use anyhow::{bail, Context, Result};
use std::cmp::Reverse;
use std::ffi::CString;
use std::fs;
use std::io::BufRead;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

/// Global child PID for signal forwarding (set by the parent).
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// First termination signal forwards to child; the second sends SIGKILL.
static TERM_SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// Exit code when exec fails (shell convention for "command not found").
const EXIT_COMMAND_NOT_FOUND: i32 = 127;

/// Timeout for waiting for the FUSE mount to become ready.
const FUSE_MOUNT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Virtual filesystems that must remain writable for system operation.
const SKIP_MOUNT_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/tmp"];

/// Default directories allowed to be writable (common agent config/cache dirs).
const DEFAULT_ALLOWED_DIRS: &[&str] = &[
    ".amp",         // Amp config
    ".cache",       // XDG cache directory (corepack, pip, etc.)
    ".claude",      // Claude Code config
    ".claude.json", // Claude Code config file
    ".codex",       // OpenAI Codex config
    ".gemini",      // Gemini CLI config
    ".local",       // Local data directory
    ".npm",         // npm local registry
];

/// Field index for mount point in /proc/self/mountinfo.
/// Format: ID PARENT_ID MAJOR:MINOR ROOT MOUNT_POINT OPTIONS ...
const MOUNTINFO_MOUNT_POINT_FIELD: usize = 4;

/// Signal handler forwarding termination signals to the sandboxed child.
///
/// SAFETY: async-signal-safe only (kill + atomics).
extern "C" fn forward_signal_to_child(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        let count = TERM_SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        // SAFETY: kill() is async-signal-safe
        unsafe {
            if count == 0 {
                libc::kill(pid, sig); // graceful first
            } else {
                libc::kill(pid, libc::SIGKILL); // second signal: force
            }
        }
    }
}

/// Install SIGTERM/SIGINT handlers that forward to the sandboxed child.
fn install_signal_handlers() {
    TERM_SIGNAL_COUNT.store(0, Ordering::SeqCst);
    // SAFETY: sigaction with a valid struct and async-signal-safe handler.
    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGTERM);
        libc::sigaddset(&mut sigset, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &sigset, std::ptr::null_mut());

        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = forward_signal_to_child as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;

        for sig in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                eprintln!("warning: failed to install signal handler: {}", std::io::Error::last_os_error());
            }
        }
    }
}

/// One sandboxed run: mount the overlay (or join the existing session), fork
/// a child in a fresh user+mount namespace with the rest of the FS read-only,
/// exec `command`, then clean up and return its exit code.
pub async fn run_cmd(
    allow: Vec<String>,
    session_id: String,
    command: PathBuf,
    args: Vec<String>,
) -> Result<i32> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    if std::env::var("PIT_SANDBOX_DEBUG").is_ok() {
        eprintln!("sandbox: cwd={} sid={}", cwd.display(), session_id);
    }
    let allowed_paths = build_allowed_paths(&allow)?;

    let session = setup_run_directory(&session_id)?;

    // Same layout as agentfs: if the FUSE mountpoint is already mounted, join
    // the running session instead of starting a second overlay.
    if crate::mount::is_mountpoint(&session.fuse_mountpoint) {
        if std::env::var("PIT_SANDBOX_DEBUG").is_ok() {
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

    // Open the cwd BEFORE mounting FUSE on top of it. This fd lets HostFS
    // access the underlying directory through /proc/self/fd/N, bypassing the
    // FUSE mount that will be placed on top.
    let cwd_fd = fs::File::open(&cwd).context("Failed to open current directory")?;
    let fd_num = cwd_fd.as_raw_fd();
    let fd_path = format!("/proc/self/fd/{}", fd_num);

    let db_path_str = session
        .db_path
        .to_str()
        .context("Database path contains non-UTF8 characters")?;
    let agentfs = AgentFS::open(AgentFSOptions::with_path(db_path_str.to_string()))
        .await
        .context("Failed to create delta AgentFS")?;

    let hostfs = HostFS::new(&fd_path).context("Failed to create HostFS")?;
    let mountpoint_inode = fs::metadata(&session.fuse_mountpoint)
        .map(|m| m.ino())
        .context("Failed to get mountpoint inode")?;
    let hostfs = hostfs.with_fuse_mountpoint(mountpoint_inode);

    let base = std::sync::Arc::new(hostfs);
    let overlay = OverlayFS::new(base, agentfs.fs);

    let cwd_str = cwd
        .to_str()
        .context("Current directory path contains non-UTF8 characters")?;
    overlay
        .init(cwd_str)
        .await
        .context("Failed to initialize overlay")?;

    // Write the base path for session joining
    fs::write(&session.base_path_file, cwd_str).context("Failed to write session base path")?;

    // SAFETY: getuid/getgid are always safe
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mount_opts = MountOpts {
        mountpoint: session.fuse_mountpoint.clone(),
        fsname: format!("agentfs:{}", session_id),
        allow_other: false,
        allow_root: false,
        auto_unmount: false,
        lazy_unmount: true,
        timeout: FUSE_MOUNT_TIMEOUT,
    };

    let mount_handle = mount_fs(std::sync::Arc::new(tokio::sync::Mutex::new(overlay)), mount_opts).await?;

    // Pipes for parent-child coordination: the parent writes uid_map/gid_map
    // for the child after it unshares.
    let (pipe_to_child, pipe_to_parent) = create_sync_pipes()?;

    // SAFETY: fork() from a single-threaded context; the child closes unused
    // fds and execs after namespace setup without touching async state.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        bail!("Failed to fork: {}", std::io::Error::last_os_error());
    }

    if child_pid == 0 {
        // SAFETY: closing our ends of the pipes; fds are valid from pipe().
        unsafe {
            libc::close(pipe_to_child[1]);
            libc::close(pipe_to_parent[0]);
        }
        drop(cwd_fd); // parent keeps it for the FUSE thread
        run_child(
            &cwd,
            &session.fuse_mountpoint,
            &allowed_paths,
            command,
            args,
            &session_id,
            pipe_to_child[0],
            pipe_to_parent[1],
        );
    }

    // SAFETY: closing the parent's pipe ends.
    unsafe {
        libc::close(pipe_to_child[0]);
        libc::close(pipe_to_parent[1]);
    }

    // Wait for the child to signal that it has called unshare.
    if !wait_for_pipe_signal(pipe_to_parent[0]) {
        eprintln!("Error: Failed to read sync signal from child process");
        abort_child(pipe_to_child[1], child_pid);
    }

    write_namespace_mappings(child_pid, uid, gid, pipe_to_child[1]);

    // Signal the child that mappings are done.
    // SAFETY: writing to and closing valid pipe fds.
    unsafe {
        libc::write(pipe_to_child[1], b"x".as_ptr() as *const libc::c_void, 1);
        libc::close(pipe_to_child[1]);
        libc::close(pipe_to_parent[0]);
    }

    install_signal_handlers();
    let exit_code = wait_for_child(child_pid);

    let fuse_mountpoint = session.fuse_mountpoint.clone();

    // Release the cwd fd (was kept alive for HostFS), then drop the mount
    // handle to unmount. Drop chdir's to "/" first (unmount EBUSY guard), so
    // restore the caller's cwd after — pit lives on for the next run, unlike
    // the agentfs CLI which exits here.
    drop(cwd_fd);
    drop(mount_handle);
    if std::env::set_current_dir(&cwd).is_err() {
        eprintln!("Warning: failed to restore cwd to {}", cwd.display());
    }

    // Clean up the FUSE mountpoint dir (keep the delta DB).
    if let Err(e) = fs::remove_dir_all(&fuse_mountpoint) {
        eprintln!(
            "Warning: Failed to clean up mountpoint {}: {}",
            fuse_mountpoint.display(),
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
    // SAFETY: getuid/getgid are always safe
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let (pipe_to_child, pipe_to_parent) = create_sync_pipes()?;

    // SAFETY: fork() is safe here.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        bail!("Failed to fork: {}", std::io::Error::last_os_error());
    }

    if child_pid == 0 {
        unsafe {
            libc::close(pipe_to_child[1]);
            libc::close(pipe_to_parent[0]);
        }
        run_child(
            cwd,
            fuse_mountpoint,
            allowed_paths,
            command,
            args,
            session_id,
            pipe_to_child[0],
            pipe_to_parent[1],
        );
    }

    unsafe {
        libc::close(pipe_to_child[0]);
        libc::close(pipe_to_parent[1]);
    }

    if !wait_for_pipe_signal(pipe_to_parent[0]) {
        eprintln!("Error: Failed to read sync signal from child process");
        abort_child(pipe_to_child[1], child_pid);
    }

    write_namespace_mappings(child_pid, uid, gid, pipe_to_child[1]);

    unsafe {
        libc::write(pipe_to_child[1], b"x".as_ptr() as *const libc::c_void, 1);
        libc::close(pipe_to_child[1]);
        libc::close(pipe_to_parent[0]);
    }

    // Joining session: don't unmount or clean up — the owner does that.
    install_signal_handlers();
    let exit_code = wait_for_child(child_pid);
    Ok(exit_code)
}

/// A sandbox run session: delta DB path, FUSE mountpoint, base-path file.
struct RunSession {
    db_path: PathBuf,
    fuse_mountpoint: PathBuf,
    base_path_file: PathBuf,
}

/// Create the run directory (~/.agentfs/run/<sid>) with delta DB, mountpoint
/// and base-path marker. Kept compatible with agentfs so sessions interop.
fn setup_run_directory(session_id: &str) -> Result<RunSession> {
    let run_dir = run_dir()?;
    let run_dir = run_dir.join(session_id);
    fs::create_dir_all(&run_dir).context("Failed to create run directory")?;

    let db_path = run_dir.join("delta.db");
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

/// Wait for a single-byte sync signal on a pipe. True if received.
fn wait_for_pipe_signal(fd: libc::c_int) -> bool {
    let mut buf = [0u8; 1];
    // SAFETY: reading into a valid buffer from a valid fd.
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) > 0 }
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

/// Write uid_map, gid_map, and setgroups for the child's user namespace
/// (maps the real uid/gid to itself). Aborts the child on failure.
fn write_namespace_mappings(
    child_pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    pipe_write_fd: libc::c_int,
) {
    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    let gid_map_path = format!("/proc/{}/gid_map", child_pid);
    let setgroups_path = format!("/proc/{}/setgroups", child_pid);

    if let Err(e) = fs::write(&uid_map_path, format!("{} {} 1\n", uid, uid)) {
        eprintln!("Error: Could not write uid_map: {}", e);
        eprintln!("This may indicate missing unprivileged user namespace support.");
        abort_child(pipe_write_fd, child_pid);
    }
    if let Err(e) = fs::write(&setgroups_path, "deny") {
        eprintln!("Error: Could not write setgroups: {}", e);
        abort_child(pipe_write_fd, child_pid);
    }
    if let Err(e) = fs::write(&gid_map_path, format!("{} {} 1\n", gid, gid)) {
        eprintln!("Error: Could not write gid_map: {}", e);
        abort_child(pipe_write_fd, child_pid);
    }
}

/// Convert a path to a CString, exiting the child on failure.
fn path_to_cstring(path: &Path, description: &str) -> CString {
    match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Invalid {} (contains NUL byte): {}", description, path.display());
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

/// Child process: set up namespace isolation and exec the command.
fn run_child(
    cwd: &Path,
    fuse_mountpoint: &Path,
    allowed_paths: &[PathBuf],
    command: PathBuf,
    args: Vec<String>,
    session_id: &str,
    pipe_from_parent: libc::c_int,
    pipe_to_parent: libc::c_int,
) -> ! {
    // Step 1: new user + mount namespaces. The user namespace gives us
    // CAP_SYS_ADMIN within the namespace to manipulate mounts.
    // SAFETY: unshare() with valid flags; error handled.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        child_exit(&format!(
            "Failed to unshare namespaces: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 2: signal the parent so it can write uid_map/gid_map.
    // SAFETY: writing to and closing valid pipe fds.
    unsafe {
        libc::write(pipe_to_parent, b"x".as_ptr() as *const libc::c_void, 1);
        libc::close(pipe_to_parent);
    }

    // Step 3: wait for the parent to finish the namespace mappings.
    if !wait_for_pipe_signal(pipe_from_parent) {
        child_exit("Failed to read sync signal from parent: pipe closed unexpectedly");
    }
    // SAFETY: closing a valid fd.
    unsafe { libc::close(pipe_from_parent) };

    // Step 4: make all mounts private to prevent propagation to the parent.
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

    // Step 5: bind-mount the FUSE overlay (from the temp dir) onto the cwd.
    // Only visible in this namespace.
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

    // Step 6: chdir to cwd so we're using the overlay.
    if std::env::set_current_dir(cwd).is_err() {
        child_exit("Failed to change to working directory");
    }

    // Step 7: remount everything else read-only.
    if let Err(e) = remount_all_readonly_except(cwd, allowed_paths) {
        child_exit(&format!("Failed to remount filesystems read-only: {}", e));
    }

    // Step 8: exec (does not return).
    exec_command(command, args, session_id);
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
    std::env::set_var("PS1", "🤖 \\u@\\h:\\w\\$ ");

    // Configure SSH to skip system config files: inside the user namespace,
    // root-owned files in /etc/ssh/ssh_config.d/ appear with unmapped uid,
    // causing ssh to reject them. Use only ~/.ssh/config.
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
