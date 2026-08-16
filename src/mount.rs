//! FUSE mount plumbing for the sandbox — ported from the agentfs CLI
//! (`cli/src/mount/fuse.rs` + `cli/src/mount/mod.rs`, MIT), using the
//! published `fuser` crate instead of the vendored fork.

use crate::fuse::FuseMountOptions;
use agentfs_sdk::{FileSystem, Stats};
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Options for mounting the virtual filesystem.
pub struct MountOpts {
    pub mountpoint: PathBuf,
    pub fsname: String,
    pub allow_other: bool,
    pub allow_root: bool,
    pub auto_unmount: bool,
    pub lazy_unmount: bool,
    pub timeout: Duration,
}

/// A mounted virtual FS; unmounts when dropped.
pub struct MountHandle {
    mountpoint: PathBuf,
    lazy_unmount: bool,
    _thread: std::thread::JoinHandle<anyhow::Result<()>>,
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        // Move away from the mountpoint before unmounting to avoid EBUSY.
        let _ = std::env::set_current_dir("/");
        if let Err(e) = unmount_fuse(&self.mountpoint, self.lazy_unmount) {
            eprintln!(
                "Warning: Failed to unmount FUSE filesystem at {}: {}",
                self.mountpoint.display(),
                e
            );
        }
    }
}

/// Unmount via fusermount3/fusermount (setuid helper; `-uz` = lazy).
fn unmount_fuse(mountpoint: &Path, lazy: bool) -> Result<()> {
    const FUSERMOUNT_COMMANDS: &[&str] = &["fusermount3", "fusermount"];
    let args: &[&str] = if lazy { &["-uz"] } else { &["-u"] };

    for cmd in FUSERMOUNT_COMMANDS {
        match Command::new(cmd).args(args).arg(mountpoint.as_os_str()).status() {
            Ok(status) if status.success() => return Ok(()),
            _ => continue,
        }
    }

    anyhow::bail!(
        "Failed to unmount {}. You may need to unmount manually with: fusermount -u {}",
        mountpoint.display(),
        mountpoint.display()
    )
}

/// Adapter so `Arc<Mutex<dyn FileSystem + Send>>` can be passed as
/// `Arc<dyn FileSystem>` (the SDK trait is async; the lock serializes access).
struct MutexFsAdapter {
    inner: Arc<Mutex<dyn FileSystem + Send>>,
}

#[async_trait::async_trait]
impl FileSystem for MutexFsAdapter {
    async fn lookup(&self, parent_ino: i64, name: &str) -> Result<Option<Stats>, agentfs_sdk::error::Error> {
        self.inner.lock().await.lookup(parent_ino, name).await
    }
    async fn getattr(&self, ino: i64) -> Result<Option<Stats>, agentfs_sdk::error::Error> {
        self.inner.lock().await.getattr(ino).await
    }
    async fn readlink(&self, ino: i64) -> Result<Option<String>, agentfs_sdk::error::Error> {
        self.inner.lock().await.readlink(ino).await
    }
    async fn readdir(&self, ino: i64) -> Result<Option<Vec<String>>, agentfs_sdk::error::Error> {
        self.inner.lock().await.readdir(ino).await
    }
    async fn readdir_plus(&self, ino: i64) -> Result<Option<Vec<agentfs_sdk::DirEntry>>, agentfs_sdk::error::Error> {
        self.inner.lock().await.readdir_plus(ino).await
    }
    async fn chmod(&self, ino: i64, mode: u32) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.chmod(ino, mode).await
    }
    async fn chown(&self, ino: i64, uid: Option<u32>, gid: Option<u32>) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.chown(ino, uid, gid).await
    }
    async fn utimens(&self, ino: i64, atime: agentfs_sdk::TimeChange, mtime: agentfs_sdk::TimeChange) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.utimens(ino, atime, mtime).await
    }
    async fn open(&self, ino: i64, flags: i32) -> Result<agentfs_sdk::BoxedFile, agentfs_sdk::error::Error> {
        self.inner.lock().await.open(ino, flags).await
    }
    async fn mkdir(&self, parent_ino: i64, name: &str, mode: u32, uid: u32, gid: u32) -> Result<Stats, agentfs_sdk::error::Error> {
        self.inner.lock().await.mkdir(parent_ino, name, mode, uid, gid).await
    }
    async fn create_file(&self, parent_ino: i64, name: &str, mode: u32, uid: u32, gid: u32) -> Result<(Stats, agentfs_sdk::BoxedFile), agentfs_sdk::error::Error> {
        self.inner.lock().await.create_file(parent_ino, name, mode, uid, gid).await
    }
    async fn mknod(&self, parent_ino: i64, name: &str, mode: u32, rdev: u64, uid: u32, gid: u32) -> Result<Stats, agentfs_sdk::error::Error> {
        self.inner.lock().await.mknod(parent_ino, name, mode, rdev, uid, gid).await
    }
    async fn symlink(&self, parent_ino: i64, name: &str, target: &str, uid: u32, gid: u32) -> Result<Stats, agentfs_sdk::error::Error> {
        self.inner.lock().await.symlink(parent_ino, name, target, uid, gid).await
    }
    async fn unlink(&self, parent_ino: i64, name: &str) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.unlink(parent_ino, name).await
    }
    async fn rmdir(&self, parent_ino: i64, name: &str) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.rmdir(parent_ino, name).await
    }
    async fn link(&self, ino: i64, newparent_ino: i64, newname: &str) -> Result<Stats, agentfs_sdk::error::Error> {
        self.inner.lock().await.link(ino, newparent_ino, newname).await
    }
    async fn rename(&self, oldparent_ino: i64, oldname: &str, newparent_ino: i64, newname: &str) -> Result<(), agentfs_sdk::error::Error> {
        self.inner.lock().await.rename(oldparent_ino, oldname, newparent_ino, newname).await
    }
    async fn statfs(&self) -> Result<agentfs_sdk::FilesystemStats, agentfs_sdk::error::Error> {
        self.inner.lock().await.statfs().await
    }
    async fn forget(&self, ino: i64, nlookup: u64) {
        self.inner.lock().await.forget(ino, nlookup).await;
    }
}

/// Mount the virtual filesystem at the mountpoint. The FUSE session runs on a
/// background thread; the mountpoint stays mounted until the handle drops
/// (unmounting then is this process's job — the child's namespace only sees
/// the bind-mounted cwd, which dies with the child).
pub async fn mount_fs(
    fs: Arc<Mutex<dyn FileSystem + Send>>,
    opts: MountOpts,
) -> Result<MountHandle> {
    let mountpoint = opts.mountpoint.clone();
    let timeout = opts.timeout;
    let lazy_unmount = opts.lazy_unmount;

    let fuse_opts = FuseMountOptions {
        mountpoint: mountpoint.clone(),
        auto_unmount: opts.auto_unmount,
        allow_root: opts.allow_root,
        allow_other: opts.allow_other,
        fsname: opts.fsname.clone(),
    };

    // The mount thread reports Session::new's result back so a mount failure
    // (e.g. missing fusermount3) surfaces immediately instead of after the
    // readiness timeout.
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);

    let fs_adapter: Arc<dyn FileSystem> = Arc::new(MutexFsAdapter { inner: fs });

    let thread = std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = ready_tx.send(Err(anyhow!("failed to build FUSE runtime: {e}")));
                return Err(anyhow!("failed to build FUSE runtime: {e}"));
            }
        };
        crate::fuse::mount(fs_adapter, fuse_opts, rt, ready_tx)
    });

    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(MountHandle {
            mountpoint,
            lazy_unmount,
            _thread: thread,
        }),
        Ok(Err(e)) => Err(e.context("FUSE mount failed")),
        Err(_) => {
            anyhow::bail!("FUSE mount did not become ready within {:?}", timeout)
        }
    }
}

/// Check if a path is a mountpoint by comparing device IDs with its parent.
pub fn is_mountpoint(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let path_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("/"),
    };
    let parent_meta = match std::fs::metadata(parent) {
        Ok(m) => m,
        Err(_) => return false,
    };
    path_meta.dev() != parent_meta.dev()
}
