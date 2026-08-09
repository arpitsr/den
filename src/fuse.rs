//! FUSE adapter bridging the agentfs SDK's async `FileSystem` trait to the
//! sync `fuser::Filesystem` trait — ported from the agentfs CLI
//! (`cli/src/fuse.rs`, MIT). The vendored fork's `Request::deferred_notifier`
//! is replaced by a local `DeferredNotifier` backed by the published crate's
//! `Session::notifier()` (same deferred-flush design).

use agentfs_sdk::error::Error as SdkError;
use agentfs_sdk::filesystem::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFSOCK};
use agentfs_sdk::{BoxedFile, FileSystem, Stats, TimeChange};
use anyhow::Result;
use fuser::consts::{
    FUSE_ASYNC_READ, FUSE_CACHE_SYMLINKS, FUSE_NO_OPENDIR_SUPPORT, FUSE_PARALLEL_DIROPS,
    FUSE_WRITEBACK_CACHE,
};
use fuser::{
    fuse_forget_one, FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, Request,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;

/// Convert an SDK error to an errno for FUSE replies.
///
/// Filesystem-specific errors map to their errno; database busy / connection
/// pool timeouts return EAGAIN so the caller retries; otherwise EIO.
fn error_to_errno(e: &SdkError) -> i32 {
    match e {
        SdkError::Fs(fs_err) => fs_err.to_errno(),
        SdkError::Io(io_err) => io_err.raw_os_error().unwrap_or(libc::EIO),
        // ponytail: string check instead of matching turso::Error::Busy directly
        // (would add a direct turso dep for one match arm). "busy" -> EAGAIN,
        // anything else (corruption etc.) -> EIO.
        SdkError::Database(e) => {
            if e.to_string().to_lowercase().contains("busy") {
                libc::EAGAIN
            } else {
                libc::EIO
            }
        }
        SdkError::ConnectionPoolTimeout => libc::EAGAIN,
        _ => libc::EIO,
    }
}

/// Maximize the fd limit (soft -> hard). Passthrough filesystems cache O_PATH
/// fds for inode handles; without this, big repos hit EMFILE.
fn maximize_fd_limit() {
    // SAFETY: getrlimit/setrlimit with valid rlimit structs.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            let old_soft = lim.rlim_cur;
            lim.rlim_cur = lim.rlim_max;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0 {
                eprintln!("debug: raised fd limit from {old_soft} to {}", lim.rlim_max);
            }
        }
    }
}

/// Cache entries never expire — we use deferred kernel cache invalidation
/// (via the notify thread) after mutations. Safe: we're the only writer.
const TTL: Duration = Duration::MAX;

/// Options for mounting the agent filesystem via FUSE.
#[derive(Debug, Clone)]
pub struct FuseMountOptions {
    pub mountpoint: PathBuf,
    pub auto_unmount: bool,
    pub allow_root: bool,
    pub allow_other: bool,
    pub fsname: String,
}

/// A queued kernel-cache invalidation, flushed by a dedicated thread.
///
/// FUSE notification writes to /dev/fuse cannot be issued from the session
/// loop thread: the kernel processes FUSE_NOTIFY_INVAL_ENTRY synchronously
/// inside the writev() call, which can trigger d_invalidate -> iput ->
/// FUSE_FORGET, which needs the daemon reading /dev/fuse — the loop thread is
/// blocked in writev(), so that deadlocks. Deferring to a separate thread
/// avoids it.
#[derive(Debug, Clone)]
pub(crate) struct DeferredNotifier {
    tx: mpsc::Sender<NotifyOp>,
}

#[derive(Debug)]
pub(crate) enum NotifyOp {
    InvalEntry { parent: u64, name: std::ffi::OsString },
}

impl DeferredNotifier {
    pub(crate) fn new(tx: mpsc::Sender<NotifyOp>) -> Self {
        Self { tx }
    }

    pub(crate) fn inval_entry(&self, parent: u64, name: &OsStr) {
        let _ = self.tx.send(NotifyOp::InvalEntry {
            parent,
            name: name.to_os_string(),
        });
    }
}

/// Tracks an open file handle.
struct OpenFile {
    file: BoxedFile,
}

struct AgentFSFuse {
    fs: Arc<dyn FileSystem>,
    runtime: Runtime,
    open_files: Arc<Mutex<HashMap<u64, OpenFile>>>,
    next_fh: AtomicU64,
    notifier: DeferredNotifier,
}

impl Filesystem for AgentFSFuse {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        let _ = config.add_capabilities(
            FUSE_ASYNC_READ
                | FUSE_WRITEBACK_CACHE
                | FUSE_PARALLEL_DIROPS
                | FUSE_CACHE_SYMLINKS
                | FUSE_NO_OPENDIR_SUPPORT,
        );
        Ok(())
    }

    // ── Name resolution & attributes ────────────────────────────────────────

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self
            .runtime
            .block_on(async move { fs.lookup(parent as i64, &name_owned).await })
        {
            Ok(Some(stats)) => reply.entry(&TTL, &fillattr(&stats), 0),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let fs = self.fs.clone();
        match self
            .runtime
            .block_on(async move { fs.getattr(ino as i64).await })
        {
            Ok(Some(stats)) => reply.attr(&TTL, &fillattr(&stats)),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let fs = self.fs.clone();
        match self
            .runtime
            .block_on(async move { fs.readlink(ino as i64).await })
        {
            Ok(Some(target)) => reply.data(target.as_bytes()),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // chmod
        if let Some(new_mode) = mode {
            let fs = self.fs.clone();
            if let Err(e) = self
                .runtime
                .block_on(async move { fs.chmod(ino as i64, new_mode).await })
            {
                reply.error(error_to_errno(&e));
                return;
            }
        }

        // chown
        if uid.is_some() || gid.is_some() {
            let fs = self.fs.clone();
            if let Err(e) = self
                .runtime
                .block_on(async move { fs.chown(ino as i64, uid, gid).await })
            {
                reply.error(error_to_errno(&e));
                return;
            }
        }

        // truncate
        if let Some(new_size) = size {
            let result = if let Some(fh) = fh {
                let file = {
                    let open_files = self.open_files.lock().unwrap();
                    open_files.get(&fh).map(|f| f.file.clone())
                };
                if let Some(file) = file {
                    self.runtime
                        .block_on(async move { file.truncate(new_size).await })
                } else {
                    reply.error(libc::EBADF);
                    return;
                }
            } else {
                let fs = self.fs.clone();
                self.runtime.block_on(async move {
                    let file = fs.open(ino as i64, libc::O_RDWR).await?;
                    file.truncate(new_size).await
                })
            };
            if let Err(e) = result {
                reply.error(error_to_errno(&e));
                return;
            }
        }

        // atime/mtime (utimensat)
        if atime.is_some() || mtime.is_some() {
            let new_atime = match atime {
                Some(fuser::TimeOrNow::SpecificTime(t)) => {
                    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    TimeChange::Set(dur.as_secs() as i64, dur.subsec_nanos())
                }
                Some(fuser::TimeOrNow::Now) => TimeChange::Now,
                None => TimeChange::Omit,
            };
            let new_mtime = match mtime {
                Some(fuser::TimeOrNow::SpecificTime(t)) => {
                    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    TimeChange::Set(dur.as_secs() as i64, dur.subsec_nanos())
                }
                Some(fuser::TimeOrNow::Now) => TimeChange::Now,
                None => TimeChange::Omit,
            };
            let fs = self.fs.clone();
            if let Err(e) = self
                .runtime
                .block_on(async move { fs.utimens(ino as i64, new_atime, new_mtime).await })
            {
                reply.error(error_to_errno(&e));
                return;
            }
        }

        let fs = self.fs.clone();
        match self
            .runtime
            .block_on(async move { fs.getattr(ino as i64).await })
        {
            Ok(Some(stats)) => reply.attr(&TTL, &fillattr(&stats)),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    // ── Directory operations ────────────────────────────────────────────────

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let fs = self.fs.clone();
        let entries = match self
            .runtime
            .block_on(async move { fs.readdir_plus(ino as i64).await })
        {
            Ok(Some(entries)) => entries,
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(error_to_errno(&e));
                return;
            }
        };

        // We don't track parent relationships; the kernel resolves ".."
        // itself. 1 (root) is a safe fallback.
        let parent_ino = 1u64;
        let mut all_entries = vec![
            (ino, FileType::Directory, "."),
            (parent_ino, FileType::Directory, ".."),
        ];
        for entry in &entries {
            let kind = if entry.stats.is_directory() {
                FileType::Directory
            } else if entry.stats.is_symlink() {
                FileType::Symlink
            } else {
                FileType::RegularFile
            };
            all_entries.push((entry.stats.ino as u64, kind, entry.name.as_str()));
        }

        for (i, entry) in all_entries.iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let fs = self.fs.clone();
        let entries = match self
            .runtime
            .block_on(async move { fs.readdir_plus(ino as i64).await })
        {
            Ok(Some(entries)) => entries,
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                reply.error(error_to_errno(&e));
                return;
            }
        };

        // "." stats
        let fs = self.fs.clone();
        let dir_stats = self
            .runtime
            .block_on(async move { fs.getattr(ino as i64).await })
            .ok()
            .flatten();

        // ".." — root's stats as fallback; kernel handles real resolution.
        let (parent_ino, parent_stats) = if ino == 1 {
            (1u64, dir_stats.clone())
        } else {
            let fs = self.fs.clone();
            let parent_stats = self
                .runtime
                .block_on(async move { fs.getattr(1).await })
                .ok()
                .flatten();
            (1u64, parent_stats)
        };

        let mut offset_counter = 0i64;

        if offset <= offset_counter {
            if let Some(ref stats) = dir_stats {
                let attr = fillattr(stats);
                if reply.add(ino, offset_counter + 1, ".", &TTL, &attr, 0) {
                    reply.ok();
                    return;
                }
            }
        }
        offset_counter += 1;

        if offset <= offset_counter {
            if let Some(ref stats) = parent_stats {
                let attr = fillattr(stats);
                if reply.add(parent_ino, offset_counter + 1, "..", &TTL, &attr, 0) {
                    reply.ok();
                    return;
                }
            }
        }
        offset_counter += 1;

        for entry in &entries {
            if offset <= offset_counter {
                let attr = fillattr(&entry.stats);
                if reply.add(
                    entry.stats.ino as u64,
                    offset_counter + 1,
                    &entry.name,
                    &TTL,
                    &attr,
                    0,
                ) {
                    reply.ok();
                    return;
                }
            }
            offset_counter += 1;
        }

        reply.ok();
    }

    fn mknod(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let uid = req.uid();
        let gid = req.gid();
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self.runtime.block_on(async move {
            fs.mknod(parent as i64, &name_owned, mode, rdev as u64, uid, gid)
                .await
        }) {
            Ok(stats) => reply.entry(&TTL, &fillattr(&stats), 0),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let uid = req.uid();
        let gid = req.gid();
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self.runtime.block_on(async move {
            fs.mkdir(parent as i64, &name_owned, mode, uid, gid).await
        }) {
            Ok(stats) => reply.entry(&TTL, &fillattr(&stats), 0),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self
            .runtime
            .block_on(async move { fs.rmdir(parent as i64, &name_owned).await })
        {
            Ok(()) => {
                reply.ok();
                self.notifier.inval_entry(parent, name);
            }
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    // ── File creation & removal ─────────────────────────────────────────────

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let uid = req.uid();
        let gid = req.gid();
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self.runtime.block_on(async move {
            fs.create_file(parent as i64, &name_owned, mode, uid, gid).await
        }) {
            Ok((stats, file)) => {
                let attr = fillattr(&stats);
                let fh = self.alloc_fh();
                self.open_files.lock().unwrap().insert(fh, OpenFile { file });
                reply.created(&TTL, &attr, 0, fh, 0);
            }
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let (Some(name_str), Some(target_str)) = (link_name.to_str(), target.to_str()) else {
            reply.error(libc::EINVAL);
            return;
        };
        let uid = req.uid();
        let gid = req.gid();
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        let target_owned = target_str.to_string();
        match self.runtime.block_on(async move {
            fs.symlink(parent as i64, &name_owned, &target_owned, uid, gid).await
        }) {
            Ok(stats) => reply.entry(&TTL, &fillattr(&stats), 0),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = newname.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self.runtime.block_on(async move {
            fs.link(ino as i64, newparent as i64, &name_owned).await
        }) {
            Ok(stats) => reply.entry(&TTL, &fillattr(&stats), 0),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let fs = self.fs.clone();
        let name_owned = name_str.to_string();
        match self
            .runtime
            .block_on(async move { fs.unlink(parent as i64, &name_owned).await })
        {
            Ok(()) => {
                reply.ok();
                self.notifier.inval_entry(parent, name);
            }
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(old_name_str), Some(new_name_str)) = (name.to_str(), newname.to_str()) else {
            reply.error(libc::EINVAL);
            return;
        };
        let fs = self.fs.clone();
        let old_name_owned = old_name_str.to_string();
        let new_name_owned = new_name_str.to_string();
        match self.runtime.block_on(async move {
            fs.rename(
                parent as i64,
                &old_name_owned,
                newparent as i64,
                &new_name_owned,
            )
            .await
        }) {
            Ok(()) => {
                reply.ok();
                self.notifier.inval_entry(parent, name);
                self.notifier.inval_entry(newparent, newname);
            }
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    // ── File I/O lifecycle ──────────────────────────────────────────────────

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let fs = self.fs.clone();
        match self
            .runtime
            .block_on(async move { fs.open(ino as i64, flags).await })
        {
            Ok(file) => {
                let fh = self.alloc_fh();
                self.open_files.lock().unwrap().insert(fh, OpenFile { file });
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let file = {
            let open_files = self.open_files.lock().unwrap();
            let Some(open_file) = open_files.get(&fh) else {
                reply.error(libc::EBADF);
                return;
            };
            open_file.file.clone()
        };
        match self
            .runtime
            .block_on(async move { file.pread(offset as u64, size as u64).await })
        {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let file = {
            let open_files = self.open_files.lock().unwrap();
            let Some(open_file) = open_files.get(&fh) else {
                reply.error(libc::EBADF);
                return;
            };
            open_file.file.clone()
        };
        let data_len = data.len();
        let data_vec = data.to_vec();
        match self
            .runtime
            .block_on(async move { file.pwrite(offset as u64, &data_vec).await })
        {
            Ok(()) => reply.written(data_len as u32),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    /// Writes go straight to the DB, so flush is a no-op.
    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if self.open_files.lock().unwrap().contains_key(&fh) {
            reply.ok();
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        let file = {
            let open_files = self.open_files.lock().unwrap();
            match open_files.get(&fh) {
                Some(open_file) => open_file.file.clone(),
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            }
        };
        match self.runtime.block_on(async move { file.fsync().await }) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(error_to_errno(&e)),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files.lock().unwrap().remove(&fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        const BLOCK_SIZE: u64 = 4096;
        const TOTAL_INODES: u64 = 1_000_000;
        const MAX_NAMELEN: u32 = 255;

        let fs = self.fs.clone();
        let result = self.runtime.block_on(async move { fs.statfs().await });

        let (used_blocks, used_inodes) = match result {
            Ok(stats) => (stats.bytes_used.div_ceil(BLOCK_SIZE), stats.inodes),
            Err(_) => (0, 1),
        };

        // Large virtual capacity so tools don't think we're out of space.
        const TOTAL_BLOCKS: u64 = 1024 * 1024 * 1024;
        let free_blocks = TOTAL_BLOCKS.saturating_sub(used_blocks);
        let free_inodes = TOTAL_INODES.saturating_sub(used_inodes);

        reply.statfs(
            TOTAL_BLOCKS,
            free_blocks,
            free_blocks,
            TOTAL_INODES,
            free_inodes,
            BLOCK_SIZE as u32,
            MAX_NAMELEN,
            BLOCK_SIZE as u32,
        );
    }

    // ── Inode lifecycle ─────────────────────────────────────────────────────

    /// Releases cached O_PATH fds in passthrough filesystems (HostFS).
    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        let fs = self.fs.clone();
        self.runtime
            .block_on(async move { fs.forget(ino as i64, nlookup).await });
    }

    fn batch_forget(&mut self, _req: &Request<'_>, nodes: &[fuse_forget_one]) {
        let fs = self.fs.clone();
        let nodes_vec: Vec<(i64, u64)> = nodes
            .iter()
            .map(|n| (n.nodeid as i64, n.nlookup))
            .collect();
        self.runtime.block_on(async move {
            for (ino, nlookup) in nodes_vec {
                fs.forget(ino, nlookup).await;
            }
        });
    }
}

impl AgentFSFuse {
    fn new(fs: Arc<dyn FileSystem>, runtime: Runtime, notifier: DeferredNotifier) -> Self {
        Self {
            fs,
            runtime,
            open_files: Arc::new(Mutex::new(HashMap::new())),
            next_fh: AtomicU64::new(1),
            notifier,
        }
    }

    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }
}

/// Fill a `FileAttr` from agentfs stats. uid/gid override the stored values
/// to avoid "dubious ownership" errors from git.
fn fillattr(stats: &Stats) -> FileAttr {
    let file_type = stats.mode & S_IFMT;
    let kind = match file_type {
        S_IFDIR => FileType::Directory,
        S_IFLNK => FileType::Symlink,
        S_IFIFO => FileType::NamedPipe,
        S_IFCHR => FileType::CharDevice,
        S_IFBLK => FileType::BlockDevice,
        S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    };

    let size = if file_type == S_IFDIR {
        4096_u64
    } else {
        stats.size as u64
    };

    FileAttr {
        ino: stats.ino as u64,
        size,
        blocks: size.div_ceil(512),
        atime: UNIX_EPOCH + Duration::new(stats.atime as u64, stats.atime_nsec),
        mtime: UNIX_EPOCH + Duration::new(stats.mtime as u64, stats.mtime_nsec),
        ctime: UNIX_EPOCH + Duration::new(stats.ctime as u64, stats.ctime_nsec),
        crtime: UNIX_EPOCH,
        kind,
        perm: (stats.mode & 0o7777) as u16,
        nlink: stats.nlink,
        uid: stats.uid,
        gid: stats.gid,
        rdev: stats.rdev as u32,
        flags: 0,
        blksize: 512,
    }
}

/// Is `allow_other` supported? Root always; otherwise `user_allow_other` in
/// /etc/fuse.conf.
fn allow_other_supported() -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } == 0 {
        return true;
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/fuse.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if !line.starts_with('#') && !line.is_empty() && line == "user_allow_other" {
                return true;
            }
        }
    }
    false
}

/// Mount the overlay: create the fuser session (mounts via fusermount3),
/// hand the notifier to a deferred invalidation thread, then serve requests
/// until unmounted. Sends the mount result to `ready_tx` so the caller
/// doesn't sit through the readiness timeout on failure.
pub(crate) fn mount(
    fs: Arc<dyn FileSystem>,
    opts: FuseMountOptions,
    runtime: Runtime,
    ready_tx: std::sync::mpsc::SyncSender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    maximize_fd_limit();

    let (notify_tx, notify_rx) = mpsc::channel::<NotifyOp>();
    let fs = AgentFSFuse::new(fs, runtime, DeferredNotifier::new(notify_tx));

    let mut mount_opts = vec![
        MountOption::FSName(opts.fsname),
        MountOption::DefaultPermissions,
    ];
    if opts.allow_other {
        if allow_other_supported() {
            mount_opts.push(MountOption::AllowOther);
        } else {
            let msg = "FUSE allow_other not supported. Add 'user_allow_other' to /etc/fuse.conf or run as root.";
            let _ = ready_tx.send(Err(anyhow::anyhow!("{msg}")));
            return Err(anyhow::anyhow!("{msg}"));
        }
    }
    if opts.auto_unmount {
        mount_opts.push(MountOption::AutoUnmount);
    }
    if opts.allow_root {
        mount_opts.push(MountOption::AllowRoot);
    }

    let mut session = fuser::Session::new(fs, &opts.mountpoint, &mount_opts)
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}"))?;

    // Deferred kernel-cache invalidation, on its own thread (see
    // DeferredNotifier for the deadlock rationale).
    let notifier = session.notifier();
    std::thread::spawn(move || {
        while let Ok(op) = notify_rx.recv() {
            match op {
                NotifyOp::InvalEntry { parent, name } => {
                    let _ = notifier.inval_entry(parent, &name);
                }
            }
        }
    });

    let _ = ready_tx.send(Ok(()));
    session.run().map_err(|e| anyhow::anyhow!("FUSE session ended with error: {e}"))
}
