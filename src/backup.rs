//! LTX backup & restore of session fs.db files, using the `litetx` crate (a
//! port of https://github.com/superfly/ltx-rs — the Lite Transaction File
//! format for SQLite backup).
//!
//!   den backup <sid> [--from <prev.ltx>] [--out <path>] [-c] [--watch]
//!     snapshot (or delta from the previous file in the chain) of
//!     ~/.den/sessions/<sid>/fs.db; --watch keeps appending chained deltas
//!     while the session is written (Litestream-style streaming)
//!   den restore <file.ltx> [--to <db>]
//!     apply an LTX file (and any chain siblings) back into a session fs.db
//!   den ltx <file.ltx>
//!     inspect a backup file: header, page count, checksums (verifies them)
//!
//! The fs.db is a plain SQLite file that the agentfs SDK leaves in WAL mode
//! (a `-wal` sibling persists after a clean close). `prepare_db` folds any WAL
//! frames into the main file via wal_checkpoint before we read it page-by-page;
//! a `-journal` sibling (mid-commit) is refused. Page reads are plain file
//! reads: SQLite header at offset 16 gives the page size, offset 28 the page
//! count (0 = infer from file size).

use anyhow::{anyhow, bail, Context, Result};
use litetx::{
    Checksum, Decoder, Encoder, Header, HeaderFlags, PageChecksum, PageNum, PageSize, Trailer, TXID,
};
use rusqlite::Connection;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// litetx's Header::is_snapshot is crate-private; a snapshot is min_txid == 1.
fn is_snapshot(h: &Header) -> bool {
    h.min_txid == TXID::ONE
}

/// bytes 16..18 (page size, 1 means 65536) and 28..32 (page count, 0 = infer)
fn sqlite_header(path: &Path) -> Result<(u32, u32)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hdr = [0u8; 100];
    f.read_exact(&mut hdr)
        .with_context(|| format!("read SQLite header of {}", path.display()))?;
    let ps = u16::from_be_bytes([hdr[16], hdr[17]]) as u32;
    let ps = if ps == 1 { 65536 } else { ps };
    let mut count = u32::from_be_bytes([hdr[28], hdr[29], hdr[30], hdr[31]]);
    if count == 0 {
        count = (f.metadata()?.len() / ps as u64) as u32;
    }
    if !(512..=65536).contains(&ps) || ps & (ps - 1) != 0 {
        bail!("{}: unsupported page size {ps}", path.display());
    }
    Ok((ps, count))
}

/// Fold the WAL into the main file so it's a complete snapshot of committed
/// state, and refuse a torn DB. `strict` is for on-demand backup: a mid-write
/// DB is an error. The watch loop passes false and gets `Ok(false)` to skip
/// the round — the frames are still safe in the WAL, and the writer's own
/// auto-checkpoint flushes them soon.
fn prepare_db(db: &Path, strict: bool) -> Result<bool> {
    // a -journal sibling means a rollback-journal commit is mid-write —
    // refuse rather than read a torn DB
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    if journal.exists() {
        if strict {
            bail!(
                "{} present — session appears mid-write; run backup after the agent exits",
                journal.display()
            );
        }
        return Ok(false);
    }
    // the SDK leaves its DBs in WAL mode (a -wal sibling persists after a
    // clean close, usually empty) — fold any frames into the main file
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    if wal.exists() {
        let conn = Connection::open(db)?;
        let res = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?;
        drop(conn);
        if res.0 != 0 {
            if strict {
                bail!(
                    "wal_checkpoint on {} failed (result {}): DB may be mid-write",
                    db.display(),
                    res.0
                );
            }
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_page(f: &mut File, pgno: u32, ps: u32) -> Result<Vec<u8>> {
    let mut page = vec![0u8; ps as usize];
    f.seek(SeekFrom::Start((pgno - 1) as u64 * ps as u64))?;
    f.read_exact(&mut page)?;
    Ok(page)
}

/// Running DB checksum: XOR of CRC-64 page checksums over pages 1..=count
/// (mirrors litetx's own test fixtures: `checksum ^ buf.page_checksum(pgno)`).
///
/// The lock-byte page is included if it falls within `count`; since LTX never
/// stores that page, `cmd_backup` refuses DBs that contain it (≥1 GiB at 4 KiB
/// pages) so the checksums recorded at backup and re-derived at restore agree.
fn db_checksum(path: &Path, ps: u32, count: u32) -> Result<Checksum> {
    let mut f = File::open(path)?;
    let mut sum = Checksum::new(0);
    for pgno in 1..=count {
        let page = read_page(&mut f, pgno, ps)?;
        sum = sum ^ page.page_checksum(PageNum::new(pgno)?);
    }
    Ok(sum)
}

/// Decode an LTX file: header, pages (pgno -> data), trailer.
fn read_ltx(path: &Path) -> Result<(Header, HashMap<u32, Vec<u8>>, Trailer)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let (mut dec, header) = Decoder::new(&mut f)?;
    let mut pages = HashMap::new();
    let mut buf = vec![0u8; header.page_size.into_inner() as usize];
    while let Some(pgno) = dec.decode_page(&mut buf)? {
        pages.insert(pgno.into_inner(), buf.clone());
    }
    let trailer = dec.finish()?;
    Ok((header, pages, trailer))
}

/// Write one LTX file for the session: a snapshot, or a delta against `from`
/// (the previous file in the chain). `strict` is the on-demand mode: a
/// mid-write DB is an error. The watch loop passes false and gets `Ok(false)`
/// to skip the round and retry. Returns whether a file was written.
fn cmd_backup_inner(
    sid: &str,
    from: Option<&Path>,
    out: &Path,
    compress: bool,
    strict: bool,
) -> Result<bool> {
    let db = crate::session_db_path(sid)?;
    if !db.exists() {
        bail!("no fs.db for session {sid} at {}", db.display());
    }
    if !prepare_db(&db, strict)? {
        return Ok(false); // writer mid-commit; the watch loop retries next round
    }
    let (ps, commit) = sqlite_header(&db)?;
    let lock = PageNum::lock_page(PageSize::new(ps)?).into_inner();
    if commit >= lock {
        bail!(
            "{}: {commit}-page DB contains the lock-byte page {lock}, which LTX never stores — too large to back up",
            db.display()
        );
    }

    let mut f = File::open(&db)?;
    let (header, n_pages, post_apply) = match from {
        None => write_snapshot(&mut f, out, ps, commit, compress)?,
        Some(prev_path) => write_delta(&mut f, out, ps, commit, compress, prev_path)?,
    };

    let size = std::fs::metadata(out)?.len();
    let kind = if is_snapshot(&header) {
        "snapshot"
    } else {
        "delta"
    };
    println!(
        "den: backed up session {sid} -> {} ({kind}, txid {}, {n_pages} pages of {ps} B, {size} bytes)",
        out.display(),
        header.min_txid
    );
    match header.pre_apply_checksum {
        Some(pre) => println!("  pre-apply {pre}, post-apply {post_apply}"),
        None => println!("  post-apply checksum {post_apply}"),
    }
    Ok(true)
}

/// `den backup <sid> [--from <prev.ltx>] [--out <path>] [-c]`
pub fn cmd_backup(sid: &str, from: Option<&Path>, out: &Path, compress: bool) -> Result<()> {
    cmd_backup_inner(sid, from, out, compress, true)?;
    Ok(())
}

/// The k-th file of a watch chain: k=0 is the snapshot, k≥1 the deltas
/// (out.ltx, out.0001.ltx, out.0002.ltx, ...).
pub(crate) fn chain_path(base: &Path, k: u32) -> PathBuf {
    if k == 0 {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    base.with_file_name(format!("{stem}.{k:04}{ext}"))
}

/// (len, mtime) of the DB file and its -wal sibling (if any) — a cheap
/// change detector for the watch loop.
/// Chain files present next to `base` (`base.0001.ltx`, ...), in order.
/// The chain must be contiguous — a gap means newer deltas sit beyond a
/// missing link, and replaying only the prefix would silently restore a
/// stale state, so refuse.
pub(crate) fn existing_chain_indices(base: &Path) -> Result<Vec<u32>> {
    let dir = match base.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let prefix = format!("{stem}.");
    let mut idxs: Vec<u32> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(num) = rest.strip_suffix(&ext) else {
            continue;
        };
        if num.len() >= 4 && num.chars().all(|c| c.is_ascii_digit()) {
            idxs.push(num.parse().unwrap_or(0));
        }
    }
    idxs.sort_unstable();
    for (i, &idx) in idxs.iter().enumerate() {
        let expected = i as u32 + 1;
        if idx != expected {
            bail!(
                "chain gap: missing {} before {} — restore the newest surviving prefix by hand",
                chain_path(base, expected).display(),
                chain_path(base, idx).display()
            );
        }
    }
    Ok(idxs)
}

type DbState = (u64, SystemTime, Option<(u64, SystemTime)>);

fn db_state(db: &Path) -> Result<DbState> {
    let m = std::fs::metadata(db)?;
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let w = match wal.metadata() {
        Ok(w) => Some((w.len(), w.modified()?)),
        Err(_) => None,
    };
    Ok((m.len(), m.modified()?, w))
}

/// Poll interval for --watch. Like Litestream (which also polls the WAL —
/// SQLite has no cross-process write notification), we re-check the DB and
/// its -wal sibling every couple of seconds.
const WATCH_POLL: Duration = Duration::from_secs(2);

/// Streaming watch state: chain position + last-seen DB state.
struct Watch {
    sid: String,
    out: PathBuf,
    compress: bool,
    n: u32, // files written so far: chain_path(out, 0..=n) all exist
    state: DbState,
}

impl Watch {
    /// One round: if the DB changed since the last write, append the next
    /// chain file (a delta against the newest one). Skipped while the writer
    /// is mid-commit — the frames stay safe in the WAL and the next round
    /// catches them.
    fn tick(&mut self) -> Result<()> {
        let db = crate::session_db_path(&self.sid)?;
        let now = db_state(&db)?;
        if now == self.state {
            return Ok(());
        }
        let next = chain_path(&self.out, self.n + 1);
        let prev = chain_path(&self.out, self.n);
        if !cmd_backup_inner(&self.sid, Some(&prev), &next, self.compress, false)? {
            return Ok(());
        }
        self.n += 1;
        self.state = db_state(&db)?; // re-stat: the writer may have moved on
        Ok(())
    }
}

/// `den backup --watch <sid> [--out <base>.ltx]` — Litestream-style
/// streaming: write a snapshot, then keep appending chained deltas while the
/// session's DB changes, until interrupted. Every file is written complete,
/// so Ctrl-C (or a crash) always leaves the chain restorable up to the last
/// tick, and restarting resumes from the newest file. `den restore <base>.ltx`
/// replays the whole chain.
/// One watcher per session: hold an exclusive flock on a lock file next to
/// the fs.db for the process lifetime, so a second `--watch` on the same
/// session (e.g. a duplicate `den <profile> --autostart`) refuses instead of
/// racing on the chain files. The lock dies with the process — no stale-pid
/// bookkeeping.
fn lock_watch(sid: &str) -> Result<File> {
    let path = crate::run_dir()?.join(sid).join("backup-watch.lock");
    let f = File::create(&path)?;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        bail!(
            "another backup watch is already streaming session {sid} ({})",
            path.display()
        );
    }
    Ok(f)
}

/// `den backup --watch <sid> [--out <base>.ltx]` — Litestream-style
/// streaming: write a snapshot, then keep appending chained deltas while the
/// session's DB changes, until interrupted. Every file is written complete,
/// so Ctrl-C (or a crash) always leaves the chain restorable up to the last
/// tick, and restarting resumes from the newest file. `den restore <base>.ltx`
/// replays the whole chain. Waits up to 30s for the session DB to appear, so
/// `den <profile> --autostart` works on the very first run of a profile.
pub fn cmd_backup_watch(sid: &str, out: &Path, compress: bool) -> Result<()> {
    let db = crate::session_db_path(sid)?;
    let mut waited = 0;
    while !db.exists() {
        if waited >= 15 {
            bail!(
                "no fs.db for session {sid} at {} (waited 30s)",
                db.display()
            );
        }
        std::thread::sleep(WATCH_POLL);
        waited += 1;
    }
    // Spawned from `den <profile> --autostart`, SIGINT/SIGTERM arrive
    // SIG_IGN (inherited from `den run`): keep the INT-ignore so the stream
    // survives Ctrl-C on the run, but restore TERM so `kill` can stop us.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = libc::SIG_DFL;
    unsafe {
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    let _lock = lock_watch(sid)?;
    let mut watch = Watch {
        sid: sid.to_string(),
        out: out.to_path_buf(),
        compress,
        n: 0,
        state: db_state(&db)?,
    };
    // resume an existing chain from its newest file
    while chain_path(out, watch.n + 1).exists() {
        watch.n += 1;
    }
    if watch.n == 0 {
        // fresh chain: initial snapshot (retry while the writer is mid-commit)
        loop {
            if cmd_backup_inner(sid, None, out, compress, false)? {
                break;
            }
            std::thread::sleep(WATCH_POLL);
        }
    } else {
        eprintln!(
            "den: resuming chain at {}",
            chain_path(out, watch.n).display()
        );
    }
    watch.state = db_state(&db)?;
    loop {
        std::thread::sleep(WATCH_POLL);
        watch.tick()?;
    }
}

/// Full snapshot (txid 1): every page 1..=commit, nothing else.
fn write_snapshot(
    f: &mut File,
    out: &Path,
    ps: u32,
    commit: u32,
    compress: bool,
) -> Result<(Header, u32, Checksum)> {
    let header = Header {
        flags: if compress {
            HeaderFlags::COMPRESS_LZ4
        } else {
            HeaderFlags::empty()
        },
        page_size: PageSize::new(ps)?,
        commit: PageNum::new(commit)?,
        min_txid: TXID::ONE,
        max_txid: TXID::ONE,
        timestamp: SystemTime::now(),
        pre_apply_checksum: None,
    };
    let mut out_f = File::create(out).with_context(|| format!("create {}", out.display()))?;
    let mut enc = Encoder::new(&mut out_f, &header)?;

    let mut n_pages = 0u32;
    let mut post_apply = Checksum::new(0);
    for pgno in 1..=commit {
        let page = read_page(f, pgno, ps)?;
        post_apply = post_apply ^ page.page_checksum(PageNum::new(pgno)?);
        enc.encode_page(PageNum::new(pgno)?, &page)?;
        n_pages += 1;
    }
    enc.finish(post_apply)?;
    out_f.sync_all()?;
    Ok((header, n_pages, post_apply))
}

/// Delta (txid prev+1): only pages whose checksum changed since the previous
/// file in the chain — a snapshot or another delta — with that file's
/// post-apply checksum as pre-apply, so a delta only applies on top of exactly
/// the preceding stream state.
fn write_delta(
    f: &mut File,
    out: &Path,
    ps: u32,
    commit: u32,
    compress: bool,
    prev_path: &Path,
) -> Result<(Header, u32, Checksum)> {
    let (ph, ppages, ptrailer) = read_ltx(prev_path)?;
    let prev_checksums: HashMap<u32, Checksum> = ppages
        .iter()
        .map(|(pgno, data)| {
            (
                *pgno,
                data.page_checksum(PageNum::new(*pgno).expect("pgno > 0")),
            )
        })
        .collect();

    let header = Header {
        flags: if compress {
            HeaderFlags::COMPRESS_LZ4
        } else {
            HeaderFlags::empty()
        },
        page_size: PageSize::new(ps)?,
        commit: PageNum::new(commit)?,
        min_txid: ph.max_txid + 1,
        max_txid: ph.max_txid + 1,
        timestamp: SystemTime::now(),
        pre_apply_checksum: Some(ptrailer.post_apply_checksum),
    };
    let mut out_f = File::create(out).with_context(|| format!("create {}", out.display()))?;
    let mut enc = Encoder::new(&mut out_f, &header)?;

    let mut n_pages = 0u32;
    let mut post_apply = Checksum::new(0);
    for pgno in 1..=commit {
        let page = read_page(f, pgno, ps)?;
        let pg_checksum = page.page_checksum(PageNum::new(pgno)?);
        post_apply = post_apply ^ pg_checksum;
        if prev_checksums.get(&pgno) == Some(&pg_checksum) {
            continue; // unchanged since the base snapshot
        }
        enc.encode_page(PageNum::new(pgno)?, &page)?;
        n_pages += 1;
    }
    enc.finish(post_apply)?;
    out_f.sync_all()?;
    Ok((header, n_pages, post_apply))
}

/// `den restore <file.ltx> [--to <db>]` — target defaults to the session
/// named by the file (codex-foo.ltx -> ~/.den/sessions/codex-foo/fs.db).
pub fn cmd_restore(ltx: &Path, to: &Path) -> Result<()> {
    let (header, pages, trailer) = read_ltx(ltx)?;
    if is_snapshot(&header) {
        restore_snapshot(to, &header, &pages, &trailer)?;
    } else {
        restore_delta(to, &header, &pages, &trailer)?;
    }
    integrity_check(to)?;
    println!(
        "den: restored {} -> {} (txid {}-{}, post-apply checksum {})",
        ltx.display(),
        to.display(),
        header.min_txid,
        header.max_txid,
        trailer.post_apply_checksum
    );
    Ok(())
}

/// Full snapshot: write a fresh DB from the page set; drop stale WAL siblings
/// that belonged to whatever main file was there before.
fn restore_snapshot(
    to: &Path,
    header: &Header,
    pages: &HashMap<u32, Vec<u8>>,
    trailer: &Trailer,
) -> Result<()> {
    let ps = header.page_size.into_inner();
    let commit = header.commit.into_inner();
    prepare_db(to, true)?; // may be a live DB — strict is right before we destroy it
    for side in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{side}", to.display()));
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(to).with_context(|| format!("create {}", to.display()))?;
    f.set_len(commit as u64 * ps as u64)?;
    let mut post_apply = Checksum::new(0);
    for pgno in 1..=commit {
        let page = pages
            .get(&pgno)
            .ok_or_else(|| anyhow!("snapshot missing page {pgno}"))?;
        post_apply = post_apply ^ page.page_checksum(PageNum::new(pgno)?);
        f.seek(SeekFrom::Start((pgno - 1) as u64 * ps as u64))?;
        f.write_all(page)?;
    }
    f.sync_all()?;
    if post_apply != trailer.post_apply_checksum {
        bail!(
            "post-apply checksum mismatch after restore (expected {}, got {})",
            trailer.post_apply_checksum,
            post_apply
        );
    }
    Ok(())
}

/// Delta: apply the changed pages onto an existing DB whose checksum matches
/// the pre-apply checksum.
fn restore_delta(
    to: &Path,
    header: &Header,
    pages: &HashMap<u32, Vec<u8>>,
    trailer: &Trailer,
) -> Result<()> {
    let ps = header.page_size.into_inner();
    let commit = header.commit.into_inner();
    if !to.exists() {
        bail!(
            "delta restore needs an existing target DB ({}); restore the base snapshot first",
            to.display()
        );
    }
    prepare_db(to, true)?;
    let (tps, tcount) = sqlite_header(to)?;
    if tps != ps {
        bail!(
            "target page size {tps} != backup page size {ps} at {}",
            to.display()
        );
    }
    let pre = db_checksum(to, tps, tcount)?;
    let expected = header
        .pre_apply_checksum
        .context("non-snapshot without pre-apply checksum")?;
    if pre != expected {
        bail!(
            "pre-apply checksum mismatch on {} (expected {expected}, got {pre}) — restore the base snapshot first",
            to.display()
        );
    }
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(to)
        .with_context(|| format!("open {}", to.display()))?;
    for (pgno, page) in pages {
        f.seek(SeekFrom::Start((pgno - 1) as u64 * ps as u64))?;
        f.write_all(page)?;
    }
    // the DB may have grown (or shrunk) — resize and restate the page count
    f.set_len(commit as u64 * ps as u64)?;
    let mut p1 = read_page(&mut f, 1, ps)?;
    p1[28..32].copy_from_slice(&commit.to_be_bytes());
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&p1)?;
    f.sync_all()?;
    let post = db_checksum(to, ps, commit)?;
    if post != trailer.post_apply_checksum {
        bail!(
            "post-apply checksum mismatch after restore (expected {}, got {})",
            trailer.post_apply_checksum,
            post
        );
    }
    Ok(())
}

/// `den ltx <file.ltx>` — inspect and verify a backup file.
pub fn cmd_ltx_info(path: &Path) -> Result<()> {
    let (header, pages, trailer) = read_ltx(path)?; // verifies the file checksum
    let size = std::fs::metadata(path)?.len();
    let kind = if is_snapshot(&header) {
        "snapshot"
    } else {
        "delta"
    };
    println!("file: {} ({size} bytes)", path.display());
    println!(
        "  {kind}: page size {}, commit {} pages, txid {} -> {}, flags {:#x}",
        header.page_size.into_inner(),
        header.commit.into_inner(),
        header.min_txid,
        header.max_txid,
        header.flags.bits()
    );
    println!(
        "  pre-apply checksum: {}",
        header
            .pre_apply_checksum
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(none)".into())
    );
    println!("  post-apply checksum: {}", trailer.post_apply_checksum);
    println!("  file checksum: {} (verified)", trailer.file_checksum);
    let mut pgnos: Vec<u32> = pages.keys().copied().collect();
    pgnos.sort_unstable();
    if let (Some(first), Some(last)) = (pgnos.first(), pgnos.last()) {
        println!("  {} pages: {first}..={last}", pgnos.len());
    }
    Ok(())
}

/// PRAGMA integrity_check via rusqlite — a new dependency (agentfs-sdk uses
/// `turso`, not rusqlite); it earns its keep because `prepare_db`'s
/// wal_checkpoint and this B-tree check both need real SQLite in-process.
/// Opens read-only so we can never touch a live DB.
fn integrity_check(path: &Path) -> Result<()> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let s: String = row.get(0)?;
        if s != "ok" {
            bail!("integrity check failed: {s}");
        }
    }
    Ok(())
}

/// Default restore target: codex-foo.ltx -> ~/.den/sessions/codex-foo/fs.db.
/// Chain deltas are numbered codex-foo.NNNN.ltx; strip the number so a
/// numbered file still resolves to the session it belongs to (session ids
/// never contain '.', so the suffix is unambiguous).
pub fn default_restore_target(ltx: &Path) -> Result<PathBuf> {
    let stem = ltx
        .file_stem()
        .context("backup file has no name")?
        .to_string_lossy();
    let sid = match stem.rsplit_once('.') {
        Some((base, n)) if n.chars().all(|c| c.is_ascii_digit()) && n.len() >= 4 => base,
        _ => &stem,
    }
    .to_string();
    let db = crate::session_db_path(&sid)?;
    if !db.exists() {
        bail!(
            "no session '{sid}' at {} (pass --to <db-path>)",
            db.display()
        );
    }
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfs_sdk::{AgentFS, AgentFSOptions, DEFAULT_FILE_MODE};
    use std::sync::Mutex;

    /// HOME is process-global; serialize the tests that swap it.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    struct TestHome {
        _guard: std::sync::MutexGuard<'static, ()>,
        dir: TempDir,
    }

    // tiny tempdir helper (no extra dep): unique dir under std::env::temp_dir()
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "den-test-{}-{:x}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn with_home() -> TestHome {
        let guard = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new();
        let home = dir.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        TestHome { _guard: guard, dir }
    }

    /// Build a fake session fs.db via the agentfs SDK (like examples/mkdelta.rs).
    fn build_session(sid: &str, base: &str) {
        std::fs::create_dir_all(base).unwrap();
        let db = crate::session_db_path(sid).unwrap();
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        let db = db.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&db);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let agent = AgentFS::open(AgentFSOptions::with_path(&db).with_base(base))
                .await
                .unwrap();
            agent
                .fs
                .create_file("/hello.txt", DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            agent.fs.mkdir("/out", 0, 0).await.unwrap();
            let conn = agent.get_connection().await.unwrap();
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            conn.execute(
                "INSERT INTO fs_whiteout (path, created_at) VALUES (?, ?)",
                ("README.md", now),
            )
            .await
            .unwrap();
            drop(conn);
            drop(agent);
        });
    }

    /// Reopen a session's DB and add one file (mutates the fs.db).
    fn mutate_session(sid: &str, base: &str, name: &str) {
        std::fs::create_dir_all(base).unwrap();
        let db = crate::session_db_path(sid)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let agent = AgentFS::open(AgentFSOptions::with_path(&db).with_base(base))
                .await
                .unwrap();
            agent
                .fs
                .create_file(name, DEFAULT_FILE_MODE, 0, 0)
                .await
                .unwrap();
            drop(agent);
        });
    }

    fn db_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    #[test]
    fn backup_snapshot_restore_roundtrip() {
        let home = with_home();
        let sid = "test-proj";
        build_session(sid, home.dir.0.join("base").to_str().unwrap());

        let out = home.dir.0.join("test-proj.ltx");
        cmd_backup(sid, None, &out, false).unwrap();

        // the snapshot restores byte-identically
        let restored = home.dir.0.join("restored.db");
        cmd_restore(&out, &restored).unwrap();
        assert_eq!(
            db_bytes(&restored),
            db_bytes(&crate::session_db_path(sid).unwrap())
        );
    }

    #[test]
    fn backup_delta_after_snapshot() {
        let home = with_home();
        let sid = "test-proj";
        let base = home.dir.0.join("base");
        build_session(sid, base.to_str().unwrap());

        let snap = home.dir.0.join("test-proj.ltx");
        cmd_backup(sid, None, &snap, false).unwrap();

        // mutate the session (add another file), then take a delta from the snapshot
        mutate_session(sid, base.to_str().unwrap(), "/new.txt");
        let delta = home.dir.0.join("test-proj-delta.ltx");
        cmd_backup(sid, Some(&snap), &delta, false).unwrap();

        // delta: txid 2, pre-apply == snapshot's post-apply, only changed pages
        let (header, pages, _trailer) = read_ltx(&delta).unwrap();
        assert_eq!(header.min_txid.into_inner(), 2);
        assert_eq!(header.max_txid.into_inner(), 2);
        let (_, _, snap_trailer) = read_ltx(&snap).unwrap();
        assert_eq!(
            header.pre_apply_checksum.unwrap(),
            snap_trailer.post_apply_checksum
        );
        assert!(!pages.is_empty());

        // snapshot restore + delta apply == the final DB, byte for byte
        let restored = home.dir.0.join("restored.db");
        cmd_restore(&snap, &restored).unwrap();
        cmd_restore(&delta, &restored).unwrap();
        let final_db = crate::session_db_path(sid).unwrap();
        assert_eq!(db_bytes(&restored), db_bytes(&final_db));
    }

    #[test]
    fn ltx_info_verifies() {
        let home = with_home();
        let sid = "test-proj";
        build_session(sid, home.dir.0.join("base").to_str().unwrap());
        let out = home.dir.0.join("test-proj.ltx");
        cmd_backup(sid, None, &out, true).unwrap(); // compressed
                                                    // decoding verifies the file checksum — no panic/err means it's valid
        cmd_ltx_info(&out).unwrap();
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let home = with_home();
        let sid = "test-proj";
        build_session(sid, home.dir.0.join("base").to_str().unwrap());
        let snap = home.dir.0.join("test-proj.ltx");
        cmd_backup(sid, None, &snap, false).unwrap();

        // mutate the session DB (new file), then try restoring the old snapshot's
        // delta onto a *different* base: pre-apply must fail
        mutate_session(sid, home.dir.0.join("base2").to_str().unwrap(), "/x.txt");
        let delta = home.dir.0.join("d.ltx");
        cmd_backup(sid, Some(&snap), &delta, false).unwrap();

        // target a fresh copy of the original snapshot state -> pre-apply mismatch
        let fresh = home.dir.0.join("fresh.db");
        cmd_restore(&snap, &fresh).unwrap();
        let mut bytes = std::fs::read(&fresh).unwrap();
        bytes[0] ^= 0xff; // corrupt the target so its checksum no longer matches
        std::fs::write(&fresh, bytes).unwrap();
        assert!(cmd_restore(&delta, &fresh).is_err());
    }

    #[test]
    fn lock_page_db_is_refused() {
        let home = with_home();
        let sid = "test-proj";
        build_session(sid, home.dir.0.join("base").to_str().unwrap());

        // patch the header page count so the lock-byte page (which LTX never
        // stores) falls inside the DB; the guard must refuse before any page
        // is read or the out file is created
        let db = crate::session_db_path(sid).unwrap();
        for side in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{side}", db.display()));
        }
        let (ps, _) = sqlite_header(&db).unwrap();
        let lock = PageNum::lock_page(PageSize::new(ps).unwrap()).into_inner();
        let mut bytes = std::fs::read(&db).unwrap();
        bytes[28..32].copy_from_slice(&lock.to_be_bytes());
        std::fs::write(&db, bytes).unwrap();

        let out = home.dir.0.join("too-big.ltx");
        let err = cmd_backup(sid, None, &out, false).unwrap_err().to_string();
        assert!(err.contains("lock-byte"), "unexpected error: {err}");
        assert!(!out.exists());
    }

    #[test]
    fn chained_deltas_restore_in_order() {
        let home = with_home();
        let sid = "test-proj";
        let base = home.dir.0.join("base");
        build_session(sid, base.to_str().unwrap());

        let snap = home.dir.0.join("s.ltx");
        cmd_backup(sid, None, &snap, false).unwrap();

        mutate_session(sid, base.to_str().unwrap(), "/a.txt");
        let d1 = chain_path(&snap, 1);
        cmd_backup(sid, Some(&snap), &d1, false).unwrap();

        mutate_session(sid, base.to_str().unwrap(), "/b.txt");
        let d2 = chain_path(&snap, 2);
        cmd_backup(sid, Some(&d1), &d2, false).unwrap();

        // delta-on-delta: d2's pre-apply is d1's post-apply, txid 3
        let (h2, _, _) = read_ltx(&d2).unwrap();
        let (_, _, t1) = read_ltx(&d1).unwrap();
        assert_eq!(h2.min_txid.into_inner(), 3);
        assert_eq!(h2.pre_apply_checksum.unwrap(), t1.post_apply_checksum);

        // snapshot + deltas replay to the final DB, byte for byte
        let restored = home.dir.0.join("restored.db");
        cmd_restore(&snap, &restored).unwrap();
        cmd_restore(&d1, &restored).unwrap();
        cmd_restore(&d2, &restored).unwrap();
        let final_db = crate::session_db_path(sid).unwrap();
        assert_eq!(db_bytes(&restored), db_bytes(&final_db));
    }

    #[test]
    fn watch_appends_deltas_on_change() {
        let home = with_home();
        let sid = "test-proj";
        let base = home.dir.0.join("base");
        build_session(sid, base.to_str().unwrap());
        let db = crate::session_db_path(sid).unwrap();

        let out = home.dir.0.join("w.ltx");
        cmd_backup(sid, None, &out, false).unwrap(); // initial snapshot
        let mut watch = Watch {
            sid: sid.into(),
            out: out.clone(),
            compress: false,
            n: 0,
            state: db_state(&db).unwrap(),
        };

        // no change -> no new file
        watch.tick().unwrap();
        assert!(!chain_path(&out, 1).exists());

        // one mutation -> one delta; another -> a second, chained delta
        mutate_session(sid, base.to_str().unwrap(), "/c.txt");
        watch.tick().unwrap();
        assert!(chain_path(&out, 1).exists());
        mutate_session(sid, base.to_str().unwrap(), "/d.txt");
        watch.tick().unwrap();
        assert!(chain_path(&out, 2).exists());

        // the chain replays to the final state, byte for byte
        let restored = home.dir.0.join("restored.db");
        cmd_restore(&out, &restored).unwrap();
        cmd_restore(&chain_path(&out, 1), &restored).unwrap();
        cmd_restore(&chain_path(&out, 2), &restored).unwrap();
        let final_db = crate::session_db_path(sid).unwrap();
        assert_eq!(db_bytes(&restored), db_bytes(&final_db));
    }

    #[test]
    fn chain_indices_detect_gaps() {
        let dir = TempDir::new();
        let base = dir.0.join("s.ltx");
        std::fs::write(&base, "x").unwrap();
        std::fs::write(dir.0.join("s.0001.ltx"), "x").unwrap();
        std::fs::write(dir.0.join("s.0002.ltx"), "x").unwrap();
        std::fs::write(dir.0.join("s.0003.ltx"), "x").unwrap();
        // different base or extension: ignored
        std::fs::write(dir.0.join("other.0001.ltx"), "x").unwrap();
        std::fs::write(dir.0.join("s.0001.txt"), "x").unwrap();
        assert_eq!(existing_chain_indices(&base).unwrap(), vec![1, 2, 3]);

        // a missing middle link is a gap, not an end of chain
        std::fs::remove_file(dir.0.join("s.0002.ltx")).unwrap();
        let err = existing_chain_indices(&base).unwrap_err().to_string();
        assert!(err.contains("gap"), "unexpected error: {err}");
    }

    #[test]
    fn watch_lock_excludes_duplicate() {
        let home = with_home();
        let sid = "test-proj";
        build_session(sid, home.dir.0.join("base").to_str().unwrap());

        let l1 = lock_watch(sid).unwrap();
        let err = lock_watch(sid).unwrap_err().to_string();
        assert!(err.contains("already streaming"), "unexpected error: {err}");
        drop(l1);
        lock_watch(sid).unwrap(); // released with the process -> reacquirable
    }
}
