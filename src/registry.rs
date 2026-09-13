//! platform.db — the run registry (bookkeeping only; fs.db is the truth).
//!
//! One SQLite DB under the den state dir tracking platform sessions and
//! turn runs (docs/platform-api.md §6). Every row is rebuildable by
//! scanning ~/.den/sessions, so deleting this DB loses bookkeeping, never
//! agent work. Sync rusqlite behind a Mutex; serve calls it from
//! spawn_blocking (registry methods are deliberately blocking-simple).

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Session lifecycle: `idle` (reserved, no run yet) -> `running` (live
/// child) -> `exited` | `failed`; daemon kind uses `attached` for a live
/// client-facing daemon (idle between attach calls is still `attached` —
/// the child is what matters); `orphaned` after a serve crash, until the
/// boot reconcile decides (relaunch, exited, or failed).
pub const S_IDLE: &str = "idle";
pub const S_RUNNING: &str = "running";
pub const S_ATTACHED: &str = "attached";
pub const S_EXITED: &str = "exited";
pub const S_FAILED: &str = "failed";
#[allow(dead_code)] // boot reconcile marks orphaned sessions in Phase 2
pub const S_ORPHANED: &str = "orphaned";

/// Run lifecycle (turn kind only — dex tracks its own turns):
/// `queued` -> `running` -> `exited` (0) | `failed` (!=0) | `killed`;
/// `orphaned` when serve died mid-run.
pub const R_QUEUED: &str = "queued";
pub const R_RUNNING: &str = "running";
pub const R_EXITED: &str = "exited";
pub const R_FAILED: &str = "failed";
pub const R_KILLED: &str = "killed";
#[allow(dead_code)] // asserted in tests; Phase 2 boot reconcile sets it too
pub const R_ORPHANED: &str = "orphaned";

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRow {
    pub sid: String,
    pub kind: String,
    pub profile: String,
    pub seed_json: Option<String>,
    pub status: String,
    pub owner: Option<String>,
    pub attach_port: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunRow {
    pub id: String,
    pub sid: String,
    pub profile: String,
    pub prompt: Option<String>,
    pub argv_json: Option<String>,
    pub status: String,
    pub exit_code: Option<i64>,
    pub pid: Option<i64>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub delta_json: Option<String>,
    pub log_path: Option<String>,
}

pub struct NewSession {
    pub sid: String,
    pub kind: String, // turn | daemon
    pub profile: String,
    pub seed_json: Option<String>,
    pub owner: Option<String>,
}

pub struct NewRun {
    pub id: String,
    pub sid: String,
    pub profile: String,
    pub prompt: Option<String>,
    pub argv_json: Option<String>,
}

/// Registry handle. Cheap to clone is not needed — one per serve process.
pub struct Registry {
    conn: Mutex<Connection>,
}

impl Registry {
    /// Open (creating on first use) the platform DB. WAL + busy timeout:
    /// serve writes from multiple blocking tasks; runs/sessions tables are
    /// tiny, so contention is nil — the timeout is belt-and-braces.
    pub fn open(path: &Path) -> Result<Registry> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)
                .with_context(|| format!("create platform db dir {}", p.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS sessions (
               sid TEXT PRIMARY KEY,
               kind TEXT NOT NULL CHECK (kind IN ('turn','daemon')),
               profile TEXT NOT NULL,
               seed_json TEXT,
               status TEXT NOT NULL,
               owner TEXT,
               attach_port INTEGER,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS runs (
               id TEXT PRIMARY KEY,
               sid TEXT NOT NULL REFERENCES sessions(sid),
               profile TEXT NOT NULL,
               prompt TEXT,
               argv_json TEXT,
               status TEXT NOT NULL,
               exit_code INTEGER,
               pid INTEGER,
               started_at INTEGER,
               finished_at INTEGER,
               delta_json TEXT,
               log_path TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_runs_sid ON runs(sid);
             CREATE TABLE IF NOT EXISTS keys (
               key_hash TEXT PRIMARY KEY,
               key_id TEXT UNIQUE NOT NULL,
               owner TEXT NOT NULL,
               name TEXT,
               max_concurrent INTEGER,
               created_at INTEGER NOT NULL,
               revoked_at INTEGER
             );",
        )?;
        Ok(Registry {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A poisoned registry mutex means a write panicked mid-statement —
        // SQLite is transactional per statement, so the DB is intact; the
        // panic is the bug to surface, not state to recover around.
        self.conn.lock().expect("platform registry poisoned")
    }

    // ---- sessions ----

    pub fn create_session(&self, s: &NewSession) -> Result<()> {
        let kind_ok = matches!(s.kind.as_str(), "turn" | "daemon");
        if !kind_ok {
            bail!("unknown session kind '{}' (turn|daemon)", s.kind);
        }
        let now = unix_now();
        self.conn()
            .execute(
                "INSERT INTO sessions (sid, kind, profile, seed_json, status, owner,
                                       created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![s.sid, s.kind, s.profile, s.seed_json, S_IDLE, s.owner, now,],
            )
            .with_context(|| format!("create session {}", s.sid))?;
        Ok(())
    }

    pub fn get_session(&self, sid: &str) -> Result<Option<SessionRow>> {
        self.conn()
            .query_row(
                "SELECT sid, kind, profile, seed_json, status, owner, attach_port,
                        created_at, updated_at
                 FROM sessions WHERE sid = ?1",
                params![sid],
                row_session,
            )
            .optional()
            .context("read session")
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRow>> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT sid, kind, profile, seed_json, status, owner, attach_port,
                        created_at, updated_at
                 FROM sessions ORDER BY updated_at DESC, sid",
            )
            .context("list sessions")?;
        let rows = st
            .query_map([], row_session)
            .context("list sessions")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("list sessions")?;
        Ok(rows)
    }

    pub fn set_session_status(&self, sid: &str, status: &str) -> Result<()> {
        let n = self
            .conn()
            .execute(
                "UPDATE sessions SET status = ?2, updated_at = ?3 WHERE sid = ?1",
                params![sid, status, unix_now()],
            )
            .context("update session status")?;
        if n == 0 {
            bail!("no session {sid}");
        }
        Ok(())
    }

    #[allow(dead_code)] // daemon sessions record their host port in Phase 2
    pub fn set_attach_port(&self, sid: &str, port: i64) -> Result<()> {
        let n = self
            .conn()
            .execute(
                "UPDATE sessions SET attach_port = ?2, updated_at = ?3 WHERE sid = ?1",
                params![sid, port, unix_now()],
            )
            .context("update attach port")?;
        if n == 0 {
            bail!("no session {sid}");
        }
        Ok(())
    }

    pub fn delete_session(&self, sid: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM runs WHERE sid = ?1", params![sid])
            .context("delete runs")?;
        let n = conn
            .execute("DELETE FROM sessions WHERE sid = ?1", params![sid])
            .context("delete session")?;
        if n == 0 {
            bail!("no session {sid}");
        }
        Ok(())
    }

    // ---- runs (turn kind) ----

    pub fn insert_run(&self, r: &NewRun, status: &str, log_path: Option<&str>) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO runs (id, sid, profile, prompt, argv_json, status, log_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    r.id,
                    r.sid,
                    r.profile,
                    r.prompt,
                    r.argv_json,
                    status,
                    log_path
                ],
            )
            .with_context(|| format!("insert run {}", r.id))?;
        Ok(())
    }

    pub fn set_run_pid(&self, id: &str, pid: i32) -> Result<()> {
        let n = self
            .conn()
            .execute(
                "UPDATE runs SET pid = ?2, started_at = ?3, status = 'running' WHERE id = ?1",
                params![id, pid, unix_now()],
            )
            .context("set run pid")?;
        if n == 0 {
            bail!("no run {id}");
        }
        Ok(())
    }

    /// Terminal transition: status becomes exited/failed/killed/orphaned,
    /// exit code and delta snapshot stored alongside.
    pub fn finish_run(
        &self,
        id: &str,
        status: &str,
        exit_code: Option<i64>,
        delta_json: Option<&str>,
    ) -> Result<()> {
        let n = self
            .conn()
            .execute(
                "UPDATE runs SET status = ?2, exit_code = ?3, delta_json = ?4,
                                 finished_at = ?5
                 WHERE id = ?1",
                params![id, status, exit_code, delta_json, unix_now()],
            )
            .context("finish run")?;
        if n == 0 {
            bail!("no run {id}");
        }
        Ok(())
    }

    pub fn get_run(&self, id: &str) -> Result<Option<RunRow>> {
        self.conn()
            .query_row(
                "SELECT id, sid, profile, prompt, argv_json, status, exit_code, pid,
                        started_at, finished_at, delta_json, log_path
                 FROM runs WHERE id = ?1",
                params![id],
                row_run,
            )
            .optional()
            .context("read run")
    }

    pub fn list_runs(&self, sid: &str) -> Result<Vec<RunRow>> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT id, sid, profile, prompt, argv_json, status, exit_code, pid,
                        started_at, finished_at, delta_json, log_path
                 FROM runs WHERE sid = ?1 ORDER BY started_at, id",
            )
            .context("list runs")?;
        let rows = st
            .query_map(params![sid], row_run)
            .context("list runs")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("list runs")?;
        Ok(rows)
    }

    /// Boot sweep: serve's children died with it (or reparented to init)
    /// — every `running` row from a previous serve can no longer be
    /// observed, so mark them all `orphaned`. A live orphan child still
    /// holds the session flock, so the session stays busy until it exits.
    /// Returns how many rows moved.
    pub fn sweep_orphans(&self) -> Result<usize> {
        let conn = self.conn();
        let now = unix_now();
        let moved = conn
            .execute(
                "UPDATE runs SET status = 'orphaned', finished_at = ?1
                 WHERE status = 'running'",
                params![now],
            )
            .context("sweep: mark orphans")?;
        Ok(moved)
    }
}

fn row_session(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        sid: r.get(0)?,
        kind: r.get(1)?,
        profile: r.get(2)?,
        seed_json: r.get(3)?,
        status: r.get(4)?,
        owner: r.get(5)?,
        attach_port: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
    })
}

fn row_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        id: r.get(0)?,
        sid: r.get(1)?,
        profile: r.get(2)?,
        prompt: r.get(3)?,
        argv_json: r.get(4)?,
        status: r.get(5)?,
        exit_code: r.get(6)?,
        pid: r.get(7)?,
        started_at: r.get(8)?,
        finished_at: r.get(9)?,
        delta_json: r.get(10)?,
        log_path: r.get(11)?,
    })
}

/// A minted platform API key. Only the sha256 lives here; the raw
/// "dk_…" is shown exactly once at mint time.
#[derive(Clone, Debug, Serialize)]
pub struct KeyRow {
    pub key_id: String,
    pub owner: String,
    pub name: Option<String>,
    pub max_concurrent: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

pub struct NewKey {
    pub key_hash: String,
    pub key_id: String,
    pub owner: String,
    pub name: Option<String>,
    pub max_concurrent: Option<i64>,
}

fn row_key(r: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRow> {
    Ok(KeyRow {
        key_id: r.get(0)?,
        owner: r.get(1)?,
        name: r.get(2)?,
        max_concurrent: r.get(3)?,
        created_at: r.get(4)?,
        revoked_at: r.get(5)?,
    })
}

impl Registry {
    // ---- keys (platform auth; raw "dk_…" never stored) ----

    pub fn create_key(&self, k: &NewKey) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO keys (key_hash, key_id, owner, name, max_concurrent, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    k.key_hash,
                    k.key_id,
                    k.owner,
                    k.name,
                    k.max_concurrent,
                    unix_now()
                ],
            )
            .with_context(|| format!("create key {}", k.key_id))?;
        Ok(())
    }

    /// The live key for a presented bearer token (by hash), or None.
    pub fn find_key(&self, key_hash: &str) -> Result<Option<KeyRow>> {
        self.conn()
            .query_row(
                "SELECT key_id, owner, name, max_concurrent, created_at, revoked_at
                 FROM keys WHERE key_hash = ?1",
                params![key_hash],
                row_key,
            )
            .optional()
            .context("find key")
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT key_id, owner, name, max_concurrent, created_at, revoked_at
                 FROM keys ORDER BY created_at DESC, key_id",
            )
            .context("list keys")?;
        let rows = st
            .query_map([], row_key)
            .context("list keys")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("list keys")?;
        Ok(rows)
    }

    pub fn revoke_key(&self, key_id: &str) -> Result<()> {
        let n = self
            .conn()
            .execute(
                "UPDATE keys SET revoked_at = ?2 WHERE key_id = ?1 AND revoked_at IS NULL",
                params![key_id, unix_now()],
            )
            .context("revoke key")?;
        if n == 0 {
            bail!("no live key {key_id}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Result<TempDir> {
            let d = std::env::temp_dir()
                .join(format!("den-registry-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d)?;
            Ok(TempDir(d))
        }
        fn db(&self) -> Registry {
            Registry::open(&self.0.join("platform.db")).unwrap()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    use std::path::PathBuf;

    fn sess(sid: &str) -> NewSession {
        NewSession {
            sid: sid.into(),
            kind: "turn".into(),
            profile: "codex".into(),
            seed_json: None,
            owner: None,
        }
    }

    #[test]
    fn session_crud_roundtrip() {
        let t = TempDir::new("crud").unwrap();
        let db = t.db();
        db.create_session(&sess("s1")).unwrap();
        db.create_session(&sess("s2")).unwrap();
        // duplicate sid is an error (PRIMARY KEY)
        assert!(db.create_session(&sess("s1")).is_err());
        let got = db.get_session("s1").unwrap().unwrap();
        assert_eq!(got.status, S_IDLE);
        assert_eq!(got.kind, "turn");
        assert!(db.get_session("missing").unwrap().is_none());
        assert_eq!(db.list_sessions().unwrap().len(), 2);
        db.set_session_status("s1", S_EXITED).unwrap();
        assert_eq!(db.get_session("s1").unwrap().unwrap().status, S_EXITED);
        db.set_attach_port("s2", 40011).unwrap();
        assert_eq!(
            db.get_session("s2").unwrap().unwrap().attach_port,
            Some(40011)
        );
        db.delete_session("s1").unwrap();
        assert!(db.get_session("s1").unwrap().is_none());
        assert!(db.set_session_status("s1", S_IDLE).is_err());
    }

    #[test]
    fn session_kind_is_checked() {
        let t = TempDir::new("kind").unwrap();
        let db = t.db();
        let bad = NewSession {
            kind: "wat".into(),
            ..sess("s3")
        };
        assert!(db.create_session(&bad).is_err());
    }

    #[test]
    fn run_lifecycle() {
        let t = TempDir::new("runs").unwrap();
        let db = t.db();
        db.create_session(&sess("s1")).unwrap();
        let r = NewRun {
            id: "r-aaaaa".into(),
            sid: "s1".into(),
            profile: "codex".into(),
            prompt: Some("touch /hello.txt".into()),
            argv_json: Some(r#"[\"codex\",\"exec\"]"#.into()),
        };
        db.insert_run(&r, R_QUEUED, Some("/sessions/s1/runs/r-aaaaa.log"))
            .unwrap();
        assert_eq!(db.get_run("r-aaaaa").unwrap().unwrap().status, R_QUEUED);
        db.set_run_pid("r-aaaaa", 4242).unwrap();
        let running = db.get_run("r-aaaaa").unwrap().unwrap();
        assert_eq!(running.status, R_RUNNING);
        assert_eq!(running.pid, Some(4242));
        db.finish_run(
            "r-aaaaa",
            R_EXITED,
            Some(0),
            Some(r#"{"added":["/hello.txt"]}"#),
        )
        .unwrap();
        let done = db.get_run("r-aaaaa").unwrap().unwrap();
        assert_eq!(done.status, R_EXITED);
        assert_eq!(done.exit_code, Some(0));
        assert_eq!(
            done.delta_json.as_deref(),
            Some(r#"{"added":["/hello.txt"]}"#)
        );
        assert!(done.finished_at.is_some());
        assert_eq!(db.list_runs("s1").unwrap().len(), 1);
        assert!(db.finish_run("missing", R_EXITED, None, None).is_err());
    }

    #[test]
    fn run_requires_existing_session() {
        let t = TempDir::new("fk").unwrap();
        let db = t.db();
        let r = NewRun {
            id: "r-bbbbb".into(),
            sid: "ghost".into(),
            profile: "codex".into(),
            prompt: None,
            argv_json: None,
        };
        assert!(db.insert_run(&r, R_QUEUED, None).is_err());
    }

    #[test]
    fn key_lifecycle() {
        let t = TempDir::new("keys").unwrap();
        let db = t.db();
        let k = NewKey {
            key_hash: "h1".into(),
            key_id: "id1".into(),
            owner: "ci".into(),
            name: Some("ci-bot".into()),
            max_concurrent: Some(2),
        };
        db.create_key(&k).unwrap();
        let found = db.find_key("h1").unwrap().unwrap();
        assert_eq!(found.owner, "ci");
        assert_eq!(found.max_concurrent, Some(2));
        assert!(found.revoked_at.is_none());
        assert!(db.find_key("nope").unwrap().is_none());
        assert_eq!(db.list_keys().unwrap().len(), 1);
        db.revoke_key("id1").unwrap();
        assert!(db.find_key("h1").unwrap().unwrap().revoked_at.is_some());
        // revoked key still findable by hash (caller rejects revoked), but
        // revoking again is a no-op error (already revoked)
        assert!(db.revoke_key("id1").is_err());
        // minting the same hash twice fails (PRIMARY KEY)
        assert!(db.create_key(&k).is_err());
    }

    #[test]
    fn orphan_sweep_marks_all_running_rows() {
        let t = TempDir::new("sweep").unwrap();
        let db = t.db();
        db.create_session(&sess("s1")).unwrap();
        for (id, pid) in [("r-live", Some(7)), ("r-nopid", None)] {
            let r = NewRun {
                id: id.into(),
                sid: "s1".into(),
                profile: "codex".into(),
                prompt: None,
                argv_json: None,
            };
            db.insert_run(&r, R_QUEUED, None).unwrap();
            if let Some(p) = pid {
                db.set_run_pid(id, p).unwrap();
            }
        }
        // a finished row must survive the sweep untouched
        db.finish_run("r-nopid", R_EXITED, Some(0), None).unwrap();
        let moved = db.sweep_orphans().unwrap();
        assert_eq!(moved, 1); // only r-live (the running one)
        assert_eq!(db.get_run("r-live").unwrap().unwrap().status, R_ORPHANED);
        assert!(db.get_run("r-live").unwrap().unwrap().finished_at.is_some());
        assert_eq!(db.get_run("r-nopid").unwrap().unwrap().status, R_EXITED);
        assert_eq!(db.sweep_orphans().unwrap(), 0); // idempotent
    }
}
