//! Throwaway: build a session delta DB that looks like what `agentfs run` would
//! leave behind, so we can exercise `pit inspect` / `pit sessions` (and the
//! post-run SDK summary) without installing the real agentfs CLI.
//!
//!   cargo run --example mkdelta -- <session-id> [base-dir]
//!
//! Creates `~/.agentfs/run/<session-id>/delta.db` with overlay schema (base
//! recorded), one created file `/hello.txt`, one created dir `/out`, and one
//! whiteout `README.md`. Then print the sid.

use agentfs_sdk::{AgentFS, AgentFSOptions, DEFAULT_FILE_MODE};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let sid = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: mkdelta <session-id> [base-dir]"))?;
    let base = std::env::args()
        .nth(2)
        .unwrap_or_else(|| std::env::temp_dir().join("mkdelta-base").to_string_lossy().to_string());
    std::fs::create_dir_all(&base)?;

    let home = std::env::var("HOME")?;
    let dir = format!("{home}/.agentfs/run/{sid}");
    std::fs::create_dir_all(&dir)?;
    let db = format!("{dir}/delta.db");
    // start clean so re-runs are idempotent
    let _ = std::fs::remove_file(&db);

    let agent =
        AgentFS::open(AgentFSOptions::with_path(&db).with_base(&base)).await?;

    // a created/modified file (shows up in get_delta_paths)
    let _ = agent
        .fs
        .create_file("/hello.txt", DEFAULT_FILE_MODE, 0, 0)
        .await?;
    // a created dir (also a delta path)
    agent.fs.mkdir("/out", 0, 0).await?;

    // a deleted-from-base file (shows up in get_whiteouts)
    let conn = agent.get_connection().await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO fs_whiteout (path, created_at) VALUES (?, ?)",
        ("README.md", now),
    )
    .await?;

    println!("created {db}");
    println!("sid={sid} base={base} changed=2 deleted=1");
    Ok(())
}