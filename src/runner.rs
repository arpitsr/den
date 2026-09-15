//! The Runner trait: how serve spawns session children.
//!
//! serve is a supervisor, not a sandbox host (docs/platform-api.md §1) — it
//! launches `den <profile> …` children and reaps them. *How* the child is
//! isolated is pluggable:
//!
//! - `process` (default): plain `std::process` with its own process group.
//!   Works on macOS, Linux, CI, plain Docker. Same API, less isolation.
//! - `sandbox` (Linux, private backend): the FUSE + user/mount/net
//!   namespace chain in sandbox.rs. Same trait, plugged in via
//!   `DEN_RUNNER=sandbox` when the backend is linked.
//!
//! Contract: the runner must put the child in its own process group
//! (kill/stop escalate SIGTERM→SIGKILL against the whole group, serve.rs
//! `kill_run`/`stop_session`), and must not share stdio with serve.
use anyhow::Result;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;

/// What serve hands the runner: a fully-qualified argv plus stdio plumbing
/// and per-session env. The runner decides *how* to isolate the exec,
/// nothing else — argv is the runner's contract with profiles.
pub struct Launch {
    pub exe: String,
    pub args: Vec<String>,
    /// Session id, always exported as DEN_SESSION (children key their
    /// journal, locks, and delta snapshots on it).
    pub sid: String,
    /// Extra env (e.g. DEX_DAEMON_TOKEN), set on the child.
    pub env: Vec<(String, String)>,
    /// Env vars removed from the inherited environment (e.g. DEN_NEW).
    pub env_remove: Vec<String>,
    /// Appended stdout/stderr of the run log (caller owns the open file).
    pub stdout: Stdio,
    pub stderr: Stdio,
}

/// Isolation backend. Serve holds one behind Arc for the process lifetime.
pub trait Runner: Send + Sync {
    /// Spawn the child. On success the caller owns it (reap, kill).
    /// Errors are spawn-time only; after this returns, the child exists.
    fn launch(&self, req: Launch) -> std::io::Result<tokio::process::Child>;
}

/// Default backend: exec directly with the child in its own process group.
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn launch(&self, req: Launch) -> std::io::Result<tokio::process::Child> {
        let mut cmd = Command::new(&req.exe);
        cmd.args(&req.args)
            .env("DEN_SESSION", &req.sid)
            .envs(req.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        for k in &req.env_remove {
            cmd.env_remove(k);
        }
        cmd.stdin(Stdio::null())
            .stdout(req.stdout)
            .stderr(req.stderr)
            .process_group(0);
        cmd.spawn()
    }
}

/// Backend selection: DEN_RUNNER=process (default) | sandbox.
/// The sandbox backend lives in the private build; fail loudly rather than
/// silently downgrading isolation.
pub fn runner() -> Result<Arc<dyn Runner>> {
    match std::env::var("DEN_RUNNER").as_deref() {
        Ok("sandbox") => Err(anyhow::anyhow!(
            "DEN_RUNNER=sandbox: sandbox backend not linked in this build"
        )),
        Ok(other) if other.is_empty() || other == "process" => Ok(Arc::new(ProcessRunner)),
        Ok(other) => Err(anyhow::anyhow!(
            "unknown DEN_RUNNER '{other}' (known: process)"
        )),
        Err(_) => Ok(Arc::new(ProcessRunner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_req(exe: &str, args: &[&str]) -> Launch {
        Launch {
            exe: exe.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            sid: "s-test".into(),
            env: vec![],
            env_remove: vec![],
            stdout: Stdio::null(),
            stderr: Stdio::null(),
        }
    }

    #[test]
    fn process_runner_spawns_and_exits_zero() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut c = ProcessRunner
                .launch(launch_req("/bin/sh", &["-c", "exit 0"]))
                .unwrap();
            assert_eq!(c.wait().await.unwrap().code(), Some(0));
        });
    }

    #[test]
    fn process_runner_env_reaches_child() {
        let out = std::env::temp_dir().join("den-runner-env-test");
        let mut req = launch_req(
            "/bin/sh",
            &[
                "-c",
                &format!("echo $DEN_SESSION-$MARKER > {}", out.to_str().unwrap()),
            ],
        );
        req.env.push(("MARKER".into(), "42".into()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut c = ProcessRunner.launch(req).unwrap();
            let st = c.wait().await.unwrap();
            assert!(st.success(), "child exit: {st:?}");
        });
        let got = match std::fs::read_to_string(&out) {
            Ok(g) => g,
            Err(e) => panic!("read {out:?} failed: {e}; exists={}", out.exists()),
        };
        std::fs::remove_file(&out).ok();
        assert_eq!(got.trim(), "s-test-42");
    }

    #[test]
    fn runner_selection() {
        std::env::set_var("DEN_RUNNER", "process");
        assert!(runner().is_ok());
        std::env::set_var("DEN_RUNNER", "nope");
        assert!(runner().is_err());
        std::env::remove_var("DEN_RUNNER");
        assert!(runner().is_ok());
    }
}
