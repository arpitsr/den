//! Egress policy for the sandbox proxy: which hosts may be reached.
//!
//! The proxy asks a `PolicySource` for the policy on every connection and
//! fails closed on error, so a source can change its answer over time:
//! `FilePolicy` re-reads its YAML (edits apply live), and a cloud control
//! plane later implements the same trait with remote-supplied lists and its
//! own cache — merging over `local()` keeps the defaults as a floor.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

/// Built-in default policy, embedded so zero-config runs stay fail-safe
/// even with no user file. Same schema as DEN_PROXY_POLICY files.
const DEFAULT_YAML: &str = include_str!("default-egress.yaml");

/// Allow/deny host lists. Deny wins over allow; entries match the host
/// exactly or any of its subdomains.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EgressPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl EgressPolicy {
    pub fn allows(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let m = |d: &String| h == *d || h.ends_with(&format!(".{}", d));
        !self.deny.iter().any(&m) && self.allow.iter().any(&m)
    }

    /// Fold another source's lists into this one (defaults < file < cloud).
    pub fn merge(&mut self, other: EgressPolicy) {
        self.allow.extend(other.allow);
        self.deny.extend(other.deny);
    }
}

/// Where the proxy gets its egress policy.
pub trait PolicySource: Send + Sync {
    fn policy(&self) -> Result<EgressPolicy>;
}

/// YAML allow/deny file (DEN_PROXY_POLICY, else ./den-egress.yaml in the project):
///
/// ```yaml
/// allow: [example.com]
/// deny: [ads.example.com]
/// ```
pub struct FilePolicy(pub PathBuf);

impl PolicySource for FilePolicy {
    fn policy(&self) -> Result<EgressPolicy> {
        let s = std::fs::read_to_string(&self.0)
            .with_context(|| format!("read {}", self.0.display()))?;
        serde_yaml::from_str(&s).with_context(|| format!("parse {}", self.0.display()))
    }
}

/// Local policy resolution: built-in defaults + policy file +
/// DEN_PROXY_ALLOW (comma-separated). File: DEN_PROXY_POLICY if set
/// (explicit — unreadable fails closed), else den-egress.yaml in the
/// project dir if present (the proxy inherits den's cwd). Base that a
/// cloud source merges over.
pub fn local() -> Arc<dyn PolicySource> {
    struct Local;
    impl PolicySource for Local {
        fn policy(&self) -> Result<EgressPolicy> {
            // Static asset; a parse failure here is a build-time bug.
            let mut p: EgressPolicy =
                serde_yaml::from_str(DEFAULT_YAML).expect("default-egress.yaml");
            if let Ok(f) = std::env::var("DEN_PROXY_POLICY") {
                p.merge(FilePolicy(f.into()).policy()?);
            } else {
                let f = std::env::current_dir()?.join("den-egress.yaml");
                if f.exists() {
                    p.merge(FilePolicy(f).policy()?);
                }
            }
            if let Ok(extra) = std::env::var("DEN_PROXY_ALLOW") {
                p.allow.extend(
                    extra
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                );
            }
            Ok(p)
        }
    }
    Arc::new(Local)
}

/// Append `host` to the allow list of the user's egress policy file
/// (DEN_PROXY_POLICY, else ./den-egress.yaml in the project dir), creating
/// it if needed. Returns the file written so the caller can tell the user.
/// Existing comments/structure are preserved; the entry is appended to the
/// `allow:` list (or a new one is added).
pub fn persist_allow(host: &str) -> Result<PathBuf> {
    let path = match std::env::var("DEN_PROXY_POLICY") {
        Ok(f) => PathBuf::from(f),
        Err(_) => std::env::current_dir()?.join("den-egress.yaml"),
    };
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut out = String::with_capacity(existing.len() + 32);
    let mut in_allow = false;
    let mut appended = false;
    for line in existing.lines() {
        let trimmed = line.trim_end();
        if trimmed == "allow:" || trimmed.starts_with("allow:") && !trimmed[6..].trim().is_empty() {
            // Inline form ("allow: [a.com]") or block form — normalize to block.
            if trimmed.ends_with(':') {
                out.push_str(line);
                out.push('\n');
                out.push_str(&format!("  - {}\n", host));
                appended = true;
            } else {
                out.push_str(&format!("allow:\n  - {}\n", host));
                appended = true;
            }
            in_allow = trimmed.ends_with(':');
            continue;
        }
        if in_allow {
            if line.starts_with(' ') || line.starts_with('-') {
                out.push_str(line);
                out.push('\n');
                continue;
            }
            in_allow = false;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !appended {
        if !out.is_empty() && !out.ends_with("\n\n") {
            out.push('\n');
        }
        out.push_str(&format!("allow:\n  - {}\n", host));
    }
    std::fs::write(&path, out)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_parses() {
        let p: EgressPolicy = serde_yaml::from_str(DEFAULT_YAML).unwrap();
        assert!(p.allows("api.anthropic.com"));
        assert!(!p.allows("example.com"));
    }

    #[test]
    fn deny_wins_subdomains_match() {
        let p: EgressPolicy =
            serde_yaml::from_str("allow: [example.com]\ndeny: [evil.example.com]").unwrap();
        assert!(p.allows("example.com"));
        assert!(p.allows("api.example.com"));
        assert!(p.allows("API.Example.COM.")); // case + trailing dot normalized
        assert!(!p.allows("evil.example.com"));
        assert!(!p.allows("deep.evil.example.com"));
        assert!(!p.allows("notexample.com"));
        assert!(!p.allows("other.org"));
    }

    #[test]
    fn file_policy_reads_yaml() {
        let path = std::env::temp_dir().join(format!("den-policy-test-{}", std::process::id()));
        std::fs::write(&path, "allow: [a.com]\ndeny: [b.a.com]").unwrap();
        let p = FilePolicy(path.clone()).policy().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(p.allow, ["a.com"]);
        assert_eq!(p.deny, ["b.a.com"]);
    }
}
