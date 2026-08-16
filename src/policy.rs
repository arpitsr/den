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
/// even with no user file. Same schema as PIT_PROXY_POLICY files.
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

/// YAML allow/deny file (PIT_PROXY_POLICY):
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

/// Local policy resolution: built-in defaults + PIT_PROXY_POLICY file +
/// PIT_PROXY_ALLOW (comma-separated). Base that a cloud source merges over.
pub fn local() -> Arc<dyn PolicySource> {
    struct Local;
    impl PolicySource for Local {
        fn policy(&self) -> Result<EgressPolicy> {
            // Static asset; a parse failure here is a build-time bug.
            let mut p: EgressPolicy =
                serde_yaml::from_str(DEFAULT_YAML).expect("default-egress.yaml");
            if let Ok(f) = std::env::var("PIT_PROXY_POLICY") {
                p.merge(FilePolicy(f.into()).policy()?);
            }
            if let Ok(extra) = std::env::var("PIT_PROXY_ALLOW") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_parses() {
        let p: EgressPolicy = serde_yaml::from_str(DEFAULT_YAML).unwrap();
        assert!(p.allows("api.github.com"));
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
        let path = std::env::temp_dir().join(format!("pit-policy-test-{}", std::process::id()));
        std::fs::write(&path, "allow: [a.com]\ndeny: [b.a.com]").unwrap();
        let p = FilePolicy(path.clone()).policy().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(p.allow, ["a.com"]);
        assert_eq!(p.deny, ["b.a.com"]);
    }
}
