use async_trait::async_trait;
use smbx_core::{Finding, SmbxResult};

/// Vulnerability check trait - each check must implement this
#[async_trait]
pub trait VulnCheck: Send + Sync {
    /// Unique identifier for this check
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Description of the vulnerability
    fn description(&self) -> &str;

    /// CVE identifiers if applicable
    fn cves(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Which exploit module can prove this vulnerability (if any)
    fn exploit_module(&self) -> Option<&str> {
        None
    }

    /// Run the check
    async fn check(&self) -> SmbxResult<Option<Finding>>;
}

/// Registry of all available vulnerability checks
pub struct VulnRegistry {
    checks: Vec<Box<dyn VulnCheck>>,
}

impl VulnRegistry {
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
        }
    }

    pub fn register(&mut self, check: Box<dyn VulnCheck>) {
        self.checks.push(check);
    }

    pub fn get_checks(&self) -> &[Box<dyn VulnCheck>] {
        &self.checks
    }

    pub fn find_by_id(&self, id: &str) -> Option<&Box<dyn VulnCheck>> {
        self.checks.iter().find(|c| c.id() == id)
    }

    pub async fn run_all(&self) -> SmbxResult<Vec<Finding>> {
        let mut findings = Vec::new();

        for check in &self.checks {
            match check.check().await {
                Ok(Some(finding)) => findings.push(finding),
                Ok(None) => {
                    log::debug!("Check {} found no vulnerabilities", check.id());
                }
                Err(e) => {
                    log::warn!("Check {} failed: {}", check.id(), e);
                }
            }
        }

        Ok(findings)
    }
}

impl Default for VulnRegistry {
    fn default() -> Self {
        Self::new()
    }
}
