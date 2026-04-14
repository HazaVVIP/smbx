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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct DummyCheck {
        id: &'static str,
        name: &'static str,
    }

    #[async_trait]
    impl VulnCheck for DummyCheck {
        fn id(&self) -> &str {
            self.id
        }

        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "dummy check for testing"
        }

        async fn check(&self) -> SmbxResult<Option<Finding>> {
            Ok(None)
        }
    }

    #[test]
    fn registry_starts_empty() {
        let reg = VulnRegistry::new();
        assert!(reg.get_checks().is_empty());
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = VulnRegistry::default();
        assert!(reg.get_checks().is_empty());
    }

    #[test]
    fn registry_register_and_count() {
        let mut reg = VulnRegistry::new();
        reg.register(Box::new(DummyCheck { id: "check-1", name: "Check One" }));
        reg.register(Box::new(DummyCheck { id: "check-2", name: "Check Two" }));
        assert_eq!(reg.get_checks().len(), 2);
    }

    #[test]
    fn registry_find_by_id_found() {
        let mut reg = VulnRegistry::new();
        reg.register(Box::new(DummyCheck { id: "my-check", name: "My Check" }));
        let found = reg.find_by_id("my-check");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), "my-check");
    }

    #[test]
    fn registry_find_by_id_not_found() {
        let reg = VulnRegistry::new();
        assert!(reg.find_by_id("nonexistent").is_none());
    }

    #[tokio::test]
    async fn registry_run_all_returns_only_some_findings() {
        struct FindingCheck;

        #[async_trait]
        impl VulnCheck for FindingCheck {
            fn id(&self) -> &str { "finding-check" }
            fn name(&self) -> &str { "Finding Check" }
            fn description(&self) -> &str { "always returns a finding" }

            async fn check(&self) -> SmbxResult<Option<Finding>> {
                Ok(Some(Finding::new("test vuln", "desc")))
            }
        }

        let mut reg = VulnRegistry::new();
        reg.register(Box::new(FindingCheck));
        reg.register(Box::new(DummyCheck { id: "d1", name: "D1" })); // returns None

        let findings = reg.run_all().await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, "test vuln");
    }
}
