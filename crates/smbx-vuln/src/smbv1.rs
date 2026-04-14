use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbxResult};

use crate::check::VulnCheck;

pub struct SmbV1Check {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl SmbV1Check {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for SmbV1Check {
    fn id(&self) -> &str {
        "smb-v1-enabled"
    }

    fn name(&self) -> &str {
        "SMBv1 Protocol Enabled"
    }

    fn description(&self) -> &str {
        "SMBv1 is an older, insecure SMB protocol version that is vulnerable to multiple RCE vulnerabilities including EternalBlue. Modern systems should disable SMBv1 entirely."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-0144"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("eternalblue")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.dialect == smbx_core::SmbDialect::Smb1 {
                let finding = Finding::new(
                    "SMBv1 Protocol Enabled",
                    "The target supports the legacy SMBv1 protocol which is vulnerable to multiple RCE exploits.",
                )
                .with_cve(vec!["CVE-2017-0144".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .add_host(fp.target.clone())
                .with_exploit_module("eternalblue".to_string())
                .with_remediation(
                    "Disable SMBv1 on the target system: disable-smbv1 in Windows or remove samba-client:i386 on Linux."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smbx_core::{Fingerprint, SmbDialect, OperatingSystem};
    use crate::check::VulnCheck;

    fn smb1_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("192.168.1.100".to_string(), 445);
        fp.dialect = SmbDialect::Smb1;
        fp.os = OperatingSystem::Windows7;
        fp
    }

    fn smb2_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("192.168.1.100".to_string(), 445);
        fp.dialect = SmbDialect::Smb21;
        fp.os = OperatingSystem::Windows10;
        fp
    }

    #[tokio::test]
    async fn check_smb1_returns_finding() {
        let check = SmbV1Check::new(Some(smb1_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.severity, smbx_core::Severity::Critical);
        assert_eq!(finding.confidence, smbx_core::Confidence::Confirmed);
        assert!(finding.cve.as_ref().map_or(false, |c| c.contains(&"CVE-2017-0144".to_string())));
        assert!(finding.affected_hosts.contains(&"192.168.1.100".to_string()));
        assert_eq!(finding.exploit_module.as_deref(), Some("eternalblue"));
    }

    #[tokio::test]
    async fn check_smb2_returns_none() {
        let check = SmbV1Check::new(Some(smb2_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_no_fingerprint_returns_none() {
        let check = SmbV1Check::new(None);
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn metadata() {
        let check = SmbV1Check::new(None);
        assert_eq!(check.id(), "smb-v1-enabled");
        assert_eq!(check.name(), "SMBv1 Protocol Enabled");
        assert!(!check.description().is_empty());
        assert!(check.cves().contains(&"CVE-2017-0144"));
        assert_eq!(check.exploit_module(), Some("eternalblue"));
    }
}
