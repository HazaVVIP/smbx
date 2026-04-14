use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbxResult};

use crate::check::VulnCheck;

pub struct SigningDisabledCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl SigningDisabledCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for SigningDisabledCheck {
    fn id(&self) -> &str {
        "smb-signing-disabled"
    }

    fn name(&self) -> &str {
        "SMB Signing Disabled"
    }

    fn description(&self) -> &str {
        "SMB message signing is not required. This allows for NTLM relay attacks and man-in-the-middle attacks."
    }

    fn cves(&self) -> Vec<&str> {
        vec![]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("ntlm_relay")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if !fp.signing_required {
                let finding = Finding::new(
                    "SMB Signing Disabled",
                    "SMB message signing is not enforced on the target. This allows NTLM relay attacks and credential interception.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .add_host(fp.target.clone())
                .with_exploit_module("ntlm_relay".to_string())
                .with_remediation(
                    "Enable SMB signing: Set 'require security signatures' in Group Policy or registry."
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
    use smbx_core::{Fingerprint, SmbDialect};
    use crate::check::VulnCheck;

    fn unsigned_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("192.168.0.10".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.signing_required = false;
        fp
    }

    fn signed_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("192.168.0.10".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.signing_required = true;
        fp
    }

    #[tokio::test]
    async fn check_signing_disabled_returns_finding() {
        let check = SigningDisabledCheck::new(Some(unsigned_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.severity, smbx_core::Severity::High);
        assert_eq!(finding.confidence, smbx_core::Confidence::Confirmed);
        assert_eq!(finding.exploit_module.as_deref(), Some("ntlm_relay"));
        assert!(finding.affected_hosts.contains(&"192.168.0.10".to_string()));
    }

    #[tokio::test]
    async fn check_signing_required_returns_none() {
        let check = SigningDisabledCheck::new(Some(signed_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_no_fingerprint_returns_none() {
        let check = SigningDisabledCheck::new(None);
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn metadata() {
        let check = SigningDisabledCheck::new(None);
        assert_eq!(check.id(), "smb-signing-disabled");
        assert!(!check.name().is_empty());
        assert!(!check.description().is_empty());
        assert!(check.cves().is_empty());
        assert_eq!(check.exploit_module(), Some("ntlm_relay"));
    }
}
