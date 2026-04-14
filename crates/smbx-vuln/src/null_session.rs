use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbDialect, SmbxResult};

use crate::check::VulnCheck;

pub struct NullSessionCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl NullSessionCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for NullSessionCheck {
    fn id(&self) -> &str {
        "null-session-enabled"
    }

    fn name(&self) -> &str {
        "Null Session Allowed"
    }

    fn description(&self) -> &str {
        "The target accepts unauthenticated SMB connections (null sessions). This allows an attacker to enumerate shares, users, and other information without credentials."
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("null_pivot")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            // SMBv1 historically allows null sessions.
            // For SMBv2+ targets, signing-disabled hosts are also commonly susceptible.
            let potentially_vulnerable = fp.dialect == SmbDialect::Smb1
                || (fp.dialect != SmbDialect::Unknown && !fp.signing_required);

            if potentially_vulnerable {
                let finding = Finding::new(
                    "Null Session Allowed",
                    "The target may accept unauthenticated SMB connections. Null sessions allow share and user enumeration without credentials.",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Likely)
                .add_host(fp.target.clone())
                .with_exploit_module("null_pivot".to_string())
                .with_remediation(
                    "Restrict null session access: set RestrictAnonymous=2 in the registry, or enable SMB signing to prevent unauthenticated enumeration."
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

    fn smb1_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.1.2.3".to_string(), 445);
        fp.dialect = SmbDialect::Smb1;
        fp.signing_required = false;
        fp
    }

    fn smb2_unsigned_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.1.2.3".to_string(), 445);
        fp.dialect = SmbDialect::Smb21;
        fp.signing_required = false;
        fp
    }

    fn smb2_signed_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.1.2.3".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.signing_required = true;
        fp
    }

    fn unknown_dialect_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.1.2.3".to_string(), 445);
        fp.dialect = SmbDialect::Unknown;
        fp.signing_required = false;
        fp
    }

    #[tokio::test]
    async fn check_smb1_returns_finding() {
        let check = NullSessionCheck::new(Some(smb1_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.severity, smbx_core::Severity::Medium);
        assert_eq!(finding.exploit_module.as_deref(), Some("null_pivot"));
    }

    #[tokio::test]
    async fn check_smb2_unsigned_returns_finding() {
        let check = NullSessionCheck::new(Some(smb2_unsigned_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn check_smb2_signed_returns_none() {
        let check = NullSessionCheck::new(Some(smb2_signed_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_unknown_dialect_returns_none() {
        // Unknown dialect with signing_required=false: dialect==Unknown means
        // the second condition (dialect != Unknown && !signing_required) is false
        // and dialect==Smb1 is also false, so should return None.
        let check = NullSessionCheck::new(Some(unknown_dialect_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_no_fingerprint_returns_none() {
        let check = NullSessionCheck::new(None);
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn metadata() {
        let check = NullSessionCheck::new(None);
        assert_eq!(check.id(), "null-session-enabled");
        assert!(!check.name().is_empty());
        assert!(!check.description().is_empty());
        assert_eq!(check.exploit_module(), Some("null_pivot"));
    }
}
