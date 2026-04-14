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
