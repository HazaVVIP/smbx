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
