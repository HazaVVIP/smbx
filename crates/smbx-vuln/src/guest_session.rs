use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbDialect, SmbxResult};

use crate::check::VulnCheck;

pub struct GuestSessionCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl GuestSessionCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for GuestSessionCheck {
    fn id(&self) -> &str {
        "guest-account-enabled"
    }

    fn name(&self) -> &str {
        "Guest Account Potentially Enabled"
    }

    fn description(&self) -> &str {
        "The target exposes an SMB service where the guest account may be enabled. Guest access allows limited share enumeration and file access without valid credentials."
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("guest_pivot")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            // Any reachable SMB host (dialect identified) is a candidate for guest access.
            // The exploit module performs the actual authentication probe.
            if fp.dialect != SmbDialect::Unknown {
                let finding = Finding::new(
                    "Guest Account Potentially Enabled",
                    "The target hosts an SMB service that may allow guest-level access. Guest accounts can enumerate shares and read world-readable files.",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Possible)
                .add_host(fp.target.clone())
                .with_exploit_module("guest_pivot".to_string())
                .with_remediation(
                    "Disable the Guest account and ensure all SMB shares require authenticated access. On Windows: Computer Management → Local Users and Groups → Guest → Account is disabled."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}
