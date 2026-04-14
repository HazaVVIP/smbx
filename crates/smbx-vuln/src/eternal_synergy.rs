use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbDialect, SmbxResult};

use crate::check::VulnCheck;

/// EternalSynergy (MS17-010, CVE-2017-0143) vulnerability check.
///
/// Triggered when the target exposes SMBv1 on Windows XP or Server 2003 —
/// the NT_TRANSACT CREATE path with MaxSetupCount=0 is a distinct overflow
/// primitive from EternalBlue and EternalRomance.
pub struct EternalSynergyCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl EternalSynergyCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }

    fn is_affected_os(os: &OperatingSystem) -> bool {
        matches!(
            os,
            OperatingSystem::WindowsXp | OperatingSystem::Windows2003
        )
    }
}

#[async_trait]
impl VulnCheck for EternalSynergyCheck {
    fn id(&self) -> &str {
        "eternal-synergy-vulnerable"
    }

    fn name(&self) -> &str {
        "EternalSynergy RCE (MS17-010 / CVE-2017-0143)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to EternalSynergy (CVE-2017-0143), an SMBv1 \
         NT_TRANSACT pool-buffer-overflow that affects Windows XP and Server 2003. \
         Setting MaxSetupCount=0 triggers an alternative code path enabling \
         unauthenticated remote code execution."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-0143"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("eternal_synergy")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.dialect == SmbDialect::Smb1 && Self::is_affected_os(&fp.os) {
                let finding = Finding::new(
                    "EternalSynergy RCE (MS17-010 / CVE-2017-0143)",
                    "The target is running SMBv1 on Windows XP or Server 2003 — both are \
                     vulnerable to EternalSynergy (CVE-2017-0143). A crafted NT_TRANSACT \
                     request with MaxSetupCount=0 overflows the pool block and achieves \
                     unauthenticated remote code execution.",
                )
                .with_cve(vec!["CVE-2017-0143".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Likely)
                .add_host(fp.target.clone())
                .with_exploit_module("eternal_synergy".to_string())
                .with_remediation(
                    "Apply Microsoft security update MS17-010 (KB4012212). \
                     Disable SMBv1 and upgrade to a supported OS — Windows XP and \
                     Server 2003 are end-of-life and no longer receive security patches."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}
