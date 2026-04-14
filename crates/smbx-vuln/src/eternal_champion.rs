use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbDialect, SmbxResult};

use crate::check::VulnCheck;

/// EternalChampion (MS17-010, CVE-2017-0146) vulnerability check.
///
/// Triggered when the target exposes SMBv1 on a Windows version affected by the
/// TRANSACTION2 QUERY_PATH_INFO pool overflow (XP, 2003, Vista, 7, 2008/R2).
pub struct EternalChampionCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl EternalChampionCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }

    fn is_affected_os(os: &OperatingSystem) -> bool {
        matches!(
            os,
            OperatingSystem::WindowsXp
                | OperatingSystem::Windows2003
                | OperatingSystem::WindowsVista
                | OperatingSystem::Windows7
                | OperatingSystem::Windows2008
                | OperatingSystem::Windows2008R2
        )
    }
}

#[async_trait]
impl VulnCheck for EternalChampionCheck {
    fn id(&self) -> &str {
        "eternal-champion-vulnerable"
    }

    fn name(&self) -> &str {
        "EternalChampion RCE (MS17-010 / CVE-2017-0146)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to EternalChampion (CVE-2017-0146), an SMBv1 \
         pool-buffer-overflow in the TRANSACTION2 handler that enables unauthenticated \
         remote code execution by overflowing the SrvTransactionNotifyChange pool block."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-0146"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("eternal_champion")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.dialect == SmbDialect::Smb1 && Self::is_affected_os(&fp.os) {
                let finding = Finding::new(
                    "EternalChampion RCE (MS17-010 / CVE-2017-0146)",
                    "The target is running SMBv1 on a Windows version affected by \
                     EternalChampion (CVE-2017-0146). A crafted TRANSACTION2 request \
                     can overflow the SrvTransactionNotifyChange pool block and achieve \
                     unauthenticated remote code execution.",
                )
                .with_cve(vec!["CVE-2017-0146".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Likely)
                .add_host(fp.target.clone())
                .with_exploit_module("eternal_champion".to_string())
                .with_remediation(
                    "Apply Microsoft security update MS17-010 (KB4012212 / KB4012215). \
                     Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. \
                     Block inbound TCP 445 at the network perimeter."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}
