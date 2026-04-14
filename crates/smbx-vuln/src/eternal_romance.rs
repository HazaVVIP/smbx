use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbDialect, SmbxResult};

use crate::check::VulnCheck;

/// EternalRomance (MS17-010, CVE-2017-0145) vulnerability check.
///
/// Triggered when the target exposes SMBv1 on a Windows version that shipped
/// before the May 2017 security patch (XP, 2003, Vista, 7, Server 2008/2008 R2).
pub struct EternalRomanceCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl EternalRomanceCheck {
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
impl VulnCheck for EternalRomanceCheck {
    fn id(&self) -> &str {
        "eternal-romance-vulnerable"
    }

    fn name(&self) -> &str {
        "EternalRomance RCE (MS17-010 / CVE-2017-0145)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to EternalRomance (CVE-2017-0145), an SMBv1 \
         heap-buffer-overflow in the SrvOs2FeaToNt function that enables unauthenticated \
         remote code execution on unpatched Windows systems."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-0145"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("eternal_romance")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.dialect == SmbDialect::Smb1 && Self::is_affected_os(&fp.os) {
                let finding = Finding::new(
                    "EternalRomance RCE (MS17-010 / CVE-2017-0145)",
                    "The target is running SMBv1 on a Windows version affected by \
                     EternalRomance (CVE-2017-0145). This allows unauthenticated heap \
                     buffer overflow and remote code execution via a crafted WRITE_ANDX request.",
                )
                .with_cve(vec!["CVE-2017-0145".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Likely)
                .add_host(fp.target.clone())
                .with_exploit_module("eternal_romance".to_string())
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
