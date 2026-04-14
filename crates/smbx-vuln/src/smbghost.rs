use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbxResult};

use crate::check::VulnCheck;

pub struct SmbGhostCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl SmbGhostCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for SmbGhostCheck {
    fn id(&self) -> &str {
        "smbghost-vulnerable"
    }

    fn name(&self) -> &str {
        "SMBGhost (CVE-2020-0796) Potentially Vulnerable"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to SMBGhost (CVE-2020-0796), a critical buffer overflow in the SMBv3 compression implementation affecting Windows 10 and Server 2019. Exploitation can lead to remote code execution or denial of service."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2020-0796"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("ghost_probe")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.is_vulnerable_to_smbghost() {
                let finding = Finding::new(
                    "SMBGhost (CVE-2020-0796) Potentially Vulnerable",
                    "The target is running SMBv3 on a Windows 10 or Server 2019 build that may be unpatched against CVE-2020-0796. This vulnerability allows unauthenticated RCE via a crafted compressed SMBv3 message.",
                )
                .with_cve(vec!["CVE-2020-0796".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Likely)
                .add_host(fp.target.clone())
                .with_exploit_module("ghost_probe".to_string())
                .with_remediation(
                    "Apply Microsoft security update KB4551762. Alternatively, disable SMBv3 compression as a temporary mitigation: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' DisableCompression -Type DWORD -Value 1."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}
