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

#[cfg(test)]
mod tests {
    use super::*;
    use smbx_core::{Fingerprint, SmbDialect, OperatingSystem};
    use crate::check::VulnCheck;

    fn vulnerable_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.0.0.5".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.os = OperatingSystem::Windows10;
        fp
    }

    fn patched_windows10_fingerprint() -> Fingerprint {
        // Windows10 but SMBv2 only (dialect too low for smbghost)
        let mut fp = Fingerprint::new("10.0.0.5".to_string(), 445);
        fp.dialect = SmbDialect::Smb21;
        fp.os = OperatingSystem::Windows10;
        fp
    }

    fn non_windows_fingerprint() -> Fingerprint {
        let mut fp = Fingerprint::new("10.0.0.5".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.os = OperatingSystem::Linux;
        fp
    }

    #[tokio::test]
    async fn check_vulnerable_returns_finding() {
        let check = SmbGhostCheck::new(Some(vulnerable_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.severity, smbx_core::Severity::Critical);
        assert_eq!(finding.confidence, smbx_core::Confidence::Likely);
        assert!(finding.cve.as_ref().map_or(false, |c| c.contains(&"CVE-2020-0796".to_string())));
        assert_eq!(finding.exploit_module.as_deref(), Some("ghost_probe"));
    }

    #[tokio::test]
    async fn check_patched_dialect_returns_none() {
        let check = SmbGhostCheck::new(Some(patched_windows10_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_non_windows_returns_none() {
        let check = SmbGhostCheck::new(Some(non_windows_fingerprint()));
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_no_fingerprint_returns_none() {
        let check = SmbGhostCheck::new(None);
        let result = check.check().await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn metadata() {
        let check = SmbGhostCheck::new(None);
        assert_eq!(check.id(), "smbghost-vulnerable");
        assert!(!check.name().is_empty());
        assert!(!check.description().is_empty());
        assert!(check.cves().contains(&"CVE-2020-0796"));
        assert_eq!(check.exploit_module(), Some("ghost_probe"));
    }
}
