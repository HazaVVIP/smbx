use async_trait::async_trait;
use smbx_core::{Confidence, Finding, Severity, SmbxResult};

use crate::check::VulnCheck;

pub struct SmbV1Check {
    fingerprint: Option<smbx_core::Fingerprint>,
}

impl SmbV1Check {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>) -> Self {
        Self { fingerprint }
    }
}

#[async_trait]
impl VulnCheck for SmbV1Check {
    fn id(&self) -> &str {
        "smb-v1-enabled"
    }

    fn name(&self) -> &str {
        "SMBv1 Protocol Enabled"
    }

    fn description(&self) -> &str {
        "SMBv1 is an older, insecure SMB protocol version that is vulnerable to multiple RCE vulnerabilities including EternalBlue. Modern systems should disable SMBv1 entirely."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-0144"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("eternalblue")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        if let Some(ref fp) = self.fingerprint {
            if fp.dialect == smbx_core::SmbDialect::Smb1 {
                let finding = Finding::new(
                    "SMBv1 Protocol Enabled",
                    "The target supports the legacy SMBv1 protocol which is vulnerable to multiple RCE exploits.",
                )
                .with_cve(vec!["CVE-2017-0144".to_string()])
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .add_host(fp.target.clone())
                .with_exploit_module("eternalblue".to_string())
                .with_remediation(
                    "Disable SMBv1 on the target system: disable-smbv1 in Windows or remove samba-client:i386 on Linux."
                        .to_string(),
                );

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}
