use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

use crate::check::VulnCheck;

/// SMBleed (CVE-2020-1206) vulnerability check.
///
/// Actively probes by sending an SMBv3.1.1 NEGOTIATE with a
/// COMPRESSION_TRANSFORM_HEADER where OriginalCompressedSegmentSize exceeds the
/// actual data length. If the server responds with bytes beyond the declared
/// segment boundary, those bytes constitute leaked kernel memory.
///
/// Affected OS: Windows 10 versions 1903, 1909, 2004 and Server 2019 (pre-patch).
pub struct SmBleedCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
    target: String,
    port: u16,
}

impl SmBleedCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>, target: String, port: u16) -> Self {
        Self { fingerprint, target, port }
    }

    fn is_affected_os(os: &OperatingSystem) -> bool {
        matches!(
            os,
            OperatingSystem::Windows10 | OperatingSystem::Windows2019
        )
    }
}

#[async_trait]
impl VulnCheck for SmBleedCheck {
    fn id(&self) -> &str {
        "smbleed-vulnerable"
    }

    fn name(&self) -> &str {
        "SMBleed Kernel Memory Disclosure (CVE-2020-1206)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to SMBleed (CVE-2020-1206), an SMBv3 integer \
         underflow in Srv2DecompressData() that allows an unauthenticated attacker to \
         read uninitialized kernel memory. When chained with SMBGhost (CVE-2020-0796), \
         it can enable unauthenticated remote code execution."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2020-1206"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("smbleed")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        // Passive check based on fingerprint
        let os_match = self
            .fingerprint
            .as_ref()
            .map(|fp| {
                use smbx_core::SmbDialect;
                fp.dialect >= SmbDialect::Smb30 && Self::is_affected_os(&fp.os)
            })
            .unwrap_or(false);

        // Active probe — send malformed SMBv3 compression NEGOTIATE
        let addr_str = format!("{}:{}", self.target, self.port);
        let probe_positive = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match SmbSocket::connect(&addr, 5).await {
                Ok(mut socket) => {
                    let probe = SmbFrameBuilder::build_smbleed_probe();
                    match socket.send_nbt_message(&probe).await {
                        Ok(_) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                socket.recv_message(),
                            )
                            .await
                            {
                                // Any response that includes more than 4 bytes beyond the
                                // SMBv2 header is indicative of the overread path.
                                Ok(Ok(resp)) => resp.len() > 68,
                                _ => false,
                            }
                        }
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        } else {
            false
        };

        if os_match || probe_positive {
            let host = self
                .fingerprint
                .as_ref()
                .map(|fp| fp.target.clone())
                .unwrap_or_else(|| self.target.clone());

            let finding = Finding::new(
                "SMBleed Kernel Memory Disclosure (CVE-2020-1206)",
                "The target appears to be running an unpatched SMBv3 implementation affected \
                 by SMBleed (CVE-2020-1206). A malformed COMPRESSION_TRANSFORM_HEADER causes \
                 Srv2DecompressData() to return uninitialized kernel memory to an unauthenticated \
                 caller. Combined with SMBGhost (CVE-2020-0796), this can achieve RCE.",
            )
            .with_cve(vec!["CVE-2020-1206".to_string()])
            .with_severity(Severity::High)
            .with_confidence(if probe_positive {
                Confidence::Likely
            } else {
                Confidence::Possible
            })
            .add_host(host)
            .with_exploit_module("smbleed".to_string())
            .with_remediation(
                "Apply Microsoft security update KB4560960 (June 2020 Patch Tuesday). \
                 As a temporary mitigation, disable SMBv3 compression: \
                 Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\\
LanmanServer\\Parameters' DisableCompression -Type DWORD -Value 1."
                    .to_string(),
            );

            return Ok(Some(finding));
        }

        Ok(None)
    }
}
