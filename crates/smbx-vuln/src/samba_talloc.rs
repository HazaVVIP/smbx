use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

use crate::check::VulnCheck;

/// Samba Talloc Chunk Overwrite (CVE-2012-1182) vulnerability check.
///
/// Sends an oversized SESSION_SETUP_ANDX security blob (65535 bytes) to probe
/// for the talloc heap metadata overwrite present in Samba versions prior to
/// 3.6.4 / 3.5.14 / 3.4.16 / 3.3.16 / 3.2.16 / 3.0.37. If the server
/// disconnects without returning STATUS_INVALID_PARAMETER (0xC000000D), it is
/// likely affected.
pub struct SambaTallocCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
    target: String,
    port: u16,
}

impl SambaTallocCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>, target: String, port: u16) -> Self {
        Self { fingerprint, target, port }
    }

    fn is_linux_samba(os: &OperatingSystem) -> bool {
        matches!(os, OperatingSystem::Linux | OperatingSystem::Other)
    }
}

#[async_trait]
impl VulnCheck for SambaTallocCheck {
    fn id(&self) -> &str {
        "samba-talloc-vulnerable"
    }

    fn name(&self) -> &str {
        "Samba Talloc Heap Overwrite RCE (CVE-2012-1182)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to CVE-2012-1182, a heap-based buffer overflow in \
         Samba's talloc memory allocator triggered by an oversized security blob in a \
         SESSION_SETUP_ANDX request. Samba versions prior to 3.6.4 are affected. \
         Exploitation can lead to remote code execution with root privileges."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2012-1182"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("samba_talloc")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        // Passive check: Linux/Other OS on SMB is likely Samba
        let os_match = self
            .fingerprint
            .as_ref()
            .map(|fp| Self::is_linux_samba(&fp.os))
            .unwrap_or(false);

        // Active probe: send oversized SESSION_SETUP_ANDX
        let addr_str = format!("{}:{}", self.target, self.port);
        let probe_positive = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match SmbSocket::connect(&addr, 5).await {
                Ok(mut socket) => {
                    let probe = SmbFrameBuilder::build_samba_talloc_probe();
                    match socket.send_nbt_message(&probe).await {
                        Ok(_) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                socket.recv_message(),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    // Patched Samba returns STATUS_INVALID_PARAMETER (0xC000000D)
                                    // in bytes 5-8 of the SMBv1 response.
                                    if resp.len() >= 9 {
                                        let status = u32::from_le_bytes([
                                            resp[5], resp[6], resp[7], resp[8],
                                        ]);
                                        // Anything other than STATUS_INVALID_PARAMETER
                                        // suggests the oversized blob was accepted.
                                        status != 0xC000000D
                                    } else {
                                        false
                                    }
                                }
                                // Connection closed without STATUS_INVALID_PARAMETER = potential crash
                                Ok(Err(_)) => true,
                                // Timeout after probe = potential crash / hang
                                Err(_) => true,
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
                "Samba Talloc Heap Overwrite RCE (CVE-2012-1182)",
                "The target appears to be running a Samba version affected by CVE-2012-1182. \
                 An oversized SESSION_SETUP_ANDX security blob triggers a talloc heap metadata \
                 overwrite, enabling remote code execution with root privileges without \
                 prior authentication.",
            )
            .with_cve(vec!["CVE-2012-1182".to_string()])
            .with_severity(Severity::Critical)
            .with_confidence(if probe_positive {
                Confidence::Likely
            } else {
                Confidence::Possible
            })
            .add_host(host)
            .with_exploit_module("samba_talloc".to_string())
            .with_remediation(
                "Upgrade Samba to 3.6.4 or later. Apply the vendor-supplied security patch. \
                 Block inbound TCP 445 at the network perimeter and restrict SMB access to \
                 trusted hosts only."
                    .to_string(),
            );

            return Ok(Some(finding));
        }

        Ok(None)
    }
}
