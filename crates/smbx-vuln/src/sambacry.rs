use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

use crate::check::VulnCheck;

/// SambaCry (CVE-2017-7494) vulnerability check.
///
/// Performs an active probe: connects via SMBv1/v2 and attempts to open a path
/// ending in `.so` on a writable share.  If the server does NOT return
/// STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034), the target is likely running
/// unpatched Samba < 4.4.14 with `nt pipe support = yes` (the default), making
/// it susceptible to unauthenticated shared-library injection RCE.
pub struct SambaCryCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
    target: String,
    port: u16,
}

impl SambaCryCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>, target: String, port: u16) -> Self {
        Self { fingerprint, target, port }
    }

    fn is_linux_samba(os: &OperatingSystem) -> bool {
        matches!(os, OperatingSystem::Linux | OperatingSystem::Other)
    }
}

#[async_trait]
impl VulnCheck for SambaCryCheck {
    fn id(&self) -> &str {
        "sambacry-vulnerable"
    }

    fn name(&self) -> &str {
        "SambaCry Shared-Library Injection RCE (CVE-2017-7494)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to SambaCry (CVE-2017-7494). Samba versions \
         prior to 4.4.14, 4.5.10, and 4.6.4 allow an unauthenticated attacker with \
         write access to a share to upload a shared library (.so) and trigger the \
         server to load and execute it by opening the file path, resulting in \
         unauthenticated remote code execution."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2017-7494"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("sambacry")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        // Passive check: Linux/Other OS on SMB is likely Samba
        let os_match = self
            .fingerprint
            .as_ref()
            .map(|fp| Self::is_linux_samba(&fp.os))
            .unwrap_or(false);

        // Active probe: attempt to open a .so path
        let addr_str = format!("{}:{}", self.target, self.port);
        let probe_positive = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match SmbSocket::connect(&addr, 5).await {
                Ok(mut socket) => {
                    let probe = SmbFrameBuilder::build_sambacry_probe();
                    match socket.send_nbt_message(&probe).await {
                        Ok(_) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                socket.recv_message(),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    // Parse NT Status from SMBv1 response (bytes 5-8)
                                    if resp.len() >= 9 {
                                        let status = u32::from_le_bytes([
                                            resp[5], resp[6], resp[7], resp[8],
                                        ]);
                                        // STATUS_OBJECT_NAME_NOT_FOUND = patched
                                        // Any other status (e.g. SUCCESS, ACCESS_DENIED) = potentially vulnerable
                                        status != 0xC0000034
                                    } else {
                                        false
                                    }
                                }
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
                "SambaCry Shared-Library Injection RCE (CVE-2017-7494)",
                "The target appears to be running a Samba version affected by CVE-2017-7494 \
                 (SambaCry). An attacker with write access to a share can upload a crafted \
                 shared library (.so) and trigger the server to load and execute it, achieving \
                 unauthenticated remote code execution with the privileges of the Samba daemon.",
            )
            .with_cve(vec!["CVE-2017-7494".to_string()])
            .with_severity(Severity::Critical)
            .with_confidence(if probe_positive {
                Confidence::Likely
            } else {
                Confidence::Possible
            })
            .add_host(host)
            .with_exploit_module("sambacry".to_string())
            .with_remediation(
                "Upgrade Samba to 4.4.14, 4.5.10, or 4.6.4 (or any later version). \
                 As a temporary mitigation, add 'nt pipe support = no' to smb.conf \
                 and restart the Samba service. Restrict write access to SMB shares."
                    .to_string(),
            );

            return Ok(Some(finding));
        }

        Ok(None)
    }
}
