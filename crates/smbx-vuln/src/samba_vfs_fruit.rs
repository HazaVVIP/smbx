use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

use crate::check::VulnCheck;

/// Samba vfs_fruit (CVE-2021-44142) vulnerability check.
///
/// Performs an active probe via a crafted SMBv2 IOCTL targeting the AFP_AfpInfo
/// stream exposed by the vfs_fruit VFS module. An out-of-bounds response
/// (response length > AFP_AFPINFO_STREAM_LEN + SMBv2 header) indicates that the
/// server is running unpatched Samba < 4.13.17 / 4.14.12 / 4.15.5 with
/// vfs_fruit enabled.
pub struct SambaVfsFruitCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
    target: String,
    port: u16,
}

impl SambaVfsFruitCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>, target: String, port: u16) -> Self {
        Self { fingerprint, target, port }
    }

    fn is_linux_samba(os: &OperatingSystem) -> bool {
        matches!(os, OperatingSystem::Linux | OperatingSystem::Other)
    }
}

#[async_trait]
impl VulnCheck for SambaVfsFruitCheck {
    fn id(&self) -> &str {
        "samba-vfs-fruit-vulnerable"
    }

    fn name(&self) -> &str {
        "Samba vfs_fruit OOB RCE (CVE-2021-44142)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to CVE-2021-44142, an out-of-bounds heap read/write \
         in Samba's vfs_fruit module triggered by a crafted AFP_AfpInfo EA request. \
         Samba versions prior to 4.13.17, 4.14.12, and 4.15.5 with vfs_fruit configured \
         are affected. This can lead to pre-authentication arbitrary code execution."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2021-44142"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("samba_vfs_fruit")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        // Passive check: Linux/Other OS on SMB is likely Samba
        let os_match = self
            .fingerprint
            .as_ref()
            .map(|fp| Self::is_linux_samba(&fp.os))
            .unwrap_or(false);

        // Active probe: send vfs_fruit AFP_AfpInfo IOCTL and measure response
        let addr_str = format!("{}:{}", self.target, self.port);
        let probe_positive = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match SmbSocket::connect(&addr, 5).await {
                Ok(mut socket) => {
                    let probe = SmbFrameBuilder::build_samba_fruit_probe();
                    match socket.send_nbt_message(&probe).await {
                        Ok(_) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                socket.recv_message(),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    // A response longer than the AFP_AfpInfo structure (60 bytes)
                                    // plus the SMBv2 header (64 bytes) indicates OOB data was returned.
                                    resp.len() > 64 + 60
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
                "Samba vfs_fruit OOB RCE (CVE-2021-44142)",
                "The target appears to be running a Samba version affected by CVE-2021-44142. \
                 A crafted AFP_AfpInfo EA request triggers an out-of-bounds heap read/write in \
                 the vfs_fruit module, enabling pre-authentication remote code execution with \
                 the privileges of the Samba daemon.",
            )
            .with_cve(vec!["CVE-2021-44142".to_string()])
            .with_severity(Severity::Critical)
            .with_confidence(if probe_positive {
                Confidence::Likely
            } else {
                Confidence::Possible
            })
            .add_host(host)
            .with_exploit_module("samba_vfs_fruit".to_string())
            .with_remediation(
                "Upgrade Samba to 4.13.17, 4.14.12, or 4.15.5 (or any later version). \
                 If vfs_fruit is not required, remove it from smb.conf vfs objects. \
                 Restrict share access and block TCP 445 at the network perimeter."
                    .to_string(),
            );

            return Ok(Some(finding));
        }

        Ok(None)
    }
}
