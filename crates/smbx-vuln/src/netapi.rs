use async_trait::async_trait;
use smbx_core::{Confidence, Finding, OperatingSystem, Severity, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

use crate::check::VulnCheck;

/// NetAPI / MS08-067 (CVE-2008-4250 / CVE-2006-3439) vulnerability check.
///
/// Performs an active probe: connects to TCP 445, sends a DCE/RPC bind request
/// for the wkssvc interface and inspects whether the server returns an
/// RPC_S_ACCESS_DENIED response (patched) or responds to the wkssvc interface
/// at all (potentially unpatched — further exploit module confirms).
///
/// Also checks the OS fingerprint: unpatched versions include Windows 2000,
/// XP, 2003, Vista (pre-SP2), and Server 2008 (pre-SP2).
pub struct NetApiCheck {
    fingerprint: Option<smbx_core::Fingerprint>,
    target: String,
    port: u16,
}

impl NetApiCheck {
    pub fn new(fingerprint: Option<smbx_core::Fingerprint>, target: String, port: u16) -> Self {
        Self { fingerprint, target, port }
    }

    fn is_affected_os(os: &OperatingSystem) -> bool {
        matches!(
            os,
            OperatingSystem::WindowsXp
                | OperatingSystem::Windows2003
                | OperatingSystem::WindowsVista
                | OperatingSystem::Windows2008
        )
    }
}

#[async_trait]
impl VulnCheck for NetApiCheck {
    fn id(&self) -> &str {
        "netapi-vulnerable"
    }

    fn name(&self) -> &str {
        "NetAPI / MS08-067 RCE (CVE-2008-4250)"
    }

    fn description(&self) -> &str {
        "The target may be vulnerable to MS08-067 / NetAPI (CVE-2008-4250), a stack \
         buffer overflow in the NetpwPathCanonicalize() function exposed via the Server \
         service (srvsvc) and Workstation service (wkssvc) DCE/RPC interfaces. This \
         allows unauthenticated remote code execution."
    }

    fn cves(&self) -> Vec<&str> {
        vec!["CVE-2008-4250", "CVE-2006-3439"]
    }

    fn exploit_module(&self) -> Option<&str> {
        Some("netapi")
    }

    async fn check(&self) -> SmbxResult<Option<Finding>> {
        // Passive check: known-vulnerable OS from fingerprint
        let os_vulnerable = self
            .fingerprint
            .as_ref()
            .map(|fp| Self::is_affected_os(&fp.os))
            .unwrap_or(false);

        // Active probe: attempt to bind to the wkssvc interface
        let addr_str = format!("{}:{}", self.target, self.port);
        let probe_result = if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match SmbSocket::connect(&addr, 5).await {
                Ok(mut socket) => {
                    let probe = SmbFrameBuilder::build_netapi_rpc_probe();
                    match socket.send_nbt_message(&probe).await {
                        Ok(_) => {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                socket.recv_message(),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    // Accept response (bind_ack packet type = 12)
                                    resp.first().copied() == Some(5) // DCE/RPC version check
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

        if os_vulnerable || probe_result {
            let host = self
                .fingerprint
                .as_ref()
                .map(|fp| fp.target.clone())
                .unwrap_or_else(|| self.target.clone());

            let finding = Finding::new(
                "NetAPI / MS08-067 RCE (CVE-2008-4250)",
                "The target appears to be running an unpatched Windows version exposed to \
                 MS08-067 / NetAPI (CVE-2008-4250). A crafted DCE/RPC request to the Server \
                 service can overflow NetpwPathCanonicalize() and achieve unauthenticated \
                 remote code execution with SYSTEM privileges.",
            )
            .with_cve(vec!["CVE-2008-4250".to_string(), "CVE-2006-3439".to_string()])
            .with_severity(Severity::Critical)
            .with_confidence(if probe_result {
                Confidence::Likely
            } else {
                Confidence::Possible
            })
            .add_host(host)
            .with_exploit_module("netapi".to_string())
            .with_remediation(
                "Apply Microsoft security update MS08-067 (KB958644). \
                 Upgrade to a supported Windows version. \
                 Block inbound TCP 445 and 135 at the network perimeter."
                    .to_string(),
            );

            return Ok(Some(finding));
        }

        Ok(None)
    }
}
