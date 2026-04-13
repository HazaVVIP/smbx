use smbx_core::{ExploitMode, Finding, SmbxResult};
use smbx_fingerprint::SmbFingerprinter;
use smbx_scanner::SmbScanner;
use smbx_vuln::{SigningDisabledCheck, SmbV1Check, VulnCheck, VulnRegistry};
use smbx_exploit::create_default_registry;
use log::{info, warn};

/// Orchestrates the full scanning pipeline
pub struct Orchestrator {
    timeout_secs: u64,
}

impl Orchestrator {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    /// Full scan pipeline: Scan → Fingerprint → VulnChecks → Exploitation
    pub async fn full_scan(
        &self,
        target: &str,
        port: u16,
        mode: ExploitMode,
    ) -> SmbxResult<Vec<Finding>> {
        let mut findings = Vec::new();

        info!("[Orchestrator] Starting full scan of {}:{} in {:?} mode", target, port, mode);

        // Step 1: Port scan
        info!("[Orchestrator] Step 1: Port scanning");
        let scanner = SmbScanner::new(port, self.timeout_secs, 1);
        match scanner.scan_host(target).await {
            Ok(result) => {
                if !result.open {
                    warn!("[Orchestrator] Port {} is closed on {}", port, target);
                    return Ok(findings);
                }
                info!("[Orchestrator] Port {} is open on {} ({}ms)", port, target, result.response_time_ms);
            }
            Err(e) => {
                warn!("[Orchestrator] Scan failed: {}", e);
                return Ok(findings);
            }
        }

        // Step 2: Fingerprinting
        info!("[Orchestrator] Step 2: Fingerprinting SMB target");
        let fingerprinter = SmbFingerprinter::new(self.timeout_secs);
        let fingerprint = match fingerprinter.fingerprint(target, port).await {
            Ok(fp) => {
                info!("[Orchestrator] Identified: {} {}", fp.dialect.as_str(), fp.os.as_str());
                Some(fp)
            }
            Err(e) => {
                warn!("[Orchestrator] Fingerprinting failed: {}", e);
                None
            }
        };

        // Step 3: Vulnerability checks
        info!("[Orchestrator] Step 3: Running vulnerability checks");
        let mut vuln_registry = VulnRegistry::new();

        // Register checks
        vuln_registry.register(Box::new(SmbV1Check::new(fingerprint.clone())));
        vuln_registry.register(Box::new(SigningDisabledCheck::new(fingerprint.clone())));

        match vuln_registry.run_all().await {
            Ok(vuln_findings) => {
                info!("[Orchestrator] Found {} vulnerabilities", vuln_findings.len());
                findings.extend(vuln_findings);
            }
            Err(e) => {
                warn!("[Orchestrator] Vulnerability checks failed: {}", e);
            }
        }

        // Step 4: Exploitation (if mode allows)
        if !matches!(mode, ExploitMode::Safe) || findings.iter().any(|f| f.exploit_module.is_some()) {
            info!("[Orchestrator] Step 4: Exploitation phase (mode: {:?})", mode);

            let exploit_registry = create_default_registry();

            for finding in &findings {
                if let Some(ref exploit_id) = finding.exploit_module {
                    if let Some(_exploit) = exploit_registry.find_by_id(exploit_id) {
                        if exploit_registry.can_run_at_mode(exploit_id, mode) {
                            info!("[Orchestrator] Running exploit: {}", exploit_id);

                            match exploit_registry.run_exploit_safe(exploit_id, target, port).await {
                                Ok(result) => {
                                    log::debug!("[Orchestrator] Exploit result: {:?}", result);
                                    if result.is_success() {
                                        info!("[Orchestrator] Exploit {} succeeded", exploit_id);
                                    }
                                }
                                Err(e) => {
                                    warn!("[Orchestrator] Exploit {} failed: {}", exploit_id, e);
                                }
                            }
                        } else {
                            warn!("[Orchestrator] Exploit {} requires higher mode", exploit_id);
                        }
                    }
                }
            }
        }

        info!("[Orchestrator] Scan complete. Found {} findings", findings.len());
        Ok(findings)
    }

    /// Quick fingerprint-only scan
    pub async fn fingerprint_only(&self, target: &str, port: u16) -> SmbxResult<Option<smbx_core::Fingerprint>> {
        let fingerprinter = SmbFingerprinter::new(self.timeout_secs);
        fingerprinter.fingerprint(target, port).await.map(Some)
    }

    /// List available checks
    pub fn list_checks(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("smb-v1-enabled", "Legacy SMBv1 protocol enabled"),
            ("smb-signing-disabled", "SMB message signing not required"),
            ("guest-account-enabled", "Guest account access allowed"),
            ("null-session-enabled", "Null session access allowed"),
        ]
    }

    /// List available exploits
    pub fn list_exploits(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("null_pivot", "Null Session Enumeration", "Safe"),
            ("guest_pivot", "Guest Account Access", "Safe"),
            ("ghost_probe", "SMBGhost Detection (CVE-2020-0796)", "Aggressive"),
            ("ntlm_relay", "NTLM Relay Attack", "Aggressive"),
            ("eternalblue", "EternalBlue RCE (MS17-010)", "Destructive"),
        ]
    }
}
