use smbx_core::{ExploitMode, Evidence, Finding, Fingerprint, SmbDialect, SmbxResult};
use smbx_enum::ShareEnumerator;
use smbx_fingerprint::SmbFingerprinter;
use smbx_scanner::SmbScanner;
use smbx_vuln::{
    GuestSessionCheck, NullSessionCheck, SigningDisabledCheck, SmbGhostCheck, SmbV1Check,
    VulnRegistry,
};
use smbx_exploit::create_default_registry;
use log::{info, warn};

/// Orchestrates the full scanning pipeline
pub struct Orchestrator {
    timeout_secs: u64,
    /// Samba CLI options forwarded to the share enumerator (e.g. `interfaces=lo`).
    samba_options: Vec<String>,
}

impl Orchestrator {
    #[allow(dead_code)]
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout_secs,
            samba_options: smbx_core::EnumConfig::default().samba_options,
        }
    }

    pub fn with_samba_options(timeout_secs: u64, samba_options: Vec<String>) -> Self {
        Self { timeout_secs, samba_options }
    }

    /// Full scan pipeline: Scan → Fingerprint → Enumerate → VulnChecks → Exploitation
    ///
    /// `assume_dialect` — when `Some`, fingerprinting is skipped and a synthetic
    /// `Fingerprint` with that dialect is used instead.
    pub async fn full_scan(
        &self,
        target: &str,
        port: u16,
        mode: ExploitMode,
        assume_dialect: Option<SmbDialect>,
    ) -> SmbxResult<Vec<Finding>> {
        let mut findings = Vec::new();

        info!("[Orchestrator] Starting full scan of {}:{} in {:?} mode", target, port, mode);

        // Step 1/5: Port scan
        println!("[1/5] Scanning {}:{} for open SMB port…", target, port);
        let scanner = SmbScanner::new(port, self.timeout_secs, 1);
        match scanner.scan_host(target).await {
            Ok(result) => {
                if !result.open {
                    warn!("[Orchestrator] Port {} is closed on {}", port, target);
                    println!("[-] Port {} is closed on {} — aborting", port, target);
                    return Ok(findings);
                }
                info!("[Orchestrator] Port {} is open on {} ({}ms)", port, target, result.response_time_ms);
                println!("[+] Port {} open ({}ms)", port, result.response_time_ms);
            }
            Err(e) => {
                warn!("[Orchestrator] Scan failed: {}", e);
                println!("[-] Scan failed: {}", e);
                return Ok(findings);
            }
        }

        // Step 2/5: Fingerprinting (or use assumed dialect)
        let fingerprint: Option<Fingerprint> = if let Some(dialect) = assume_dialect {
            println!("[2/5] Skipping fingerprint — using assumed dialect: {}", dialect.as_str());
            info!("[Orchestrator] Using assumed dialect: {}", dialect.as_str());
            let mut fp = Fingerprint::new(target.to_string(), port);
            fp.dialect = dialect;
            Some(fp)
        } else {
            println!("[2/5] Fingerprinting SMB target {}:{}…", target, port);
            let fingerprinter = SmbFingerprinter::new(self.timeout_secs);
            match fingerprinter.fingerprint(target, port).await {
                Ok(fp) => {
                    info!("[Orchestrator] Identified: {} {}", fp.dialect.as_str(), fp.os.as_str());
                    println!("[+] Dialect: {}  OS: {}", fp.dialect.as_str(), fp.os.as_str());
                    Some(fp)
                }
                Err(e) => {
                    warn!("[Orchestrator] Fingerprinting failed: {}", e);
                    println!("[-] Fingerprinting failed: {}", e);
                    None
                }
            }
        };

        // Step 3/5: Share enumeration
        println!("[3/5] Enumerating shares on {}:{}…", target, port);
        let enumerator = ShareEnumerator::with_samba_options(
            self.timeout_secs,
            self.samba_options.clone(),
        );
        let enumerated_shares = match enumerator.enumerate_shares(target, port).await {
            Ok(shares) => {
                info!("[Orchestrator] Enumerated {} share(s)", shares.len());
                if shares.is_empty() {
                    println!("[-] No shares discovered");
                } else {
                    for s in &shares {
                        let mark = if s.accessible { "✓" } else { "✗" };
                        println!("    [{}] {} ({})", mark, s.name, s.share_type.as_str());
                    }
                }
                shares
            }
            Err(e) => {
                warn!("[Orchestrator] Share enumeration failed: {}", e);
                println!("[-] Share enumeration failed: {}", e);
                Vec::new()
            }
        };

        // Build a share-list evidence item to attach to session-related findings later.
        let share_names: Vec<String> = enumerated_shares.iter().map(|s| s.name.clone()).collect();
        let share_evidence = if !share_names.is_empty() {
            Some(Evidence::NullSessionEstablished {
                shares_enumerated: share_names,
            })
        } else {
            None
        };

        // Step 4/5: Vulnerability checks
        println!("[4/5] Running vulnerability checks on {}:{}…", target, port);
        let mut vuln_registry = VulnRegistry::new();
        vuln_registry.register(Box::new(SmbV1Check::new(fingerprint.clone())));
        vuln_registry.register(Box::new(SigningDisabledCheck::new(fingerprint.clone())));
        vuln_registry.register(Box::new(NullSessionCheck::new(fingerprint.clone())));
        vuln_registry.register(Box::new(GuestSessionCheck::new(fingerprint.clone())));
        vuln_registry.register(Box::new(SmbGhostCheck::new(fingerprint.clone())));

        match vuln_registry.run_all().await {
            Ok(mut vuln_findings) => {
                info!("[Orchestrator] Found {} vulnerabilities", vuln_findings.len());
                println!("[+] {} vulnerability finding(s) detected", vuln_findings.len());

                // Attach share evidence to session-related findings.
                if let Some(ref ev) = share_evidence {
                    for f in &mut vuln_findings {
                        if let Some(ref module) = f.exploit_module.clone() {
                            if module == "null_pivot" || module == "guest_pivot" {
                                f.push_evidence(ev.clone());
                            }
                        }
                    }
                }

                findings.extend(vuln_findings);
            }
            Err(e) => {
                warn!("[Orchestrator] Vulnerability checks failed: {}", e);
                println!("[-] Vulnerability checks failed: {}", e);
            }
        }

        // Step 5/5: Exploitation — attempt for every finding that has an exploit module
        let exploit_count = findings.iter().filter(|f| f.exploit_module.is_some()).count();
        println!(
            "[5/5] Running {} exploit module(s) in {:?} mode…",
            exploit_count, mode
        );
        info!(
            "[Orchestrator] Step 5: Exploitation phase (mode: {:?}, {} exploit(s) to attempt)",
            mode, exploit_count
        );

        let exploit_registry = create_default_registry();

        for finding in &mut findings {
            if let Some(exploit_id) = finding.exploit_module.clone() {
                match exploit_registry.run_exploit(&exploit_id, target, port, mode).await {
                    Ok(result) => {
                        match result {
                            smbx_core::ExploitResult::Proven { evidence, ref message } => {
                                info!("[Orchestrator] Exploit {}: Proven – {}", exploit_id, message);
                                finding.push_evidence(evidence);
                                finding.set_confidence(smbx_core::Confidence::Confirmed);
                            }
                            smbx_core::ExploitResult::PartialProof { evidence, ref message } => {
                                info!("[Orchestrator] Exploit {}: PartialProof – {}", exploit_id, message);
                                finding.push_evidence(evidence);
                            }
                            smbx_core::ExploitResult::Inconclusive { ref reason } => {
                                warn!("[Orchestrator] Exploit {}: Inconclusive – {}", exploit_id, reason);
                            }
                            smbx_core::ExploitResult::Skipped { ref reason } => {
                                // Log at info so the operator can see which exploits were skipped
                                // and why (usually the current mode is too low).
                                info!(
                                    "[Orchestrator] Exploit {} skipped: {} (current mode: {:?})",
                                    exploit_id, reason, mode
                                );
                            }
                            smbx_core::ExploitResult::RequiresConsent { ref operation, ref reason } => {
                                warn!(
                                    "[Orchestrator] Exploit {} requires explicit consent \
                                     (use --confirm with destructive mode): {} – {}",
                                    exploit_id, operation, reason
                                );
                            }
                            smbx_core::ExploitResult::Failed { ref error } => {
                                warn!("[Orchestrator] Exploit {}: Failed – {}", exploit_id, error);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[Orchestrator] Exploit {} error: {}", exploit_id, e);
                    }
                }
            }
        }

        info!("[Orchestrator] Scan complete. Found {} findings", findings.len());
        println!("[*] Scan complete — {} finding(s) total", findings.len());
        Ok(findings)
    }

    /// Quick fingerprint-only scan.
    #[allow(dead_code)]
    pub async fn fingerprint_only(&self, target: &str, port: u16) -> SmbxResult<Option<smbx_core::Fingerprint>> {
        let fingerprinter = SmbFingerprinter::new(self.timeout_secs);
        fingerprinter.fingerprint(target, port).await.map(Some)
    }

    /// List available checks
    pub fn list_checks(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("smb-v1-enabled", "Legacy SMBv1 protocol enabled"),
            ("smb-signing-disabled", "SMB message signing not required"),
            ("null-session-enabled", "Null session access allowed"),
            ("guest-account-enabled", "Guest account access allowed"),
            ("smbghost-vulnerable", "SMBGhost (CVE-2020-0796) vulnerability"),
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

