mod cli;
mod orchestrator;

use cli::{Cli, Commands};
use clap::Parser;
use orchestrator::Orchestrator;
use smbx_core::{Config, ExploitMode, SmbDialect};
use smbx_report::JsonReporter;
use smbx_vuln::VulnCheck;
use std::io::Write;

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

/// Parse an `--assume-dialect` string (e.g. "SMB1", "SMB2.0", "SMB3.11") into
/// the matching `SmbDialect` variant.  Returns `None` if the string is unknown.
fn parse_dialect(s: &str) -> Option<SmbDialect> {
    // Normalise: upper-case, replace dots and hyphens with underscores.
    let norm = s.to_uppercase().replace('.', "_").replace('-', "_");
    match norm.as_str() {
        "SMB1" | "SMBV1" | "SMB_1" => Some(SmbDialect::Smb1),
        "SMB2" | "SMB2_0" | "SMBV2" | "SMBV2_0" => Some(SmbDialect::Smb20),
        "SMB2_1" | "SMBV2_1" => Some(SmbDialect::Smb21),
        "SMB3" | "SMB3_0" | "SMBV3" | "SMBV3_0" => Some(SmbDialect::Smb30),
        "SMB3_02" | "SMBV3_02" => Some(SmbDialect::Smb302),
        "SMB3_11" | "SMBV3_11" | "SMB3_1_1" => Some(SmbDialect::Smb311),
        _ => None,
    }
}

/// Try to load a `Config` from a TOML file.  Search order:
///   1. Explicit path from `--config`
///   2. `./config.toml`
///   3. `~/.config/smbx/config.toml`
///
/// Falls back to `Config::default()` if no file is found or parsing fails.
fn load_config(explicit: Option<&str>) -> Config {
    let candidates: Vec<std::path::PathBuf> = {
        let mut v = Vec::new();
        if let Some(p) = explicit {
            v.push(std::path::PathBuf::from(p));
        }
        v.push(std::path::PathBuf::from("config.toml"));
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = std::path::PathBuf::from(home);
            p.push(".config/smbx/config.toml");
            v.push(p);
        }
        v
    };

    for path in &candidates {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => match toml::from_str::<Config>(&content) {
                    Ok(cfg) => {
                        log::info!("Loaded config from {}", path.display());
                        return cfg;
                    }
                    Err(e) => {
                        log::warn!("Failed to parse config {}: {} — using defaults", path.display(), e);
                    }
                },
                Err(e) => {
                    log::warn!("Failed to read config {}: {} — using defaults", path.display(), e);
                }
            }
        }
    }

    Config::default()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(cli.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .format_timestamp_secs()
        .init();

    // Load configuration (config file is used for scanner/exploit defaults).
    let config = load_config(cli.config.as_deref());

    let orchestrator = Orchestrator::with_samba_options(
        config.scanner.timeout_secs,
        config.enum_config.samba_options.clone(),
    );

    match cli.command {
        Commands::Scan {
            target,
            port,
            jobs,
            timeout,
        } => {
            println!("[*] Scanning {} on port {} ({} threads, {}s timeout)", target, port, jobs, timeout);

            // CLI flags override config values when explicitly supplied.
            let scanner = smbx_scanner::SmbScanner::new(port, timeout, jobs);

            // Check if it's a CIDR or single host
            let results = if target.contains('/') {
                scanner.scan_network(&target).await?
            } else {
                vec![scanner.scan_host(&target).await?]
            };

            for result in results {
                if result.open {
                    println!("[+] {}:{} - OPEN ({}ms)", result.host, result.port, result.response_time_ms);
                }
            }
        }

        Commands::Fingerprint {
            target,
            port,
            timeout,
        } => {
            println!("[*] Fingerprinting {}:{}", target, port);

            let fingerprinter = smbx_fingerprint::SmbFingerprinter::new(timeout);
            match fingerprinter.fingerprint(&target, port).await {
                Ok(fp) => {
                    println!("[+] Dialect: {}", fp.dialect.as_str());
                    println!("[+] OS: {}", fp.os.as_str());
                    if let Some(ref os_str) = fp.native_os {
                        println!("[+] Native OS: {}", os_str);
                    }
                    if let Some(ref server) = fp.server_name {
                        println!("[+] Server: {}", server);
                    }
                    println!("[+] Signing Required: {}", fp.signing_required);
                    println!("[+] Capabilities: {}", fp.capabilities.join(", "));
                }
                Err(e) => {
                    eprintln!("[-] Fingerprinting failed: {}", e);
                }
            }
        }

        Commands::Full {
            target,
            port,
            mode,
            rce,
            assume_dialect,
            timeout,
        } => {
            println!("[*] Full scan {}:{} (mode: {}, timeout: {}s)", target, port, mode, timeout);

            let exploit_mode = match mode.to_lowercase().as_str() {
                "aggressive" => ExploitMode::Aggressive,
                "destructive" => ExploitMode::Destructive,
                _ => ExploitMode::Safe,
            };

            if rce && !matches!(exploit_mode, ExploitMode::Destructive) {
                eprintln!("[-] RCE flag requires destructive mode");
                return Ok(());
            }

            // Parse optional --assume-dialect flag.
            let dialect = assume_dialect.as_deref().and_then(|s| {
                let d = parse_dialect(s);
                if d.is_none() {
                    eprintln!(
                        "[-] Unknown dialect '{}'. Valid values: SMB1, SMB2.0, SMB2.1, SMB3.0, SMB3.02, SMB3.11",
                        s
                    );
                }
                d
            });

            let orchestrator_with_timeout = Orchestrator::with_samba_options(
                timeout,
                config.enum_config.samba_options.clone(),
            );
            match orchestrator_with_timeout.full_scan(&target, port, exploit_mode, dialect).await {
                Ok(findings) => {
                    println!("[+] Scan complete. Found {} findings", findings.len());

                    // Generate JSON report
                    match JsonReporter::generate_report(&findings, &target) {
                        Ok(json) => {
                            if let Some(output_file) = cli.output {
                                let mut file = std::fs::File::create(&output_file)?;
                                file.write_all(json.as_bytes())?;
                                println!("[+] Report written to {}", output_file);
                            } else {
                                println!("{}", json);
                            }
                        }
                        Err(e) => {
                            eprintln!("[-] Report generation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[-] Scan failed: {}", e);
                }
            }
        }

        Commands::Exploit {
            target,
            exploit,
            port,
            mode,
            rce,
            confirm,
            timeout,
        } => {
            if mode == "destructive" && !confirm {
                println!("[!] Destructive mode requires --confirm flag");
                return Ok(());
            }

            if rce && mode != "destructive" {
                println!("[!] RCE flag requires destructive mode");
                return Ok(());
            }

            let exploit_mode = match mode.to_lowercase().as_str() {
                "aggressive" => ExploitMode::Aggressive,
                "destructive" => ExploitMode::Destructive,
                _ => ExploitMode::Safe,
            };

            println!("[*] Running exploit: {} against {}:{} (timeout: {}s)", exploit, target, port, timeout);

            let registry = smbx_exploit::create_default_registry();
            match registry.run_exploit(&exploit, &target, port, exploit_mode).await {
                Ok(result) => {
                    println!("[+] Exploit result: {:?}", result);
                }
                Err(e) => {
                    eprintln!("[-] Exploit failed: {}", e);
                }
            }
        }

        Commands::Enum {
            target,
            port,
            timeout,
        } => {
            println!("[*] Enumerating shares on {}:{}", target, port);

            let enumerator = smbx_enum::ShareEnumerator::with_samba_options(
                timeout,
                config.enum_config.samba_options.clone(),
            );
            match enumerator.enumerate_shares(&target, port).await {
                Ok(shares) => {
                    for share in shares {
                        let status = if share.accessible { "✓" } else { "✗" };
                        println!("[{}] {} ({})", status, share.name, share.share_type.as_str());
                    }
                }
                Err(e) => {
                    eprintln!("[-] Enumeration failed: {}", e);
                }
            }
        }

        Commands::Check {
            target,
            check,
            port,
            timeout,
        } => {
            println!("[*] Running check: {} on {}:{}", check, target, port);

            let fingerprinter = smbx_fingerprint::SmbFingerprinter::new(timeout);
            match fingerprinter.fingerprint(&target, port).await {
                Ok(fp) => {
                    match check.as_str() {
                        "smb-v1-enabled" => {
                            let check = smbx_vuln::SmbV1Check::new(Some(fp));
                            match check.check().await {
                                Ok(Some(finding)) => {
                                    println!("[!] VULNERABLE: {}", finding.name);
                                    println!("    Severity: {:?}", finding.severity);
                                }
                                Ok(None) => println!("[-] Not vulnerable"),
                                Err(e) => eprintln!("[-] Check failed: {}", e),
                            }
                        }
                        "smb-signing-disabled" => {
                            let check = smbx_vuln::SigningDisabledCheck::new(Some(fp));
                            match check.check().await {
                                Ok(Some(finding)) => {
                                    println!("[!] VULNERABLE: {}", finding.name);
                                    println!("    Severity: {:?}", finding.severity);
                                }
                                Ok(None) => println!("[-] Not vulnerable"),
                                Err(e) => eprintln!("[-] Check failed: {}", e),
                            }
                        }
                        "null-session-enabled" => {
                            let check = smbx_vuln::NullSessionCheck::new(Some(fp));
                            match check.check().await {
                                Ok(Some(finding)) => {
                                    println!("[!] VULNERABLE: {}", finding.name);
                                    println!("    Severity: {:?}", finding.severity);
                                }
                                Ok(None) => println!("[-] Not vulnerable"),
                                Err(e) => eprintln!("[-] Check failed: {}", e),
                            }
                        }
                        "guest-account-enabled" => {
                            let check = smbx_vuln::GuestSessionCheck::new(Some(fp));
                            match check.check().await {
                                Ok(Some(finding)) => {
                                    println!("[!] VULNERABLE: {}", finding.name);
                                    println!("    Severity: {:?}", finding.severity);
                                }
                                Ok(None) => println!("[-] Not vulnerable"),
                                Err(e) => eprintln!("[-] Check failed: {}", e),
                            }
                        }
                        "smbghost-vulnerable" => {
                            let check = smbx_vuln::SmbGhostCheck::new(Some(fp));
                            match check.check().await {
                                Ok(Some(finding)) => {
                                    println!("[!] VULNERABLE: {}", finding.name);
                                    println!("    Severity: {:?}", finding.severity);
                                }
                                Ok(None) => println!("[-] Not vulnerable"),
                                Err(e) => eprintln!("[-] Check failed: {}", e),
                            }
                        }
                        _ => println!("[-] Unknown check: {}", check),
                    }
                }
                Err(e) => {
                    eprintln!("[-] Fingerprinting failed: {}", e);
                }
            }
        }

        Commands::List { checks, exploits } => {
            if checks {
                println!("\n[*] Available Vulnerability Checks:");
                for (id, desc) in orchestrator.list_checks() {
                    println!("  {} - {}", id, desc);
                }
            }

            if exploits {
                println!("\n[*] Available Exploits:");
                for (id, desc, mode) in orchestrator.list_exploits() {
                    println!("  {} - {} [{}]", id, desc, mode);
                }
            }

            if !checks && !exploits {
                println!("\n[*] Available Vulnerability Checks:");
                for (id, desc) in orchestrator.list_checks() {
                    println!("  {} - {}", id, desc);
                }
                println!("\n[*] Available Exploits:");
                for (id, desc, mode) in orchestrator.list_exploits() {
                    println!("  {} - {} [{}]", id, desc, mode);
                }
            }
        }
    }

    Ok(())
}

