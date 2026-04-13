mod cli;
mod orchestrator;

use cli::{Cli, Commands};
use clap::Parser;
use orchestrator::Orchestrator;
use smbx_core::ExploitMode;
use smbx_report::JsonReporter;
use std::io::Write;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(cli.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .format_timestamp_secs()
        .init();

    let orchestrator = Orchestrator::new(30);

    match cli.command {
        Commands::Scan {
            target,
            port,
            jobs,
            timeout,
        } => {
            println!("[*] Scanning {} on port {} ({} threads, {}s timeout)", target, port, jobs, timeout);

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
            assume_dialect: _,
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

            let orchestrator_with_timeout = Orchestrator::new(timeout);
            match orchestrator_with_timeout.full_scan(&target, port, exploit_mode).await {
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

            println!("[*] Running exploit: {} against {}:{}", exploit, target, port);

            let registry = smbx_exploit::create_default_registry();
            match registry.run_exploit_safe(&exploit, &target, port).await {
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

            let enumerator = smbx_enum::ShareEnumerator::new(timeout);
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
