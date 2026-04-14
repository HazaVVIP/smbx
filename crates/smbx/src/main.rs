mod cli;
mod orchestrator;

use cli::Cli;
use clap::Parser;
use orchestrator::Orchestrator;
use smbx_core::{Config, ExploitMode};
use smbx_report::JsonReporter;

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

/// Try to load a `Config` from a TOML file.  Search order:
///   1. `./config.toml`
///   2. `~/.config/smbx/config.toml`
///
/// Falls back to `Config::default()` if no file is found or parsing fails.
fn load_config() -> Config {
    let mut candidates: Vec<std::path::PathBuf> = vec![
        std::path::PathBuf::from("config.toml"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = std::path::PathBuf::from(home);
        p.push(".config/smbx/config.toml");
        candidates.push(p);
    }

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

    // Initialize logging. Override the default level via the RUST_LOG env var
    // (e.g. `RUST_LOG=debug smbx 192.168.1.100`).
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_secs()
        .init();

    let config = load_config();

    const PORT: u16 = 445;
    const SCAN_TIMEOUT: u64 = 10;
    const SCAN_JOBS: usize = 16;
    const FULL_TIMEOUT: u64 = 30;

    // Step 1: Discover open hosts (CIDR or single host).
    println!("[*] Scanning {} on port {} ({} threads, {}s timeout)", cli.target, PORT, SCAN_JOBS, SCAN_TIMEOUT);
    let scanner = smbx_scanner::SmbScanner::new(PORT, SCAN_TIMEOUT, SCAN_JOBS);
    let scan_results = if cli.target.contains('/') {
        scanner.scan_network(&cli.target).await?
    } else {
        vec![scanner.scan_host(&cli.target).await?]
    };

    let open_hosts: Vec<String> = scan_results
        .into_iter()
        .filter(|r| {
            if r.open {
                println!("[+] {}:{} - OPEN ({}ms)", r.host, r.port, r.response_time_ms);
            }
            r.open
        })
        .map(|r| r.host)
        .collect();

    if open_hosts.is_empty() {
        println!("[-] No open SMB hosts found.");
        return Ok(());
    }

    // Steps 2-5 per open host: fingerprint → vuln checks → enum → report.
    let orchestrator = Orchestrator::with_samba_options(
        FULL_TIMEOUT,
        config.enum_config.samba_options.clone(),
    );

    for host in &open_hosts {
        println!("\n[*] Running full assessment on {}:{}", host, PORT);

        match orchestrator.full_scan(host, PORT, ExploitMode::Aggressive, None).await {
            Ok(findings) => {
                println!("[+] Assessment complete for {}. Found {} finding(s).", host, findings.len());

                match JsonReporter::generate_report(&findings, host) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("[-] Report generation failed: {}", e),
                }
            }
            Err(e) => eprintln!("[-] Assessment failed for {}: {}", host, e),
        }
    }

    Ok(())
}
