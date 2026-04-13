use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub exploit: ExploitConfig,
    pub output: OutputConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub timeout_secs: u64,
    pub max_threads: usize,
    pub port_timeout_secs: u64,
    pub min_port: u16,
    pub max_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitConfig {
    pub enabled: bool,
    pub mode: String, // "safe", "aggressive", "destructive"
    pub auto_pivot: bool,
    pub relay_listen_port: u16,
    pub rce_require_flag: bool,
    pub targets: ExploitTargets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitTargets {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String, // "json", "text"
    pub file: Option<PathBuf>,
    pub verbose: bool,
    pub include_raw_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String, // "debug", "info", "warn", "error"
    pub file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scanner: ScannerConfig::default(),
            exploit: ExploitConfig::default(),
            output: OutputConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_threads: 16,
            port_timeout_secs: 5,
            min_port: 445,
            max_port: 445,
        }
    }
}

impl Default for ExploitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "safe".to_string(),
            auto_pivot: false,
            relay_listen_port: 0,
            rce_require_flag: true,
            targets: ExploitTargets::default(),
        }
    }
}

impl Default for ExploitTargets {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            file: None,
            verbose: false,
            include_raw_data: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
        }
    }
}
