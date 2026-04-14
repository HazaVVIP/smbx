use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub exploit: ExploitConfig,
    pub output: OutputConfig,
    pub logging: LoggingConfig,
    #[serde(rename = "enum", default)]
    pub enum_config: EnumConfig,
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
    pub mode: String, // "aggressive", "destructive"
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
            enum_config: EnumConfig::default(),
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
            mode: "aggressive".to_string(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumConfig {
    /// Extra Samba `--option=` flags passed to rpcclient/smbclient on every invocation.
    /// These are applied automatically as defaults so they never need to be typed manually.
    pub samba_options: Vec<String>,
}

impl Default for EnumConfig {
    fn default() -> Self {
        Self {
            samba_options: vec![
                "interfaces=lo".to_string(),
                "bind interfaces only=no".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_config_defaults() {
        let cfg = ScannerConfig::default();
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.max_threads, 16);
        assert_eq!(cfg.port_timeout_secs, 5);
        assert_eq!(cfg.min_port, 445);
        assert_eq!(cfg.max_port, 445);
    }

    #[test]
    fn exploit_config_defaults() {
        let cfg = ExploitConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "aggressive");
        assert!(!cfg.auto_pivot);
        assert_eq!(cfg.relay_listen_port, 0);
        assert!(cfg.rce_require_flag);
        assert!(cfg.targets.allowed_hosts.is_empty());
    }

    #[test]
    fn output_config_defaults() {
        let cfg = OutputConfig::default();
        assert_eq!(cfg.format, "json");
        assert!(cfg.file.is_none());
        assert!(!cfg.verbose);
        assert!(!cfg.include_raw_data);
    }

    #[test]
    fn logging_config_defaults() {
        let cfg = LoggingConfig::default();
        assert_eq!(cfg.level, "info");
        assert!(cfg.file.is_none());
    }

    #[test]
    fn enum_config_defaults() {
        let cfg = EnumConfig::default();
        assert_eq!(cfg.samba_options.len(), 2);
        assert!(cfg.samba_options.contains(&"interfaces=lo".to_string()));
        assert!(cfg
            .samba_options
            .contains(&"bind interfaces only=no".to_string()));
    }

    #[test]
    fn config_default_composes_sub_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.scanner.max_threads, 16);
        assert_eq!(cfg.output.format, "json");
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn exploit_targets_default_empty() {
        let t = ExploitTargets::default();
        assert!(t.allowed_hosts.is_empty());
    }

    #[test]
    fn config_is_clone() {
        let cfg = Config::default();
        let _ = cfg.clone();
    }

    #[test]
    fn config_serializes_to_json() {
        let cfg = Config::default();
        let json = serde_json::to_string(&cfg).expect("serialization failed");
        assert!(json.contains("scanner"));
        assert!(json.contains("exploit"));
    }

    #[test]
    fn config_round_trips_json() {
        let cfg = Config::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.scanner.max_threads, cfg2.scanner.max_threads);
        assert_eq!(cfg.output.format, cfg2.output.format);
    }
}
