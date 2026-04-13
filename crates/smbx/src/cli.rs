use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "smbx",
    about = "Enterprise-grade SMB/CIFS vulnerability scanner and exploitation tool",
    long_about = "SMBX: Comprehensive SMB/CIFS vulnerability detection and evidence-based exploitation framework"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Log level (debug, info, warn, error)
    #[arg(global = true, short, long, default_value = "info")]
    pub log_level: String,

    /// Output file (JSON)
    #[arg(global = true, short, long)]
    pub output: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan for open SMB ports
    Scan {
        /// Target host or CIDR network (e.g., 192.168.1.100 or 192.168.1.0/24)
        #[arg(value_name = "TARGET")]
        target: String,

        /// SMB port (default: 445)
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Number of concurrent threads
        #[arg(short = 'j', long, default_value = "16")]
        jobs: usize,

        /// Timeout per host (seconds)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Fingerprint SMB target (detect dialect and OS)
    Fingerprint {
        /// Target host
        #[arg(value_name = "TARGET")]
        target: String,

        /// SMB port (default: 445)
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Timeout (seconds)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Full vulnerability assessment against target
    Full {
        /// Target host
        #[arg(value_name = "TARGET")]
        target: String,

        /// SMB port (default: 445)
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Exploitation mode (safe, aggressive, destructive)
        #[arg(short, long, default_value = "safe")]
        mode: String,

        /// Enable RCE exploit (destructive mode only)
        #[arg(long)]
        rce: bool,

        /// Skip fingerprinting, assume this dialect (SMB1, SMB2.0, SMB2.1, SMB3.0, SMB3.02, SMB3.11)
        #[arg(long)]
        assume_dialect: Option<String>,

        /// Timeout (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Run specific vulnerability check
    Check {
        /// Target host
        #[arg(value_name = "TARGET")]
        target: String,

        /// Check ID (e.g., smb-v1-enabled, smb-signing-disabled)
        #[arg(value_name = "CHECK")]
        check: String,

        /// SMB port
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Timeout (seconds)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Run specific exploit
    Exploit {
        /// Target host
        #[arg(value_name = "TARGET")]
        target: String,

        /// Exploit ID (e.g., eternalblue, null_pivot, ghost_probe)
        #[arg(value_name = "EXPLOIT")]
        exploit: String,

        /// SMB port
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Exploitation mode (safe, aggressive, destructive)
        #[arg(short, long, default_value = "safe")]
        mode: String,

        /// Enable RCE (required for some exploits)
        #[arg(long)]
        rce: bool,

        /// Confirm destructive operation
        #[arg(long)]
        confirm: bool,

        /// Timeout (seconds)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Enumerate shares
    Enum {
        /// Target host
        #[arg(value_name = "TARGET")]
        target: String,

        /// SMB port
        #[arg(short, long, default_value = "445")]
        port: u16,

        /// Timeout (seconds)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// List available checks and exploits
    List {
        /// Show checks
        #[arg(long)]
        checks: bool,

        /// Show exploits
        #[arg(long)]
        exploits: bool,
    },
}
