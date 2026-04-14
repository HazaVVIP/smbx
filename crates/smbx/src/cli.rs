use clap::Parser;

#[derive(Parser)]
#[command(
    name = "smbx",
    about = "SMB/CIFS vulnerability scanner",
    long_about = "SMBX: Scan, fingerprint, check vulnerabilities, and enumerate shares in one step.\n\nExamples:\n  smbx 192.168.1.100\n  smbx 192.168.1.0/24"
)]
pub struct Cli {
    /// Target host or CIDR network (e.g. 192.168.1.100 or 192.168.1.0/24)
    #[arg(value_name = "TARGET")]
    pub target: String,
}
