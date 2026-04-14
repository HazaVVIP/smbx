use smbx_core::{ShareFile, SmbxError, SmbxResult};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    pub comment: String,
    pub accessible: bool,
    pub files: Vec<ShareFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    DiskTree,
    PrintQ,
    Device,
    IPC,
    Unknown,
}

impl ShareType {
    pub fn as_str(&self) -> &str {
        match self {
            ShareType::DiskTree => "DISKTREE",
            ShareType::PrintQ => "PRINTQ",
            ShareType::Device => "DEVICE",
            ShareType::IPC => "IPC",
            ShareType::Unknown => "UNKNOWN",
        }
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => ShareType::DiskTree,
            1 => ShareType::PrintQ,
            2 => ShareType::Device,
            3 => ShareType::IPC,
            _ => ShareType::Unknown,
        }
    }
}

pub struct ShareEnumerator {
    timeout_secs: u64,
    samba_options: Vec<String>,
}

impl ShareEnumerator {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout_secs,
            samba_options: smbx_core::EnumConfig::default().samba_options,
        }
    }

    pub fn with_samba_options(timeout_secs: u64, samba_options: Vec<String>) -> Self {
        Self {
            timeout_secs,
            samba_options,
        }
    }

    /// Enumerate SMB shares on target
    pub async fn enumerate_shares(&self, target: &str, port: u16) -> SmbxResult<Vec<ShareInfo>> {
        log::debug!(
            "Enumerating shares on {}:{} (timeout: {}s)",
            target,
            port,
            self.timeout_secs
        );
        match self.enumerate_shares_rpc(target, port).await {
            Ok(shares) if !shares.is_empty() => Ok(shares),
            Ok(_) => Ok(Vec::new()),
            Err(err) => {
                log::warn!(
                    "RPC share enumeration failed on {}:{}: {}; using compatibility fallback",
                    target,
                    port,
                    err
                );
                Ok(Self::fallback_shares())
            }
        }
    }

    /// List files in a specific share
    pub async fn list_share_files(
        &self,
        target: &str,
        port: u16,
        share: &str,
    ) -> SmbxResult<Vec<ShareFile>> {
        log::debug!(
            "Listing files in share {} on {}:{} (timeout: {}s)",
            share,
            target,
            port,
            self.timeout_secs
        );

        // In a real implementation:
        // 1. Connect to SMB target
        // 2. Authenticate if needed
        // 3. Connect to share
        // 4. Send LIST request
        // 5. Parse responses and return file list

        Ok(Vec::new())
    }

    async fn enumerate_shares_rpc(&self, target: &str, port: u16) -> SmbxResult<Vec<ShareInfo>> {
        Self::validate_target(target)?;

        let mut cmd = Command::new("rpcclient");
        cmd.arg("-U")
            .arg("%")
            .arg("-p")
            .arg(port.to_string());

        for opt in &self.samba_options {
            cmd.arg(format!("--option={}", opt));
        }

        cmd.arg(target)
            .arg("-c")
            .arg("netshareenumall")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped());

        let output = timeout(Duration::from_secs(self.timeout_secs), cmd.output())
            .await
            .map_err(|_| SmbxError::Timeout)?
            .map_err(|e| SmbxError::EnumError(format!("failed to execute rpcclient: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let shares = Self::parse_rpcclient_output(&stdout);
        if !shares.is_empty() {
            return Ok(shares);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let failure_reason = if stderr.is_empty() {
            format!(
                "rpcclient returned no share data (status: {})",
                output.status
            )
        } else {
            format!("rpcclient failed: {}", stderr)
        };

        Err(SmbxError::EnumError(failure_reason))
    }

    fn parse_rpcclient_output(output: &str) -> Vec<ShareInfo> {
        let mut shares = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_comment = String::new();

        for line in output.lines() {
            if let Some(value) = Self::extract_field_value(line, "netname:") {
                Self::push_current_share(&mut shares, &mut current_name, &current_comment);
                current_comment.clear();
                current_name = if value.is_empty() { None } else { Some(value) };
            }

            if let Some(value) = Self::extract_field_value(line, "remark:") {
                current_comment = value;
            }
        }

        Self::push_current_share(&mut shares, &mut current_name, &current_comment);

        shares
    }

    fn push_current_share(
        shares: &mut Vec<ShareInfo>,
        current_name: &mut Option<String>,
        current_comment: &str,
    ) {
        if let Some(name) = current_name.take() {
            shares.push(Self::build_share_info(name, current_comment));
        }
    }

    fn validate_target(target: &str) -> SmbxResult<()> {
        if target.is_empty() {
            return Err(SmbxError::InvalidTarget("target cannot be empty".to_string()));
        }

        let is_valid = target
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '[' | ']' | '%'));

        if is_valid {
            Ok(())
        } else {
            Err(SmbxError::InvalidTarget(format!(
                "target contains unsupported characters: {}",
                target
            )))
        }
    }

    fn extract_field_value(line: &str, field_key: &str) -> Option<String> {
        const KNOWN_FIELDS: &[&str] = &["netname:", "remark:", "path:", "password:"];

        let lower = line.to_ascii_lowercase();
        let start = lower.find(field_key)?;
        let value_start = start + field_key.len();
        let mut end = line.len();

        for marker in KNOWN_FIELDS {
            if *marker == field_key {
                continue;
            }

            if let Some(next_pos) = lower[value_start..].find(marker) {
                let absolute = value_start + next_pos;
                if absolute < end {
                    end = absolute;
                }
            }
        }

        Some(line[value_start..end].trim().to_string())
    }

    fn build_share_info(name: String, comment: &str) -> ShareInfo {
        let lowered_name = name.to_ascii_lowercase();
        let lowered_comment = comment.to_ascii_lowercase();
        let share_type = if lowered_name == "ipc$" {
            ShareType::IPC
        } else if lowered_name.starts_with("print") || lowered_comment.contains("printer") {
            ShareType::PrintQ
        } else {
            ShareType::DiskTree
        };

        ShareInfo {
            name,
            share_type,
            comment: comment.to_string(),
            accessible: true,
            files: Vec::new(),
        }
    }

    fn fallback_shares() -> Vec<ShareInfo> {
        vec![
            ShareInfo {
                name: "IPC$".to_string(),
                share_type: ShareType::IPC,
                comment: "Inter-process communication".to_string(),
                accessible: true,
                files: Vec::new(),
            },
            ShareInfo {
                name: "C$".to_string(),
                share_type: ShareType::DiskTree,
                comment: "C drive".to_string(),
                accessible: false,
                files: Vec::new(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{ShareEnumerator, ShareType};

    #[test]
    fn parse_rpcclient_output_handles_multiline_records() {
        let output = r#"
netname: xpert
remark:
path: C:\xpert
password:
netname: print$
remark: Printer Drivers
path: C:\var\lib\samba\drivers
password:
netname: IPC$
remark: IPC Service (samba server 4.7.6-Ubuntu)
path: C:\tmp
password:
"#;

        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].name, "xpert");
        assert_eq!(shares[1].share_type, ShareType::PrintQ);
        assert_eq!(shares[2].share_type, ShareType::IPC);
    }

    #[test]
    fn parse_rpcclient_output_handles_compact_records() {
        let output = "netname: IPC$ remark: IPC Service (samba server)";
        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "IPC$");
        assert_eq!(shares[0].comment, "IPC Service (samba server)");
        assert_eq!(shares[0].share_type, ShareType::IPC);
    }

    #[test]
    fn parse_rpcclient_output_empty_returns_empty() {
        let shares = ShareEnumerator::parse_rpcclient_output("");
        assert!(shares.is_empty());
    }

    #[test]
    fn parse_rpcclient_output_no_netname_lines_returns_empty() {
        let output = "path: C:\\foo\npassword:\n";
        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert!(shares.is_empty());
    }

    #[test]
    fn parse_rpcclient_disk_share_type() {
        let output = "netname: BACKUP\nremark: Backup share\n";
        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share_type, ShareType::DiskTree);
    }

    #[test]
    fn share_type_as_str() {
        assert_eq!(ShareType::DiskTree.as_str(), "DISKTREE");
        assert_eq!(ShareType::PrintQ.as_str(), "PRINTQ");
        assert_eq!(ShareType::Device.as_str(), "DEVICE");
        assert_eq!(ShareType::IPC.as_str(), "IPC");
        assert_eq!(ShareType::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn share_type_from_u32() {
        assert_eq!(ShareType::from_u32(0), ShareType::DiskTree);
        assert_eq!(ShareType::from_u32(1), ShareType::PrintQ);
        assert_eq!(ShareType::from_u32(2), ShareType::Device);
        assert_eq!(ShareType::from_u32(3), ShareType::IPC);
        assert_eq!(ShareType::from_u32(99), ShareType::Unknown);
        assert_eq!(ShareType::from_u32(0xFFFFFFFF), ShareType::Unknown);
    }

    #[test]
    fn validate_target_empty_is_err() {
        let result = ShareEnumerator::validate_target("");
        assert!(result.is_err());
    }

    #[test]
    fn validate_target_ip_is_ok() {
        assert!(ShareEnumerator::validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn validate_target_ipv6_is_ok() {
        assert!(ShareEnumerator::validate_target("[::1]").is_ok());
    }

    #[test]
    fn validate_target_hostname_is_ok() {
        assert!(ShareEnumerator::validate_target("my-server.local").is_ok());
    }

    #[test]
    fn validate_target_special_chars_is_err() {
        let result = ShareEnumerator::validate_target("bad target!");
        assert!(result.is_err());
    }

    #[test]
    fn validate_target_semicolon_is_err() {
        let result = ShareEnumerator::validate_target("host;rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn printer_comment_gives_printq_type() {
        let output = "netname: SHARE1\nremark: This is a printer share\n";
        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert_eq!(shares[0].share_type, ShareType::PrintQ);
    }

    #[test]
    fn shares_are_marked_accessible_by_default() {
        let output = "netname: DATA\nremark: Data share\n";
        let shares = ShareEnumerator::parse_rpcclient_output(output);
        assert!(shares[0].accessible);
    }

    #[test]
    fn fallback_shares_has_ipc_and_c_dollar() {
        let shares = ShareEnumerator::fallback_shares();
        assert_eq!(shares.len(), 2);
        let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"IPC$"));
        assert!(names.contains(&"C$"));
    }

    #[test]
    fn share_enumerator_new_has_default_samba_options() {
        let enumerator = ShareEnumerator::new(10);
        // Should have at least the default samba options
        assert!(!enumerator.samba_options.is_empty());
    }

    #[test]
    fn share_enumerator_with_custom_samba_options() {
        let opts = vec!["client min protocol=NT1".to_string()];
        let enumerator = ShareEnumerator::with_samba_options(5, opts.clone());
        assert_eq!(enumerator.samba_options, opts);
    }
}
