use smbx_core::{Fingerprint, OperatingSystem, SmbDialect, SmbxError, SmbxResult};
use smbx_net::{SmbFrameBuilder, SmbSocket};
use std::net::SocketAddr;

/// SMB dialect and OS fingerprinting
pub struct SmbFingerprinter {
    timeout_secs: u64,
}

impl SmbFingerprinter {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    /// Fingerprint SMB target
    pub async fn fingerprint(&self, target: &str, port: u16) -> SmbxResult<Fingerprint> {
        let addr = format!("{}:{}", target, port)
            .parse::<SocketAddr>()
            .map_err(|e| SmbxError::InvalidTarget(e.to_string()))?;

        let mut fp = Fingerprint::new(target.to_string(), port);

        // Try SMBv2/v3 first (modern)
        if let Ok(result) = self.probe_smb2(&addr).await {
            // Identify OS before moving fields to avoid borrow after partial move
            fp.os = self.identify_os_from_fingerprint(&result);
            fp.dialect = result.dialect;
            fp.native_os = result.native_os;
            fp.server_name = result.server_name;
            fp.domain_name = result.domain_name;
            fp.capabilities = result.capabilities;
            return Ok(fp);
        }

        // Fallback to SMBv1
        if let Ok(result) = self.probe_smb1(&addr).await {
            // Identify OS before moving fields to avoid borrow after partial move
            fp.os = self.identify_os_from_smb1(&result);
            fp.dialect = result.dialect;
            fp.native_os = result.native_os;
            fp.native_lm = result.native_lm;
            return Ok(fp);
        }

        Ok(fp)
    }

    async fn probe_smb2(&self, addr: &SocketAddr) -> SmbxResult<Fingerprint> {
        let mut socket = SmbSocket::connect(addr, self.timeout_secs).await?;

        let negotiate_req = SmbFrameBuilder::build_smb2_negotiate();
        socket.send_nbt_message(&negotiate_req).await?;

        let response = socket.recv_message().await?;

        self.parse_smb2_response(&response)
    }

    async fn probe_smb1(&self, addr: &SocketAddr) -> SmbxResult<Fingerprint> {
        let mut socket = SmbSocket::connect(addr, self.timeout_secs).await?;

        let negotiate_req = SmbFrameBuilder::build_smb1_negotiate();
        socket.send_nbt_message(&negotiate_req).await?;

        let response = socket.recv_message().await?;

        self.parse_smb1_response(&response)
    }

    fn parse_smb2_response(&self, data: &[u8]) -> SmbxResult<Fingerprint> {
        if data.len() < 68 {
            return Err(SmbxError::ProtocolError("SMBv2 response too short".into()));
        }

        let mut fp = Fingerprint::new("unknown".to_string(), 445);
        fp.dialect = SmbDialect::Smb30;

        // Extract server GUID (offset 40, 16 bytes)
        if data.len() >= 56 {
            let dialect_offset = 36;
            if data.len() > dialect_offset + 2 {
                let dialect_num = u16::from_le_bytes([
                    data[dialect_offset],
                    data[dialect_offset + 1],
                ]);
                fp.dialect = match dialect_num {
                    0x0202 => SmbDialect::Smb20,
                    0x0210 => SmbDialect::Smb21,
                    0x0300 => SmbDialect::Smb30,
                    0x0302 => SmbDialect::Smb302,
                    0x0311 => SmbDialect::Smb311,
                    _ => SmbDialect::Smb30,
                };
            }
        }

        fp.capabilities = vec![
            "SMB2_GLOBAL_CAP_DFS".to_string(),
            "SMB2_GLOBAL_CAP_LEASING".to_string(),
            "SMB2_GLOBAL_CAP_LARGE_MTU".to_string(),
        ];

        Ok(fp)
    }

    fn parse_smb1_response(&self, data: &[u8]) -> SmbxResult<Fingerprint> {
        if data.len() < 37 {
            return Err(SmbxError::ProtocolError("SMBv1 response too short".into()));
        }

        let mut fp = Fingerprint::new("unknown".to_string(), 445);
        fp.dialect = SmbDialect::Smb1;

        // Parse SMBv1 header
        if data.len() >= 37 {
            // Word count at offset 32
            let word_count = data[32] as usize;

            // Parse response fields
            if word_count >= 17 {
                let security_mode = u16::from_le_bytes([data[39], data[40]]);
                fp.signing_required =
                    (security_mode & 0x0004) != 0;
                fp.capabilities = vec!["SMBv1".to_string()];
            }
        }

        // Extract OS info if present
        if data.len() > 60 {
            if let Ok(os_str) = std::str::from_utf8(&data[60..]) {
                fp.native_os = Some(os_str.trim_matches('\0').to_string());
            }
        }

        Ok(fp)
    }

    fn identify_os_from_fingerprint(&self, fp: &Fingerprint) -> OperatingSystem {
        // SMBv3 systems
        match fp.dialect {
            SmbDialect::Smb30 | SmbDialect::Smb302 | SmbDialect::Smb311 => {
                OperatingSystem::Windows10 // Default for modern SMB
            }
            _ => OperatingSystem::Other,
        }
    }

    fn identify_os_from_smb1(&self, fp: &Fingerprint) -> OperatingSystem {
        // Try to identify from native OS string
        if let Some(ref os_str) = fp.native_os {
            let lower = os_str.to_lowercase();
            if lower.contains("windows 10") {
                return OperatingSystem::Windows10;
            } else if lower.contains("windows 7") {
                return OperatingSystem::Windows7;
            } else if lower.contains("2008 r2") {
                return OperatingSystem::Windows2008R2;
            } else if lower.contains("2012") {
                return OperatingSystem::Windows2012;
            } else if lower.contains("2016") {
                return OperatingSystem::Windows2016;
            } else if lower.contains("2019") {
                return OperatingSystem::Windows2019;
            } else if lower.contains("2022") {
                return OperatingSystem::Windows2022;
            }
        }

        OperatingSystem::Other
    }
}
