use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmbDialect {
    Smb1,
    Smb20,
    Smb21,
    Smb30,
    Smb302,
    Smb311,
    Unknown,
}

impl SmbDialect {
    pub fn as_str(&self) -> &str {
        match self {
            SmbDialect::Smb1 => "SMBv1",
            SmbDialect::Smb20 => "SMBv2.0",
            SmbDialect::Smb21 => "SMBv2.1",
            SmbDialect::Smb30 => "SMBv3.0",
            SmbDialect::Smb302 => "SMBv3.02",
            SmbDialect::Smb311 => "SMBv3.11",
            SmbDialect::Unknown => "Unknown",
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self, SmbDialect::Smb1)
    }

    pub fn supports_signing(&self) -> bool {
        !matches!(self, SmbDialect::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    WindowsXp,
    WindowsVista,
    Windows7,
    Windows8,
    Windows81,
    Windows10,
    Windows11,
    Windows2003,
    Windows2008,
    Windows2008R2,
    Windows2012,
    Windows2012R2,
    Windows2016,
    Windows2019,
    Windows2022,
    Linux,
    MacOS,
    Other,
}

impl OperatingSystem {
    pub fn as_str(&self) -> &str {
        match self {
            OperatingSystem::WindowsXp => "Windows XP",
            OperatingSystem::WindowsVista => "Windows Vista",
            OperatingSystem::Windows7 => "Windows 7",
            OperatingSystem::Windows8 => "Windows 8",
            OperatingSystem::Windows81 => "Windows 8.1",
            OperatingSystem::Windows10 => "Windows 10",
            OperatingSystem::Windows11 => "Windows 11",
            OperatingSystem::Windows2003 => "Windows Server 2003",
            OperatingSystem::Windows2008 => "Windows Server 2008",
            OperatingSystem::Windows2008R2 => "Windows Server 2008 R2",
            OperatingSystem::Windows2012 => "Windows Server 2012",
            OperatingSystem::Windows2012R2 => "Windows Server 2012 R2",
            OperatingSystem::Windows2016 => "Windows Server 2016",
            OperatingSystem::Windows2019 => "Windows Server 2019",
            OperatingSystem::Windows2022 => "Windows Server 2022",
            OperatingSystem::Linux => "Linux",
            OperatingSystem::MacOS => "macOS",
            OperatingSystem::Other => "Unknown",
        }
    }

    pub fn is_windows(&self) -> bool {
        matches!(
            self,
            OperatingSystem::WindowsXp
                | OperatingSystem::WindowsVista
                | OperatingSystem::Windows7
                | OperatingSystem::Windows8
                | OperatingSystem::Windows81
                | OperatingSystem::Windows10
                | OperatingSystem::Windows11
                | OperatingSystem::Windows2003
                | OperatingSystem::Windows2008
                | OperatingSystem::Windows2008R2
                | OperatingSystem::Windows2012
                | OperatingSystem::Windows2012R2
                | OperatingSystem::Windows2016
                | OperatingSystem::Windows2019
                | OperatingSystem::Windows2022
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub target: String,
    pub port: u16,
    pub dialect: SmbDialect,
    pub os: OperatingSystem,
    pub native_os: Option<String>,
    pub native_lm: Option<String>,
    pub server_name: Option<String>,
    pub domain_name: Option<String>,
    pub signing_required: bool,
    pub encryption_required: bool,
    pub capabilities: Vec<String>,
}

impl Fingerprint {
    pub fn new(target: String, port: u16) -> Self {
        Self {
            target,
            port,
            dialect: SmbDialect::Unknown,
            os: OperatingSystem::Other,
            native_os: None,
            native_lm: None,
            server_name: None,
            domain_name: None,
            signing_required: false,
            encryption_required: false,
            capabilities: Vec::new(),
        }
    }

    pub fn is_vulnerable_to_eternalblue(&self) -> bool {
        // EternalBlue (MS17-010) affects SMBv1 on specific Windows versions
        self.dialect == SmbDialect::Smb1
            && (matches!(
                self.os,
                OperatingSystem::WindowsVista
                    | OperatingSystem::Windows7
                    | OperatingSystem::Windows8
                    | OperatingSystem::Windows2008
                    | OperatingSystem::Windows2008R2
                    | OperatingSystem::Windows2012
            ))
    }

    pub fn is_vulnerable_to_smbghost(&self) -> bool {
        // SMBGhost (CVE-2020-0796) affects SMBv3 on Windows 10 and Server 2019
        self.dialect >= SmbDialect::Smb30
            && (matches!(
                self.os,
                OperatingSystem::Windows10 | OperatingSystem::Windows2019
            ))
    }
}

impl PartialOrd for SmbDialect {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SmbDialect {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            SmbDialect::Smb1 => 1,
            SmbDialect::Smb20 => 2,
            SmbDialect::Smb21 => 3,
            SmbDialect::Smb30 => 4,
            SmbDialect::Smb302 => 5,
            SmbDialect::Smb311 => 6,
            SmbDialect::Unknown => 0,
        };
        let other_val = match other {
            SmbDialect::Smb1 => 1,
            SmbDialect::Smb20 => 2,
            SmbDialect::Smb21 => 3,
            SmbDialect::Smb30 => 4,
            SmbDialect::Smb302 => 5,
            SmbDialect::Smb311 => 6,
            SmbDialect::Unknown => 0,
        };
        self_val.cmp(&other_val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // SmbDialect
    // ------------------------------------------------------------------

    #[test]
    fn smb_dialect_as_str() {
        assert_eq!(SmbDialect::Smb1.as_str(), "SMBv1");
        assert_eq!(SmbDialect::Smb20.as_str(), "SMBv2.0");
        assert_eq!(SmbDialect::Smb21.as_str(), "SMBv2.1");
        assert_eq!(SmbDialect::Smb30.as_str(), "SMBv3.0");
        assert_eq!(SmbDialect::Smb302.as_str(), "SMBv3.02");
        assert_eq!(SmbDialect::Smb311.as_str(), "SMBv3.11");
        assert_eq!(SmbDialect::Unknown.as_str(), "Unknown");
    }

    #[test]
    fn smb_dialect_is_legacy_only_smb1() {
        assert!(SmbDialect::Smb1.is_legacy());
        assert!(!SmbDialect::Smb20.is_legacy());
        assert!(!SmbDialect::Smb311.is_legacy());
        assert!(!SmbDialect::Unknown.is_legacy());
    }

    #[test]
    fn smb_dialect_supports_signing_not_unknown() {
        assert!(SmbDialect::Smb1.supports_signing());
        assert!(SmbDialect::Smb20.supports_signing());
        assert!(SmbDialect::Smb311.supports_signing());
        assert!(!SmbDialect::Unknown.supports_signing());
    }

    #[test]
    fn smb_dialect_ordering() {
        assert!(SmbDialect::Unknown < SmbDialect::Smb1);
        assert!(SmbDialect::Smb1 < SmbDialect::Smb20);
        assert!(SmbDialect::Smb20 < SmbDialect::Smb21);
        assert!(SmbDialect::Smb21 < SmbDialect::Smb30);
        assert!(SmbDialect::Smb30 < SmbDialect::Smb302);
        assert!(SmbDialect::Smb302 < SmbDialect::Smb311);
    }

    #[test]
    fn smb_dialect_ordering_ge() {
        assert!(SmbDialect::Smb30 >= SmbDialect::Smb30);
        assert!(SmbDialect::Smb311 > SmbDialect::Smb1);
    }

    #[test]
    fn smb_dialect_is_copy() {
        let d = SmbDialect::Smb1;
        let _ = d;
        let _ = d; // copy semantics
    }

    // ------------------------------------------------------------------
    // OperatingSystem
    // ------------------------------------------------------------------

    #[test]
    fn os_as_str() {
        assert_eq!(OperatingSystem::WindowsXp.as_str(), "Windows XP");
        assert_eq!(OperatingSystem::Windows7.as_str(), "Windows 7");
        assert_eq!(OperatingSystem::Windows10.as_str(), "Windows 10");
        assert_eq!(OperatingSystem::Windows2019.as_str(), "Windows Server 2019");
        assert_eq!(OperatingSystem::Linux.as_str(), "Linux");
        assert_eq!(OperatingSystem::MacOS.as_str(), "macOS");
        assert_eq!(OperatingSystem::Other.as_str(), "Unknown");
    }

    #[test]
    fn os_is_windows_true_for_windows_variants() {
        let windows_oses = [
            OperatingSystem::WindowsXp,
            OperatingSystem::WindowsVista,
            OperatingSystem::Windows7,
            OperatingSystem::Windows8,
            OperatingSystem::Windows81,
            OperatingSystem::Windows10,
            OperatingSystem::Windows11,
            OperatingSystem::Windows2003,
            OperatingSystem::Windows2008,
            OperatingSystem::Windows2008R2,
            OperatingSystem::Windows2012,
            OperatingSystem::Windows2012R2,
            OperatingSystem::Windows2016,
            OperatingSystem::Windows2019,
            OperatingSystem::Windows2022,
        ];
        for os in &windows_oses {
            assert!(os.is_windows(), "{} should be windows", os.as_str());
        }
    }

    #[test]
    fn os_is_windows_false_for_non_windows() {
        assert!(!OperatingSystem::Linux.is_windows());
        assert!(!OperatingSystem::MacOS.is_windows());
        assert!(!OperatingSystem::Other.is_windows());
    }

    // ------------------------------------------------------------------
    // Fingerprint
    // ------------------------------------------------------------------

    #[test]
    fn fingerprint_new_defaults() {
        let fp = Fingerprint::new("192.168.1.1".to_string(), 445);
        assert_eq!(fp.target, "192.168.1.1");
        assert_eq!(fp.port, 445);
        assert_eq!(fp.dialect, SmbDialect::Unknown);
        assert_eq!(fp.os, OperatingSystem::Other);
        assert!(!fp.signing_required);
        assert!(!fp.encryption_required);
        assert!(fp.capabilities.is_empty());
    }

    #[test]
    fn fingerprint_vulnerable_to_eternalblue() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb1;
        fp.os = OperatingSystem::Windows7;
        assert!(fp.is_vulnerable_to_eternalblue());
    }

    #[test]
    fn fingerprint_not_vulnerable_eternalblue_wrong_dialect() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb20;
        fp.os = OperatingSystem::Windows7;
        assert!(!fp.is_vulnerable_to_eternalblue());
    }

    #[test]
    fn fingerprint_not_vulnerable_eternalblue_wrong_os() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb1;
        fp.os = OperatingSystem::Windows10;
        assert!(!fp.is_vulnerable_to_eternalblue());
    }

    #[test]
    fn fingerprint_eternalblue_all_affected_os() {
        let affected = [
            OperatingSystem::WindowsVista,
            OperatingSystem::Windows7,
            OperatingSystem::Windows8,
            OperatingSystem::Windows2008,
            OperatingSystem::Windows2008R2,
            OperatingSystem::Windows2012,
        ];
        for os in &affected {
            let mut fp = Fingerprint::new("h".to_string(), 445);
            fp.dialect = SmbDialect::Smb1;
            fp.os = *os;
            assert!(
                fp.is_vulnerable_to_eternalblue(),
                "{} should be eternalblue-vulnerable",
                os.as_str()
            );
        }
    }

    #[test]
    fn fingerprint_vulnerable_to_smbghost() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb30;
        fp.os = OperatingSystem::Windows10;
        assert!(fp.is_vulnerable_to_smbghost());
    }

    #[test]
    fn fingerprint_smbghost_smb311_server2019() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.os = OperatingSystem::Windows2019;
        assert!(fp.is_vulnerable_to_smbghost());
    }

    #[test]
    fn fingerprint_not_vulnerable_smbghost_wrong_os() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb311;
        fp.os = OperatingSystem::Windows7;
        assert!(!fp.is_vulnerable_to_smbghost());
    }

    #[test]
    fn fingerprint_not_vulnerable_smbghost_wrong_dialect() {
        let mut fp = Fingerprint::new("10.0.0.1".to_string(), 445);
        fp.dialect = SmbDialect::Smb21;
        fp.os = OperatingSystem::Windows10;
        assert!(!fp.is_vulnerable_to_smbghost());
    }
}
