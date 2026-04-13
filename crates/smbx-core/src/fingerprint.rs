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
