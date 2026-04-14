use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Concrete evidence of vulnerability impact
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Evidence {
    /// Share and file listing enumeration result
    FileList {
        share: String,
        files: Vec<ShareFile>,
    },

    /// Sample of file contents (first 512 bytes)
    FileSample {
        path: String,
        size: u64,
        preview: Vec<u8>,
    },

    /// System crash proof (BSOD or segfault)
    CrashProof {
        timestamp: DateTime<Utc>,
        crash_code: String,
        details: String,
    },

    /// Memory leak captured from target
    MemoryLeak {
        leaked_bytes: Vec<u8>,
        location: String,
    },

    /// NTLMv2 hash captured from network relay
    CapturedHash {
        hash: String,
        username: String,
        domain: String,
    },

    /// Command execution output proof
    CommandOutput {
        command: String,
        output: String,
        timestamp: DateTime<Utc>,
    },

    /// Successful relay of credentials
    RelaySuccess {
        target: String,
        service: String,
        relayed_user: String,
    },

    /// Privilege escalation proof
    PrivEsc {
        before_user: String,
        after_user: String,
        method: String,
    },

    /// Code execution confirmation
    CodeExecution {
        injected_process: String,
        payload_hash: String,
        execution_timestamp: DateTime<Utc>,
    },

    /// SMB signing disabled confirmation
    SigningDisabled {
        dialect: String,
        capabilities: Vec<String>,
    },

    /// Null session successful establishment
    NullSessionEstablished {
        shares_enumerated: Vec<String>,
    },

    /// Generic text evidence
    TextEvidence {
        label: String,
        content: String,
    },

    /// Raw DCE/RPC response bytes captured from a named-pipe endpoint
    RpcResponse {
        endpoint: String,
        response_bytes: Vec<u8>,
    },

    /// Successful write to a named pipe (EternalRomance / EternalChampion)
    NamedPipeAccess {
        pipe_name: String,
        data_written: usize,
    },

    /// Shared library (.so) uploaded to a writable Samba share (SambaCry)
    SharedLibraryUploaded {
        share: String,
        path: String,
        size: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFile {
    pub name: String,
    pub path: String,
    pub size: Option<u64>,
    pub is_dir: bool,
    pub attributes: u32,
}

impl Evidence {
    pub fn label(&self) -> &str {
        match self {
            Evidence::FileList { .. } => "file_list",
            Evidence::FileSample { .. } => "file_sample",
            Evidence::CrashProof { .. } => "crash_proof",
            Evidence::MemoryLeak { .. } => "memory_leak",
            Evidence::CapturedHash { .. } => "captured_hash",
            Evidence::CommandOutput { .. } => "command_output",
            Evidence::RelaySuccess { .. } => "relay_success",
            Evidence::PrivEsc { .. } => "privesc",
            Evidence::CodeExecution { .. } => "code_execution",
            Evidence::SigningDisabled { .. } => "signing_disabled",
            Evidence::NullSessionEstablished { .. } => "null_session",
            Evidence::TextEvidence { .. } => "text_evidence",
            Evidence::RpcResponse { .. } => "rpc_response",
            Evidence::NamedPipeAccess { .. } => "named_pipe_access",
            Evidence::SharedLibraryUploaded { .. } => "shared_library_uploaded",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn evidence_labels() {
        let cases: Vec<(&str, Evidence)> = vec![
            (
                "file_list",
                Evidence::FileList {
                    share: "C$".to_string(),
                    files: vec![],
                },
            ),
            (
                "file_sample",
                Evidence::FileSample {
                    path: "/etc/passwd".to_string(),
                    size: 100,
                    preview: vec![0x41],
                },
            ),
            (
                "crash_proof",
                Evidence::CrashProof {
                    timestamp: Utc::now(),
                    crash_code: "BSOD".to_string(),
                    details: "blue screen".to_string(),
                },
            ),
            (
                "memory_leak",
                Evidence::MemoryLeak {
                    leaked_bytes: vec![0xDE, 0xAD],
                    location: "kernel".to_string(),
                },
            ),
            (
                "captured_hash",
                Evidence::CapturedHash {
                    hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
                    username: "admin".to_string(),
                    domain: "CORP".to_string(),
                },
            ),
            (
                "command_output",
                Evidence::CommandOutput {
                    command: "whoami".to_string(),
                    output: "nt authority\\system".to_string(),
                    timestamp: Utc::now(),
                },
            ),
            (
                "relay_success",
                Evidence::RelaySuccess {
                    target: "192.168.1.2".to_string(),
                    service: "smb".to_string(),
                    relayed_user: "CORP\\admin".to_string(),
                },
            ),
            (
                "privesc",
                Evidence::PrivEsc {
                    before_user: "user".to_string(),
                    after_user: "root".to_string(),
                    method: "token_impersonation".to_string(),
                },
            ),
            (
                "code_execution",
                Evidence::CodeExecution {
                    injected_process: "svchost.exe".to_string(),
                    payload_hash: "deadbeef".to_string(),
                    execution_timestamp: Utc::now(),
                },
            ),
            (
                "signing_disabled",
                Evidence::SigningDisabled {
                    dialect: "SMBv2".to_string(),
                    capabilities: vec![],
                },
            ),
            (
                "null_session",
                Evidence::NullSessionEstablished {
                    shares_enumerated: vec!["IPC$".to_string()],
                },
            ),
            (
                "text_evidence",
                Evidence::TextEvidence {
                    label: "test".to_string(),
                    content: "some output".to_string(),
                },
            ),
            (
                "rpc_response",
                Evidence::RpcResponse {
                    endpoint: r"\PIPE\srvsvc".to_string(),
                    response_bytes: vec![0x01, 0x02],
                },
            ),
            (
                "named_pipe_access",
                Evidence::NamedPipeAccess {
                    pipe_name: r"\PIPE\svcctl".to_string(),
                    data_written: 128,
                },
            ),
            (
                "shared_library_uploaded",
                Evidence::SharedLibraryUploaded {
                    share: "tmp".to_string(),
                    path: "/tmp/evil.so".to_string(),
                    size: 4096,
                },
            ),
        ];

        for (expected_label, evidence) in &cases {
            assert_eq!(
                evidence.label(),
                *expected_label,
                "label mismatch for {:?}",
                expected_label
            );
        }
    }

    #[test]
    fn share_file_fields() {
        let sf = ShareFile {
            name: "passwd".to_string(),
            path: "/etc/passwd".to_string(),
            size: Some(1234),
            is_dir: false,
            attributes: 0x20,
        };
        assert_eq!(sf.name, "passwd");
        assert_eq!(sf.size.unwrap(), 1234);
        assert!(!sf.is_dir);
    }
}
