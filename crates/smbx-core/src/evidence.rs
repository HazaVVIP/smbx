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
        }
    }
}
