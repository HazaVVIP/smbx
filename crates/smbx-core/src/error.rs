use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum SmbxError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("SMB negotiation failed: {0}")]
    NegotiationError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Vulnerability check failed: {0}")]
    VulnCheckError(String),

    #[error("Exploitation failed: {0}")]
    ExploitError(String),

    #[error("Enumeration failed: {0}")]
    EnumError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Timeout")]
    Timeout,

    #[error("Operation not supported: {0}")]
    NotSupported(String),

    #[error("Consent required for operation: {0}")]
    ConsentRequired(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type SmbxResult<T> = Result<T, SmbxError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_error_display() {
        let e = SmbxError::NetworkError("connection refused".to_string());
        assert_eq!(e.to_string(), "Network error: connection refused");
    }

    #[test]
    fn protocol_error_display() {
        let e = SmbxError::ProtocolError("bad magic".to_string());
        assert_eq!(e.to_string(), "Protocol error: bad magic");
    }

    #[test]
    fn negotiation_error_display() {
        let e = SmbxError::NegotiationError("no common dialect".to_string());
        assert_eq!(e.to_string(), "SMB negotiation failed: no common dialect");
    }

    #[test]
    fn auth_error_display() {
        let e = SmbxError::AuthError("bad credentials".to_string());
        assert_eq!(e.to_string(), "Authentication failed: bad credentials");
    }

    #[test]
    fn vuln_check_error_display() {
        let e = SmbxError::VulnCheckError("timeout".to_string());
        assert_eq!(e.to_string(), "Vulnerability check failed: timeout");
    }

    #[test]
    fn exploit_error_display() {
        let e = SmbxError::ExploitError("shellcode failed".to_string());
        assert_eq!(e.to_string(), "Exploitation failed: shellcode failed");
    }

    #[test]
    fn enum_error_display() {
        let e = SmbxError::EnumError("no shares".to_string());
        assert_eq!(e.to_string(), "Enumeration failed: no shares");
    }

    #[test]
    fn config_error_display() {
        let e = SmbxError::ConfigError("missing field".to_string());
        assert_eq!(e.to_string(), "Configuration error: missing field");
    }

    #[test]
    fn io_error_display() {
        let e = SmbxError::IoError("file not found".to_string());
        assert_eq!(e.to_string(), "IO error: file not found");
    }

    #[test]
    fn timeout_display() {
        let e = SmbxError::Timeout;
        assert_eq!(e.to_string(), "Timeout");
    }

    #[test]
    fn not_supported_display() {
        let e = SmbxError::NotSupported("SMBv3 encrypt".to_string());
        assert_eq!(e.to_string(), "Operation not supported: SMBv3 encrypt");
    }

    #[test]
    fn consent_required_display() {
        let e = SmbxError::ConsentRequired("write exploit".to_string());
        assert_eq!(e.to_string(), "Consent required for operation: write exploit");
    }

    #[test]
    fn invalid_target_display() {
        let e = SmbxError::InvalidTarget("bad ip".to_string());
        assert_eq!(e.to_string(), "Invalid target: bad ip");
    }

    #[test]
    fn internal_error_display() {
        let e = SmbxError::InternalError("unexpected state".to_string());
        assert_eq!(e.to_string(), "Internal error: unexpected state");
    }

    #[test]
    fn smbx_result_ok() {
        let r: SmbxResult<u32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn smbx_result_err() {
        let r: SmbxResult<u32> = Err(SmbxError::Timeout);
        assert!(r.is_err());
    }

    #[test]
    fn error_is_clone() {
        let e = SmbxError::NetworkError("x".to_string());
        let _ = e.clone();
    }
}
