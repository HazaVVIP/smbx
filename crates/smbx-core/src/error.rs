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
