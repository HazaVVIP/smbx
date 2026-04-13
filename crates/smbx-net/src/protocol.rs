// SMB Protocol Constants

pub const SMB_MAGIC: &[u8] = b"\xffSMB";
pub const SMB2_MAGIC: &[u8] = b"\xfeSMB";

pub const NBT_SESSION_REQUEST: u8 = 0x81;
pub const NBT_SESSION_MESSAGE: u8 = 0x00;
pub const NBT_SESSION_NEGATIVE: u8 = 0x83;
pub const NBT_SESSION_RETARGET: u8 = 0x84;

// SMBv1 Commands
pub const SMB_COM_NEGOTIATE: u8 = 0x72;
pub const SMB_COM_SESSION_SETUP_ANDX: u8 = 0x73;
pub const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
pub const SMB_COM_OPEN_ANDX: u8 = 0x2D;
pub const SMB_COM_READ_ANDX: u8 = 0x2E;
pub const SMB_COM_WRITE_ANDX: u8 = 0x2F;
pub const SMB_COM_CLOSE: u8 = 0x04;
pub const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
pub const SMB_COM_LOGOFF_ANDX: u8 = 0x74;

// SMBv2/v3 Commands
pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_QUERY_INFO: u16 = 0x0010;
pub const SMB2_SET_INFO: u16 = 0x0011;

// SMBv1 Flags
pub const SMB_FLAGS_RESPONSE: u8 = 0x80;
pub const SMB_FLAGS2_LONG_FILENAMES: u16 = 0x0001;
pub const SMB_FLAGS2_UNICODE: u16 = 0x0080;
pub const SMB_FLAGS2_SMB_SECURITY_SIGNATURE: u16 = 0x0004;

// SMB Dialects
pub const DIALECT_CORE: &str = "CORE";
pub const DIALECT_COREPLUS: &str = "COREPLUS";
pub const DIALECT_SMB1: &str = "LANMAN1.0";
pub const DIALECT_LM12: &str = "LM1.2X002";
pub const DIALECT_SMB20: &str = "SMB 2.002";
pub const DIALECT_SMB21: &str = "SMB 2.1";
pub const DIALECT_SMB30: &str = "SMB 3.0";
pub const DIALECT_SMB302: &str = "SMB 3.02";
pub const DIALECT_SMB311: &str = "SMB 3.1.1";

// Authentication Types
pub const AUTH_NTLM: u8 = 0x01;
pub const AUTH_NTLMV2: u8 = 0x02;
pub const AUTH_KERBEROS: u8 = 0x04;

// Share Types
pub const STYPE_DISKTREE: u32 = 0x00000000;
pub const STYPE_PRINTQ: u32 = 0x00000001;
pub const STYPE_DEVICE: u32 = 0x00000002;
pub const STYPE_IPC: u32 = 0x00000003;
pub const STYPE_HIDDEN: u32 = 0x80000000;

// File Attributes
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;
pub const FILE_ATTRIBUTE_VOLUME: u32 = 0x00000008;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x00000020;

// Access Masks
pub const FILE_READ_DATA: u32 = 0x00000001;
pub const FILE_WRITE_DATA: u32 = 0x00000002;
pub const FILE_APPEND_DATA: u32 = 0x00000004;
pub const FILE_EXECUTE: u32 = 0x00000020;

// Capabilities
pub const CAP_RAW_MODE: u32 = 0x00000001;
pub const CAP_MPX_MODE: u32 = 0x00000002;
pub const CAP_UNICODE: u32 = 0x00000004;
pub const CAP_LARGE_FILES: u32 = 0x00000008;
pub const CAP_NT_SMBS: u32 = 0x00000010;
pub const CAP_RPC_REMOTE_APIS: u32 = 0x00000020;
pub const CAP_LOCK_AND_READ: u32 = 0x00000040;
pub const CAP_NT_STATUS: u32 = 0x00000040;
pub const CAP_LEVEL_II_OPLOCKS: u32 = 0x00000080;
pub const CAP_LOCK_AND_READ2: u32 = 0x00000080;
pub const CAP_MASS_MODE: u32 = 0x00000100;
pub const CAP_EXTENDED_SECURITY: u32 = 0x80000000;

// Connection defaults
pub const DEFAULT_SMB_PORT: u16 = 445;
pub const DEFAULT_NBT_PORT: u16 = 139;
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const MAX_RECV_SIZE: usize = 65536;

// Common SID strings
pub const SID_WORLD: &str = "S-1-1-0";
pub const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_NETWORK_SERVICE: &str = "S-1-5-20";
pub const SID_LOCAL_SERVICE: &str = "S-1-5-19";
pub const SID_DOMAIN_ADMINS: &str = "S-1-5-21-X-X-X-512";
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";
