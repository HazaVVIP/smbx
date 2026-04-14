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

// SMBv1 NT_TRANSACT subcommands
pub const NT_TRANSACT_CREATE: u16 = 0x0001;
pub const NT_TRANSACT_IOCTL: u16 = 0x0002;
pub const NT_TRANSACT_SET_SECURITY_DESC: u16 = 0x0003;
pub const NT_TRANSACT_NOTIFY_CHANGE: u16 = 0x0004;
pub const NT_TRANSACT_RENAME: u16 = 0x0005;
pub const NT_TRANSACT_QUERY_SECURITY_DESC: u16 = 0x0006;

// SMBv1 TRANSACTION2 subcommands
pub const TRANS2_OPEN2: u16 = 0x0000;
pub const TRANS2_FIND_FIRST2: u16 = 0x0001;
pub const TRANS2_FIND_NEXT2: u16 = 0x0002;
pub const TRANS2_QUERY_FS_INFO: u16 = 0x0003;
pub const TRANS2_QUERY_PATH_INFO: u16 = 0x0005;
pub const TRANS2_SET_PATH_INFO: u16 = 0x0006;
pub const TRANS2_QUERY_FILE_INFO: u16 = 0x0007;
pub const TRANS2_SET_FILE_INFO: u16 = 0x0008;

// SMBv1 additional commands used by EternalRomance / MS17-010 WriteAndX path
pub const SMB_COM_NT_TRANSACT: u8 = 0xA0;
pub const SMB_COM_TRANSACTION2: u8 = 0x32;
pub const SMB_COM_NT_CREATE_ANDX: u8 = 0xA2;

// SMBv3 compression / SMBleed constants (CVE-2020-1206)
pub const SMB2_COMPRESSION_TRANSFORM_MAGIC: &[u8] = b"\xfcSMB";
pub const SMB2_COMPRESSION_ALG_LZ77: u16 = 0x0002;
pub const SMB2_COMPRESSION_ALG_LZ77_HUFFMAN: u16 = 0x0003;
pub const SMB2_COMPRESSION_ALG_LZNT1: u16 = 0x0001;
pub const SMB2_COMPRESSION_CAPABILITIES_CONTEXT_TYPE: u16 = 0x0003;

// Named pipe paths used by NetAPI / RPC exploits
pub const PIPE_SRVSVC: &str = r"\PIPE\srvsvc";
pub const PIPE_WKSSVC: &str = r"\PIPE\wkssvc";
pub const PIPE_SVCCTL: &str = r"\PIPE\svcctl";
pub const PIPE_SAMR: &str = r"\PIPE\samr";
pub const PIPE_BROWSER: &str = r"\PIPE\browser";
pub const PIPE_LSARPC: &str = r"\PIPE\lsarpc";

// Samba / DCERPC interface identifiers
pub const DCERPC_UUID_SRVSVC: &str = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
pub const DCERPC_UUID_WKSSVC: &str = "6bffd098-a112-3610-9833-46c3f87e345a";
pub const DCERPC_UUID_SVCCTL: &str = "367abb81-9844-35f1-ad32-98f038001003";
pub const DCERPC_UUID_SAMR: &str = "12345778-1234-abcd-ef00-0123456789ac";

// NTSTATUS codes commonly seen in RPC exploit responses
pub const STATUS_SUCCESS: u32 = 0x00000000;
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC0000034;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x80000005;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC0000023;
pub const RPC_S_ACCESS_DENIED: u32 = 0x00000005;

// AFP / vfs_fruit stream name used by CVE-2021-44142
pub const AFP_AFPINFO_STREAM: &str = "AFP_AfpInfo";
pub const AFP_AFPINFO_STREAM_LEN: usize = 60;

// Common SID strings
pub const SID_WORLD: &str = "S-1-1-0";
pub const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_NETWORK_SERVICE: &str = "S-1-5-20";
pub const SID_LOCAL_SERVICE: &str = "S-1-5-19";
pub const SID_DOMAIN_ADMINS: &str = "S-1-5-21-X-X-X-512";
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";
