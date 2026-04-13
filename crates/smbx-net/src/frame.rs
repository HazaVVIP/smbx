use bytes::{BytesMut, BufMut};
use smbx_core::SmbxResult;

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
    pub fn build_null_session_probe(target: &str) -> Vec<u8> {
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
        buf.put_u16_le(0x10000); // >65536 triggers overflow
        buf.put_u16_le(0);
        buf.put_u16_le(0);
        buf.put_u16_le(0);
        buf.put_u32_le(0);

        // Byte count
        buf.put_u16_le(0);

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
