use bytes::{BytesMut, Buf};
use smbx_core::{SmbxError, SmbxResult};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Low-level SMB network socket handler
pub struct SmbSocket {
    stream: TcpStream,
    read_buffer: BytesMut,
    timeout_secs: u64,
}

impl SmbSocket {
    /// Create new SMB socket with connection timeout
    pub async fn connect(addr: &SocketAddr, timeout_secs: u64) -> SmbxResult<Self> {
        let conn_timeout = Duration::from_secs(timeout_secs);
        let stream = timeout(conn_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| SmbxError::Timeout)?
            .map_err(|e| SmbxError::NetworkError(e.to_string()))?;

        Ok(Self {
            stream,
            read_buffer: BytesMut::with_capacity(65536),
            timeout_secs,
        })
    }

    /// Send raw bytes to SMB server
    pub async fn send_raw(&mut self, data: &[u8]) -> SmbxResult<()> {
        use tokio::io::AsyncWriteExt;
        
        let send_timeout = Duration::from_secs(self.timeout_secs);
        timeout(send_timeout, self.stream.write_all(data))
            .await
            .map_err(|_| SmbxError::Timeout)?
            .map_err(|e| SmbxError::NetworkError(e.to_string()))?;

        Ok(())
    }

    /// Receive data with length prefix (NetBIOS Session Service)
    pub async fn recv_message(&mut self) -> SmbxResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let read_timeout = Duration::from_secs(self.timeout_secs);

        // Read 4-byte NetBIOS header
        loop {
            if self.read_buffer.len() >= 4 {
                break;
            }
            let n = timeout(
                read_timeout,
                self.stream.read_buf(&mut self.read_buffer),
            )
            .await
            .map_err(|_| SmbxError::Timeout)?
            .map_err(|e| SmbxError::NetworkError(e.to_string()))?;

            if n == 0 {
                return Err(SmbxError::NetworkError("Connection closed".to_string()));
            }
        }

        // Parse NetBIOS length (24-bit big-endian in bytes 1-3)
        let header = &self.read_buffer[..4];
        let msg_len = ((header[1] as usize) << 16)
            | ((header[2] as usize) << 8)
            | (header[3] as usize);

        if msg_len == 0 {
            self.read_buffer.advance(4);
            return Ok(Vec::new());
        }

        // Read full message
        loop {
            if self.read_buffer.len() >= 4 + msg_len {
                break;
            }
            let n = timeout(
                read_timeout,
                self.stream.read_buf(&mut self.read_buffer),
            )
            .await
            .map_err(|_| SmbxError::Timeout)?
            .map_err(|e| SmbxError::NetworkError(e.to_string()))?;

            if n == 0 {
                return Err(SmbxError::NetworkError("Connection closed".to_string()));
            }
        }

        // Extract message (skip 4-byte header)
        let message = self.read_buffer[4..4 + msg_len].to_vec();
        self.read_buffer.advance(4 + msg_len);

        Ok(message)
    }

    /// Receive raw bytes (no length prefix parsing)
    pub async fn recv_raw(&mut self, max_bytes: usize) -> SmbxResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let read_timeout = Duration::from_secs(self.timeout_secs);

        let mut buffer = vec![0u8; max_bytes];
        let n = timeout(
            read_timeout,
            self.stream.read(&mut buffer),
        )
        .await
        .map_err(|_| SmbxError::Timeout)?
        .map_err(|e| SmbxError::NetworkError(e.to_string()))?;

        if n == 0 {
            return Err(SmbxError::NetworkError("Connection closed".to_string()));
        }

        buffer.truncate(n);
        Ok(buffer)
    }

    /// Send NetBIOS Session Service message
    pub async fn send_nbt_message(&mut self, data: &[u8]) -> SmbxResult<()> {
        let mut msg = Vec::with_capacity(4 + data.len());
        
        // NetBIOS header: type (1 byte) + length (3 bytes, big-endian)
        msg.push(0x00); // Session message
        let len = data.len() as u32;
        msg.push(((len >> 16) & 0xFF) as u8);
        msg.push(((len >> 8) & 0xFF) as u8);
        msg.push((len & 0xFF) as u8);
        msg.extend_from_slice(data);

        self.send_raw(&msg).await
    }

    /// Get peer address
    pub fn peer_addr(&self) -> SmbxResult<SocketAddr> {
        self.stream
            .peer_addr()
            .map_err(|e| SmbxError::NetworkError(e.to_string()))
    }

    /// Get local address
    pub fn local_addr(&self) -> SmbxResult<SocketAddr> {
        self.stream
            .local_addr()
            .map_err(|e| SmbxError::NetworkError(e.to_string()))
    }

    /// Set socket timeout
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }

    /// Check if socket is connected
    pub async fn is_connected(&self) -> bool {
        // Try non-blocking operation to check connection
        match self.stream.try_read_buf(&mut BytesMut::new()) {
            Ok(0) => false,          // Connection closed
            Ok(_) => true,           // Data available
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // Still connected
            Err(_) => false,         // Error indicates disconnection
        }
    }
}
