use smbx_core::{SmbxError, SmbxResult};
use smbx_net::SmbSocket;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::task;

/// Port scanner for SMB services
pub struct SmbScanner {
    port: u16,
    timeout_secs: u64,
    max_concurrent: usize,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
    pub response_time_ms: u128,
}

impl SmbScanner {
    pub fn new(port: u16, timeout_secs: u64, max_concurrent: usize) -> Self {
        Self {
            port,
            timeout_secs,
            max_concurrent,
        }
    }

    /// Scan single host for open SMB port
    pub async fn scan_host(&self, host: &str) -> SmbxResult<ScanResult> {
        let start = std::time::Instant::now();

        let addr = self.resolve_address(host)?;
        let socket_addr = SocketAddr::new(addr, self.port);

        let result = match SmbSocket::connect(&socket_addr, self.timeout_secs).await {
            Ok(_) => ScanResult {
                host: host.to_string(),
                port: self.port,
                open: true,
                response_time_ms: start.elapsed().as_millis(),
            },
            Err(SmbxError::Timeout) => ScanResult {
                host: host.to_string(),
                port: self.port,
                open: false,
                response_time_ms: start.elapsed().as_millis(),
            },
            Err(e) => {
                log::debug!("Scan error for {}: {}", host, e);
                ScanResult {
                    host: host.to_string(),
                    port: self.port,
                    open: false,
                    response_time_ms: start.elapsed().as_millis(),
                }
            }
        };

        Ok(result)
    }

    /// Scan multiple hosts concurrently
    pub async fn scan_hosts(&self, hosts: Vec<String>) -> SmbxResult<Vec<ScanResult>> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            self.max_concurrent,
        ));
        let mut handles = vec![];

        for host in hosts {
            let semaphore_clone = semaphore.clone();
            let scanner_clone = self.clone();

            let handle = task::spawn(async move {
                let _permit = semaphore_clone.acquire().await;
                scanner_clone.scan_host(&host).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Ok(result)) = handle.await {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Scan CIDR network range
    pub async fn scan_network(&self, cidr: &str) -> SmbxResult<Vec<ScanResult>> {
        let hosts = self.expand_cidr(cidr)?;
        self.scan_hosts(hosts).await
    }

    fn resolve_address(&self, host: &str) -> SmbxResult<IpAddr> {
        IpAddr::from_str(host).or_else(|_| {
            std::net::IpAddr::from_str(host)
                .map_err(|_| SmbxError::InvalidTarget(format!("Invalid host: {}", host)))
        })
    }

    fn expand_cidr(&self, cidr: &str) -> SmbxResult<Vec<String>> {
        // Simple CIDR expansion (supports /24, /25, etc.)
        if let Some((network, mask_str)) = cidr.split_once('/') {
            let mask: u8 = mask_str
                .parse()
                .map_err(|_| SmbxError::InvalidTarget("Invalid CIDR mask".to_string()))?;

            let addr = network
                .parse::<IpAddr>()
                .map_err(|_| SmbxError::InvalidTarget("Invalid network address".to_string()))?;

            match addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    let mut ips = Vec::new();

                    if mask == 32 {
                        ips.push(ipv4.to_string());
                    } else if mask == 24 {
                        for i in 1..255 {
                            let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], i);
                            ips.push(ip);
                        }
                    } else if mask == 25 {
                        for i in 1..128 {
                            let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], i);
                            ips.push(ip);
                        }
                    } else if mask == 16 {
                        // Limit to first 256 for /16
                        for i in 1..256 {
                            let ip = format!("{}.{}.{}.1", octets[0], octets[1], i);
                            ips.push(ip);
                        }
                    } else {
                        return Err(SmbxError::InvalidTarget(
                            "Unsupported CIDR mask".to_string(),
                        ));
                    }

                    Ok(ips)
                }
                IpAddr::V6(_) => Err(SmbxError::NotSupported(
                    "IPv6 CIDR expansion not yet supported".to_string(),
                )),
            }
        } else {
            Ok(vec![cidr.to_string()])
        }
    }
}

impl Clone for SmbScanner {
    fn clone(&self) -> Self {
        Self {
            port: self.port,
            timeout_secs: self.timeout_secs,
            max_concurrent: self.max_concurrent,
        }
    }
}
