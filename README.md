# SMBX

Enterprise-grade SMB/CIFS vulnerability scanner and exploitation framework in Rust.

## Features

- Port scanning with CIDR support
- SMB dialect detection (v1, 2.x, 3.x) and OS fingerprinting
- Vulnerability checks (SMBv1, signing disabled, null/guest sessions)
- Evidence-based exploitation with Safe/Aggressive/Destructive modes
- JSON reporting

## Installation

```bash
chmod +x install.sh && ./install.sh
```

**Manual build:**
```bash
cargo build --release
./target/release/smbx --help
```

**Termux (proot-distro Ubuntu):**
```bash
apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo build --release
```

## Usage

```bash
# Scan network
smbx scan 192.168.1.0/24 -j 32

# Fingerprint target
smbx fingerprint 192.168.1.100

# Full assessment (safe mode)
smbx full 192.168.1.100 -m safe -o report.json

# Run specific check
smbx check 192.168.1.100 smb-v1-enabled

# Run specific exploit
smbx exploit 192.168.1.100 null_pivot -m safe

# Enumerate shares
smbx enum 192.168.1.100

# List available modules
smbx list --checks --exploits
```

## Exploit Modules

| Module | Mode | Description |
|--------|------|-------------|
| `null_pivot` | Safe | Null session enumeration |
| `guest_pivot` | Safe | Guest account access |
| `ghost_probe` | Aggressive | SMBGhost (CVE-2020-0796) |
| `ntlm_relay` | Aggressive | NTLM hash capture |
| `eternalblue` | Destructive | MS17-010 RCE |

**Modes:**
- **Safe** - Detection only, no network manipulation
- **Aggressive** - Active probing, may destabilize target
- **Destructive** - RCE execution, requires `--rce --confirm` flags

## Project Structure

```
crates/
├── smbx/             # CLI binary
├── smbx-core/        # Core types (Finding, Evidence, Error)
├── smbx-net/         # SMB protocol/networking
├── smbx-scanner/     # Port scanner
├── smbx-fingerprint/ # Dialect/OS detection
├── smbx-vuln/        # Vulnerability checks
├── smbx-exploit/     # Exploit modules
├── smbx-enum/        # Share enumeration
└── smbx-report/      # JSON reporter
```

## Extending SMBX

### Add Vulnerability Check

1. Create `crates/smbx-vuln/src/mycheck.rs`:
```rust
use async_trait::async_trait;
use smbx_core::{Finding, Severity, SmbxResult};
use crate::check::VulnCheck;

pub struct MyCheck { /* ... */ }

#[async_trait]
impl VulnCheck for MyCheck {
    fn id(&self) -> &str { "my-check-id" }
    fn name(&self) -> &str { "My Check" }
    async fn check(&self) -> SmbxResult<Option<Finding>> { /* ... */ }
}
```

2. Export in `lib.rs` and register in `orchestrator.rs`

### Add Exploit Module

1. Create `crates/smbx-exploit/src/myexploit.rs`:
```rust
use async_trait::async_trait;
use smbx_core::{ExploitMode, ExploitResult, SmbxResult};
use crate::exploiter::Exploiter;

pub struct MyExploit;

#[async_trait]
impl Exploiter for MyExploit {
    fn id(&self) -> &str { "my-exploit" }
    fn min_mode(&self) -> ExploitMode { ExploitMode::Safe }
    async fn exploit(&self, target: &str, port: u16, mode: ExploitMode) 
        -> SmbxResult<ExploitResult> { /* ... */ }
}
```

2. Export in `lib.rs` and add to `create_default_registry()`

## Legal

**Authorized use only.** Obtain explicit written permission before testing any system. Unauthorized access is illegal.

## License

MIT
