use chrono::Utc;
use smbx_core::{Finding, FindingReport, SmbxResult};
use serde_json::{json, Value};

pub struct JsonReporter;

impl JsonReporter {
    /// Generate JSON report from findings
    pub fn generate_report(findings: &[Finding], target: &str) -> SmbxResult<String> {
        let report = FindingReport::new(findings.to_vec());

        let json_findings: Vec<Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "id": f.id,
                    "name": f.name,
                    "description": f.description,
                    "severity": format!("{:?}", f.severity).to_lowercase(),
                    "confidence": format!("{:?}", f.confidence).to_lowercase(),
                    "cve": f.cve.clone().unwrap_or_default(),
                    "affected_hosts": f.affected_hosts,
                    "exploit_module": f.exploit_module,
                    "remediation": f.remediation,
                    "references": f.references,
                    "evidence_count": f.evidence.len(),
                    "evidence": f.evidence.iter().map(|e| {
                        json!({
                            "type": e.label(),
                            "details": Self::serialize_evidence(e)
                        })
                    }).collect::<Vec<_>>(),
                    "risk_score": f.risk_score()
                })
            })
            .collect();

        let output = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "target": target,
            "summary": {
                "total_findings": report.total_findings(),
                "critical": report.total_critical,
                "high": report.total_high,
                "medium": report.total_medium,
                "low": report.total_low,
                "info": report.total_info,
                "overall_risk_score": format!("{:.2}", report.risk_score())
            },
            "findings": json_findings
        });

        Ok(output.to_string())
    }

    /// Generate minimal JSON (findings only)
    pub fn generate_minimal(findings: &[Finding], target: &str) -> SmbxResult<String> {
        let findings_data: Vec<Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "severity": format!("{:?}", f.severity).to_lowercase(),
                    "cve": f.cve.clone().unwrap_or_default(),
                })
            })
            .collect();

        let output = json!({
            "target": target,
            "timestamp": Utc::now().to_rfc3339(),
            "findings": findings_data
        });

        Ok(output.to_string())
    }

    fn serialize_evidence(evidence: &smbx_core::Evidence) -> Value {
        match evidence {
            smbx_core::Evidence::FileList { share, files } => {
                json!({
                    "share": share,
                    "file_count": files.len()
                })
            }
            smbx_core::Evidence::FileSample { path, size, preview } => {
                json!({
                    "path": path,
                    "size": size,
                    "preview_bytes": preview.len(),
                    "preview_hex": hex::encode(&preview[..preview.len().min(32)])
                })
            }
            smbx_core::Evidence::CrashProof { timestamp, crash_code, details } => {
                json!({
                    "timestamp": timestamp.to_rfc3339(),
                    "crash_code": crash_code,
                    "details": details
                })
            }
            smbx_core::Evidence::MemoryLeak { leaked_bytes, location } => {
                json!({
                    "location": location,
                    "leaked_size": leaked_bytes.len(),
                    "data_hex": hex::encode(&leaked_bytes[..leaked_bytes.len().min(64)])
                })
            }
            smbx_core::Evidence::CapturedHash { hash, username, domain } => {
                json!({
                    "hash": hash,
                    "username": username,
                    "domain": domain
                })
            }
            smbx_core::Evidence::CommandOutput { command, output, timestamp } => {
                json!({
                    "command": command,
                    "output": output,
                    "timestamp": timestamp.to_rfc3339()
                })
            }
            smbx_core::Evidence::RelaySuccess { target, service, relayed_user } => {
                json!({
                    "target": target,
                    "service": service,
                    "user": relayed_user
                })
            }
            smbx_core::Evidence::PrivEsc { before_user, after_user, method } => {
                json!({
                    "before": before_user,
                    "after": after_user,
                    "method": method
                })
            }
            smbx_core::Evidence::CodeExecution { injected_process, payload_hash, execution_timestamp } => {
                json!({
                    "process": injected_process,
                    "payload_hash": payload_hash,
                    "timestamp": execution_timestamp.to_rfc3339()
                })
            }
            smbx_core::Evidence::SigningDisabled { dialect, capabilities } => {
                json!({
                    "dialect": dialect,
                    "capabilities": capabilities
                })
            }
            smbx_core::Evidence::NullSessionEstablished { shares_enumerated } => {
                json!({
                    "shares": shares_enumerated
                })
            }
            smbx_core::Evidence::TextEvidence { label, content } => {
                json!({
                    "label": label,
                    "content": content
                })
            }
            smbx_core::Evidence::RpcResponse { endpoint, response_bytes } => {
                json!({
                    "endpoint": endpoint,
                    "response_size": response_bytes.len(),
                    "data_hex": hex::encode(&response_bytes[..response_bytes.len().min(64)])
                })
            }
            smbx_core::Evidence::NamedPipeAccess { pipe_name, data_written } => {
                json!({
                    "pipe_name": pipe_name,
                    "data_written": data_written
                })
            }
            smbx_core::Evidence::SharedLibraryUploaded { share, path, size } => {
                json!({
                    "share": share,
                    "path": path,
                    "size": size
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_generation() {
        let findings = vec![];
        let json = JsonReporter::generate_report(&findings, "192.168.1.1").unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("findings"));
    }
}
