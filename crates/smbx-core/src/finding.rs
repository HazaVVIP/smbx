use crate::evidence::Evidence;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn cvss_range(&self) -> (f32, f32) {
        match self {
            Severity::Critical => (9.0, 10.0),
            Severity::High => (7.0, 8.9),
            Severity::Medium => (4.0, 6.9),
            Severity::Low => (0.1, 3.9),
            Severity::Info => (0.0, 0.0),
        }
    }

    pub fn score(&self) -> f32 {
        match self {
            Severity::Critical => 9.5,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 2.0,
            Severity::Info => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Likely,
    Possible,
    Unknown,
}

impl Confidence {
    pub fn as_percent(&self) -> f32 {
        match self {
            Confidence::Confirmed => 100.0,
            Confidence::Likely => 80.0,
            Confidence::Possible => 50.0,
            Confidence::Unknown => 0.0,
        }
    }
}

/// Core vulnerability finding with linked evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub cve: Option<Vec<String>>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub affected_hosts: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub exploit_module: Option<String>,
    pub remediation: String,
    pub references: Vec<String>,
}

impl Finding {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: description.into(),
            cve: None,
            severity: Severity::Medium,
            confidence: Confidence::Unknown,
            affected_hosts: Vec::new(),
            evidence: Vec::new(),
            exploit_module: None,
            remediation: String::new(),
            references: Vec::new(),
        }
    }

    pub fn with_cve(mut self, cves: Vec<String>) -> Self {
        self.cve = Some(cves);
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn add_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn add_host(mut self, host: String) -> Self {
        if !self.affected_hosts.contains(&host) {
            self.affected_hosts.push(host);
        }
        self
    }

    pub fn with_exploit_module(mut self, module: String) -> Self {
        self.exploit_module = Some(module);
        self
    }

    pub fn with_remediation(mut self, text: String) -> Self {
        self.remediation = text;
        self
    }

    pub fn risk_score(&self) -> f32 {
        (self.severity.score() + self.confidence.as_percent()) / 2.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReport {
    pub findings: Vec<Finding>,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub total_info: usize,
}

impl FindingReport {
    pub fn new(findings: Vec<Finding>) -> Self {
        let mut report = Self {
            findings,
            total_critical: 0,
            total_high: 0,
            total_medium: 0,
            total_low: 0,
            total_info: 0,
        };

        for finding in &report.findings {
            match finding.severity {
                Severity::Critical => report.total_critical += 1,
                Severity::High => report.total_high += 1,
                Severity::Medium => report.total_medium += 1,
                Severity::Low => report.total_low += 1,
                Severity::Info => report.total_info += 1,
            }
        }

        report
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    pub fn risk_score(&self) -> f32 {
        if self.findings.is_empty() {
            0.0
        } else {
            self.findings.iter().map(|f| f.risk_score()).sum::<f32>()
                / self.findings.len() as f32
        }
    }
}
