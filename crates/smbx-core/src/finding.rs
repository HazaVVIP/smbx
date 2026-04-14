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

    pub fn push_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }

    pub fn set_confidence(&mut self, confidence: Confidence) {
        self.confidence = confidence;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;

    // ------------------------------------------------------------------
    // Severity
    // ------------------------------------------------------------------

    #[test]
    fn severity_cvss_ranges() {
        assert_eq!(Severity::Critical.cvss_range(), (9.0, 10.0));
        assert_eq!(Severity::High.cvss_range(), (7.0, 8.9));
        assert_eq!(Severity::Medium.cvss_range(), (4.0, 6.9));
        assert_eq!(Severity::Low.cvss_range(), (0.1, 3.9));
        assert_eq!(Severity::Info.cvss_range(), (0.0, 0.0));
    }

    #[test]
    fn severity_scores() {
        assert_eq!(Severity::Critical.score(), 9.5);
        assert_eq!(Severity::High.score(), 7.5);
        assert_eq!(Severity::Medium.score(), 5.0);
        assert_eq!(Severity::Low.score(), 2.0);
        assert_eq!(Severity::Info.score(), 0.0);
    }

    #[test]
    fn severity_is_copy() {
        let s = Severity::High;
        let _ = s;
        let _ = s; // copy semantics
    }

    // ------------------------------------------------------------------
    // Confidence
    // ------------------------------------------------------------------

    #[test]
    fn confidence_as_percent() {
        assert_eq!(Confidence::Confirmed.as_percent(), 100.0);
        assert_eq!(Confidence::Likely.as_percent(), 80.0);
        assert_eq!(Confidence::Possible.as_percent(), 50.0);
        assert_eq!(Confidence::Unknown.as_percent(), 0.0);
    }

    // ------------------------------------------------------------------
    // Finding
    // ------------------------------------------------------------------

    #[test]
    fn finding_new_defaults() {
        let f = Finding::new("Test finding", "A test description");
        assert_eq!(f.name, "Test finding");
        assert_eq!(f.description, "A test description");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, Confidence::Unknown);
        assert!(f.cve.is_none());
        assert!(f.affected_hosts.is_empty());
        assert!(f.evidence.is_empty());
        assert!(f.exploit_module.is_none());
        assert!(f.remediation.is_empty());
        assert!(f.references.is_empty());
    }

    #[test]
    fn finding_with_cve() {
        let f = Finding::new("Test", "Desc")
            .with_cve(vec!["CVE-2021-0001".to_string()]);
        assert_eq!(f.cve.unwrap(), vec!["CVE-2021-0001"]);
    }

    #[test]
    fn finding_with_severity() {
        let f = Finding::new("Test", "Desc").with_severity(Severity::Critical);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn finding_with_confidence() {
        let f = Finding::new("Test", "Desc").with_confidence(Confidence::Likely);
        assert_eq!(f.confidence, Confidence::Likely);
    }

    #[test]
    fn finding_add_host_no_duplicates() {
        let f = Finding::new("Test", "Desc")
            .add_host("192.168.1.1".to_string())
            .add_host("192.168.1.1".to_string())
            .add_host("192.168.1.2".to_string());
        assert_eq!(f.affected_hosts.len(), 2);
        assert!(f.affected_hosts.contains(&"192.168.1.1".to_string()));
        assert!(f.affected_hosts.contains(&"192.168.1.2".to_string()));
    }

    #[test]
    fn finding_with_exploit_module() {
        let f = Finding::new("Test", "Desc")
            .with_exploit_module("eternalblue".to_string());
        assert_eq!(f.exploit_module.unwrap(), "eternalblue");
    }

    #[test]
    fn finding_with_remediation() {
        let f = Finding::new("Test", "Desc")
            .with_remediation("Patch now".to_string());
        assert_eq!(f.remediation, "Patch now");
    }

    #[test]
    fn finding_add_evidence() {
        let ev = Evidence::TextEvidence {
            label: "lbl".to_string(),
            content: "content".to_string(),
        };
        let f = Finding::new("Test", "Desc").add_evidence(ev);
        assert_eq!(f.evidence.len(), 1);
    }

    #[test]
    fn finding_push_evidence_mut() {
        let mut f = Finding::new("Test", "Desc");
        f.push_evidence(Evidence::TextEvidence {
            label: "l".to_string(),
            content: "c".to_string(),
        });
        assert_eq!(f.evidence.len(), 1);
    }

    #[test]
    fn finding_set_confidence_mut() {
        let mut f = Finding::new("Test", "Desc");
        f.set_confidence(Confidence::Confirmed);
        assert_eq!(f.confidence, Confidence::Confirmed);
    }

    #[test]
    fn finding_risk_score_medium_unknown() {
        let f = Finding::new("Test", "Desc");
        // (5.0 + 0.0) / 2.0 = 2.5
        let score = f.risk_score();
        assert!((score - 2.5).abs() < 0.01);
    }

    #[test]
    fn finding_risk_score_critical_confirmed() {
        let f = Finding::new("Test", "Desc")
            .with_severity(Severity::Critical)
            .with_confidence(Confidence::Confirmed);
        // (9.5 + 100.0) / 2.0 = 54.75
        let score = f.risk_score();
        assert!((score - 54.75).abs() < 0.01);
    }

    #[test]
    fn finding_id_is_unique() {
        let f1 = Finding::new("A", "A");
        let f2 = Finding::new("B", "B");
        assert_ne!(f1.id, f2.id);
    }

    // ------------------------------------------------------------------
    // FindingReport
    // ------------------------------------------------------------------

    #[test]
    fn finding_report_empty() {
        let report = FindingReport::new(vec![]);
        assert_eq!(report.total_findings(), 0);
        assert_eq!(report.risk_score(), 0.0);
        assert_eq!(report.total_critical, 0);
    }

    #[test]
    fn finding_report_counts_severities() {
        let findings = vec![
            Finding::new("C1", "d").with_severity(Severity::Critical),
            Finding::new("C2", "d").with_severity(Severity::Critical),
            Finding::new("H1", "d").with_severity(Severity::High),
            Finding::new("M1", "d").with_severity(Severity::Medium),
            Finding::new("L1", "d").with_severity(Severity::Low),
            Finding::new("I1", "d").with_severity(Severity::Info),
        ];
        let report = FindingReport::new(findings);
        assert_eq!(report.total_critical, 2);
        assert_eq!(report.total_high, 1);
        assert_eq!(report.total_medium, 1);
        assert_eq!(report.total_low, 1);
        assert_eq!(report.total_info, 1);
        assert_eq!(report.total_findings(), 6);
    }

    #[test]
    fn finding_report_risk_score_average() {
        let findings = vec![
            Finding::new("A", "d").with_severity(Severity::Info),   // risk 0.0
            Finding::new("B", "d").with_severity(Severity::Info),   // risk 0.0
        ];
        let report = FindingReport::new(findings);
        assert_eq!(report.risk_score(), 0.0);
    }
}
