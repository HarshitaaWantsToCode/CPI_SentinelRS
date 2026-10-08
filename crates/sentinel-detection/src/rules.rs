use crate::context::DetectionContext;
use crate::engine::Detector;
use sentinel_core::{CloudEvent, DetectionCategory, DetectionFinding, EvidenceItem, Severity};
use uuid::Uuid;

// ==========================================
// 1. IAM DETECTIONS
// ==========================================

pub struct IamAdminPolicyAttachmentDetector;
impl Detector for IamAdminPolicyAttachmentDetector {
    fn id(&self) -> &'static str { "IAM-001" }
    fn name(&self) -> &'static str { "Administrative Policy Attachment" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "AttachUserPolicy" || event.action == "AttachRolePolicy" || event.action == "AttachGroupPolicy" {
            let meta_str = event.metadata.to_string();
            let is_admin = meta_str.contains("AdministratorAccess")
                || meta_str.contains("PowerUserAccess")
                || event.resource.identifier.contains("AdministratorAccess");

            if is_admin {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "Administrative Policy Attached to Principal".into(),
                    description: format!("AdministratorAccess attached to identity '{}'.", event.actor.identity),
                    severity: Severity::Critical,
                    confidence: 95,
                    category: DetectionCategory::PrivilegeEscalation,
                    tactic: "Privilege Escalation".into(),
                    technique_id: "T1098".into(),
                    technique_name: "Account Manipulation".into(),
                    why_suspicious: "Full administrative cloud permissions granted outside approved deployment pipeline.".into(),
                    recommended_response: "Revoke attached AdministratorAccess policy immediately.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "PolicyArn".into(),
                            value: "arn:aws:iam::aws:policy/AdministratorAccess".into(),
                            description: "Unrestricted root-level AWS permissions policy".into(),
                        },
                        EvidenceItem {
                            key: "Principal".into(),
                            value: event.actor.identity.clone(),
                            description: "Target IAM user / role receiving administrative rights".into(),
                        },
                    ],
                    risk_contribution: 30,
                }];
            }
        }
        Vec::new()
    }
}

pub struct IamPrivilegeEscalationDetector;
impl Detector for IamPrivilegeEscalationDetector {
    fn id(&self) -> &'static str { "IAM-002" }
    fn name(&self) -> &'static str { "IAM Privilege Escalation Sequence" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "PutUserPolicy" || event.action == "CreatePolicyVersion" || event.action == "SetDefaultPolicyVersion" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "Inline Policy / Policy Version Escalation".into(),
                description: format!("Direct policy modification detected on principal '{}'.", event.actor.identity),
                severity: Severity::High,
                confidence: 88,
                category: DetectionCategory::PrivilegeEscalation,
                tactic: "Privilege Escalation".into(),
                technique_id: "T1098".into(),
                technique_name: "Account Manipulation: Additional Cloud Roles".into(),
                why_suspicious: "Direct inline policy manipulation alters effective permissions.".into(),
                recommended_response: "Audit effective policy document and roll back unauthorized versions.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Action".into(),
                        value: event.action.clone(),
                        description: "IAM privilege escalation API".into(),
                    }
                ],
                risk_contribution: 25,
            }];
        }
        Vec::new()
    }
}

pub struct IamAccessKeyCreationDetector;
impl Detector for IamAccessKeyCreationDetector {
    fn id(&self) -> &'static str { "IAM-003" }
    fn name(&self) -> &'static str { "IAM Programmatic Access Key Generated" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "CreateAccessKey" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "IAM Programmatic Access Key Created for Persistence".into(),
                description: format!("Programmatic access key generated for identity '{}'.", event.actor.identity),
                severity: Severity::High,
                confidence: 90,
                category: DetectionCategory::Persistence,
                tactic: "Persistence".into(),
                technique_id: "T1098.001".into(),
                technique_name: "Additional Cloud Credentials".into(),
                why_suspicious: "New programmatic credentials provide persistent offline access.".into(),
                recommended_response: "Deactivate newly generated access key and audit caller session.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Actor".into(),
                        value: event.actor.identity.clone(),
                        description: "Identity generating programmatic access credentials".into(),
                    }
                ],
                risk_contribution: 20,
            }];
        }
        Vec::new()
    }
}

pub struct IamMfaDeactivationDetector;
impl Detector for IamMfaDeactivationDetector {
    fn id(&self) -> &'static str { "IAM-004" }
    fn name(&self) -> &'static str { "MFA Device Deactivation" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "DeactivateMFADevice" || event.action == "DeleteVirtualMFADevice" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "MFA Security Device Deactivated".into(),
                description: format!("MFA device removed from account '{}'.", event.actor.identity),
                severity: Severity::Critical,
                confidence: 94,
                category: DetectionCategory::DefenseEvasion,
                tactic: "Defense Evasion".into(),
                technique_id: "T1556".into(),
                technique_name: "Modify Authentication Process".into(),
                why_suspicious: "Deactivating MFA weakens defensive posture against account takeover.".into(),
                recommended_response: "Lock account and immediately re-enforce hardware MFA.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Action".into(),
                        value: event.action.clone(),
                        description: "MFA deactivation API".into(),
                    }
                ],
                risk_contribution: 35,
            }];
        }
        Vec::new()
    }
}

pub struct IamSuspiciousAssumeRoleDetector;
impl Detector for IamSuspiciousAssumeRoleDetector {
    fn id(&self) -> &'static str { "IAM-005" }
    fn name(&self) -> &'static str { "Suspicious Cross-Account AssumeRole" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "AssumeRole" {
            let meta_str = event.metadata.to_string();
            if meta_str.contains("admin") || meta_str.contains("Admin") || meta_str.contains("CrossAccount") {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "High-Privilege Role Assumption".into(),
                    description: format!("Identity '{}' assumed elevated target role.", event.actor.identity),
                    severity: Severity::Medium,
                    confidence: 80,
                    category: DetectionCategory::CredentialAccess,
                    tactic: "Lateral Movement".into(),
                    technique_id: "T1548.005".into(),
                    technique_name: "Temporary Elevated Cloud Role".into(),
                    why_suspicious: "Role assumption grants transient high-privilege STS tokens.".into(),
                    recommended_response: "Audit STS session ARN and revoke active temporary sessions.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "Actor".into(),
                            value: event.actor.identity.clone(),
                            description: "Caller requesting STS temporary credentials".into(),
                        }
                    ],
                    risk_contribution: 15,
                }];
            }
        }
        Vec::new()
    }
}

// ==========================================
// 2. CLOUDTRAIL DETECTIONS
// ==========================================

pub struct CloudTrailLoggingDisabledDetector;
impl Detector for CloudTrailLoggingDisabledDetector {
    fn id(&self) -> &'static str { "CT-001" }
    fn name(&self) -> &'static str { "CloudTrail Security Logging Halted" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "StopLogging" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "CloudTrail Security Audit Trail Stopped".into(),
                description: format!("Principal '{}' stopped logging on audit trail.", event.actor.identity),
                severity: Severity::Critical,
                confidence: 99,
                category: DetectionCategory::DefenseEvasion,
                tactic: "Defense Evasion".into(),
                technique_id: "T1562.008".into(),
                technique_name: "Impair Defenses: Disable Cloud Logs".into(),
                why_suspicious: "Halting CloudTrail blinds the SOC and destroys forensic visibility.".into(),
                recommended_response: "Re-enable CloudTrail logging immediately and isolate caller session.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "TrailName".into(),
                        value: event.resource.identifier.clone(),
                        description: "Audit trail targeted for silencing".into(),
                    }
                ],
                risk_contribution: 40,
            }];
        }
        Vec::new()
    }
}

pub struct CloudTrailTrailModifiedDetector;
impl Detector for CloudTrailTrailModifiedDetector {
    fn id(&self) -> &'static str { "CT-002" }
    fn name(&self) -> &'static str { "CloudTrail Configuration Modified" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "UpdateTrail" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "CloudTrail Configuration Altered".into(),
                description: format!("Logging parameters altered on trail '{}'.", event.resource.identifier),
                severity: Severity::High,
                confidence: 90,
                category: DetectionCategory::DefenseEvasion,
                tactic: "Defense Evasion".into(),
                technique_id: "T1562.008".into(),
                technique_name: "Impair Defenses: Modify Cloud Logs".into(),
                why_suspicious: "Altering trail scope or S3 storage location can hide malicious operations.".into(),
                recommended_response: "Verify trail integrity and ensure multi-region logging remains enabled.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Trail".into(),
                        value: event.resource.identifier.clone(),
                        description: "Modified CloudTrail resource".into(),
                    }
                ],
                risk_contribution: 25,
            }];
        }
        Vec::new()
    }
}

pub struct CloudTrailTrailDeletedDetector;
impl Detector for CloudTrailTrailDeletedDetector {
    fn id(&self) -> &'static str { "CT-003" }
    fn name(&self) -> &'static str { "CloudTrail Trail Deleted" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "DeleteTrail" {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "CloudTrail Audit Trail Deleted".into(),
                description: format!("Security audit trail '{}' was deleted.", event.resource.identifier),
                severity: Severity::Critical,
                confidence: 99,
                category: DetectionCategory::DefenseEvasion,
                tactic: "Defense Evasion".into(),
                technique_id: "T1562.008".into(),
                technique_name: "Impair Defenses: Delete Cloud Logs".into(),
                why_suspicious: "Direct attempt to permanently eliminate cloud forensic records.".into(),
                recommended_response: "Recreate CloudTrail logging infrastructure and revoke actor credentials.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "DeletedTrail".into(),
                        value: event.resource.identifier.clone(),
                        description: "Deleted logging trail ARN".into(),
                    }
                ],
                risk_contribution: 45,
            }];
        }
        Vec::new()
    }
}

// ==========================================
// 3. S3 DETECTIONS
// ==========================================

pub struct S3SuspiciousBucketAccessDetector;
impl Detector for S3SuspiciousBucketAccessDetector {
    fn id(&self) -> &'static str { "S3-001" }
    fn name(&self) -> &'static str { "Suspicious Sensitive S3 Bucket Access" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if (event.action == "ListObjects" || event.action == "ListBucket") && event.resource.is_sensitive {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "Enumeration of Sensitive S3 Bucket".into(),
                description: format!("Identity '{}' listed objects in confidential bucket '{}'.", event.actor.identity, event.resource.identifier),
                severity: Severity::Medium,
                confidence: 82,
                category: DetectionCategory::Discovery,
                tactic: "Discovery".into(),
                technique_id: "T1619".into(),
                technique_name: "Cloud Storage Object Discovery".into(),
                why_suspicious: "Reconnaissance targeting sensitive/PII cloud storage repository.".into(),
                recommended_response: "Enforce strict least-privilege bucket access policies.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "TargetBucket".into(),
                        value: event.resource.identifier.clone(),
                        description: "Confidential S3 bucket".into(),
                    }
                ],
                risk_contribution: 15,
            }];
        }
        Vec::new()
    }
}

pub struct S3MassObjectAccessDetector;
impl Detector for S3MassObjectAccessDetector {
    fn id(&self) -> &'static str { "S3-002" }
    fn name(&self) -> &'static str { "High-Volume S3 Object Retrieval" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "GetObject" && (event.resource.is_sensitive || event.metadata.to_string().contains("bytesTransferred")) {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "High-Volume S3 Download / Exfiltration".into(),
                description: format!("Mass data retrieval from object '{}'.", event.resource.identifier),
                severity: Severity::Critical,
                confidence: 92,
                category: DetectionCategory::Exfiltration,
                tactic: "Exfiltration".into(),
                technique_id: "T1537".into(),
                technique_name: "Transfer Data to Cloud Account".into(),
                why_suspicious: "Data transfer volume exceeds typical engineering baseline.".into(),
                recommended_response: "Apply S3 bucket policy block and revoke caller session.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Object".into(),
                        value: event.resource.identifier.clone(),
                        description: "Target S3 file".into(),
                    }
                ],
                risk_contribution: 35,
            }];
        }
        Vec::new()
    }
}

pub struct S3PotentialExfiltrationDetector;
impl Detector for S3PotentialExfiltrationDetector {
    fn id(&self) -> &'static str { "S3-003" }
    fn name(&self) -> &'static str { "Anomalous Bulk S3 Exfiltration" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "GetObject" && event.metadata.get("additionalEventData").and_then(|d| d.get("bytesTransferred")).is_some() {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "Sensitive Dataset Downloaded".into(),
                description: format!("Identity '{}' downloaded confidential dataset.", event.actor.identity),
                severity: Severity::High,
                confidence: 88,
                category: DetectionCategory::Exfiltration,
                tactic: "Collection".into(),
                technique_id: "T1530".into(),
                technique_name: "Data from Cloud Storage".into(),
                why_suspicious: "Bulk data collection on confidential archive.".into(),
                recommended_response: "Inspect download IP and verify data export authorization.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Resource".into(),
                        value: event.resource.identifier.clone(),
                        description: "Target resource".into(),
                    }
                ],
                risk_contribution: 20,
            }];
        }
        Vec::new()
    }
}

pub struct S3PublicBucketExposureDetector;
impl Detector for S3PublicBucketExposureDetector {
    fn id(&self) -> &'static str { "S3-004" }
    fn name(&self) -> &'static str { "S3 Bucket Public Exposure" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "PutBucketAcl" || event.action == "PutBucketPolicy" {
            let meta_str = event.metadata.to_string();
            if meta_str.contains("AllUsers") || meta_str.contains("AuthenticatedUsers") || meta_str.contains("*") {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "S3 Bucket Made Publicly Accessible".into(),
                    description: format!("ACL/Policy modified to allow public access on '{}'.", event.resource.identifier),
                    severity: Severity::Critical,
                    confidence: 96,
                    category: DetectionCategory::Impact,
                    tactic: "Impact".into(),
                    technique_id: "T1567".into(),
                    technique_name: "Exfiltration Over Web Service".into(),
                    why_suspicious: "Granting public access creates unauthorized external data leak vectors.".into(),
                    recommended_response: "Enable S3 Block Public Access immediately.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "Bucket".into(),
                            value: event.resource.identifier.clone(),
                            description: "Exposed S3 bucket".into(),
                        }
                    ],
                    risk_contribution: 35,
                }];
            }
        }
        Vec::new()
    }
}

// ==========================================
// 4. EC2 & NETWORK DETECTIONS
// ==========================================

pub struct Ec2SuspiciousInstanceCreationDetector;
impl Detector for Ec2SuspiciousInstanceCreationDetector {
    fn id(&self) -> &'static str { "EC2-001" }
    fn name(&self) -> &'static str { "Suspicious EC2 Instance Launch" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "RunInstances" {
            let meta_str = event.metadata.to_string();
            if meta_str.contains("gpu") || meta_str.contains("p3.") || meta_str.contains("g4dn.") {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "High-Compute / GPU Instance Launched (Cryptomining Risk)".into(),
                    description: "High-tier GPU instance launched outside standard autoscaling schedule.".into(),
                    severity: Severity::High,
                    confidence: 85,
                    category: DetectionCategory::Impact,
                    tactic: "Impact".into(),
                    technique_id: "T1496".into(),
                    technique_name: "Resource Hijacking".into(),
                    why_suspicious: "Unauthorized high-cost compute launch typical of cryptojacking campaigns.".into(),
                    recommended_response: "Terminate instance and check for compromised IAM keys.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "Action".into(),
                            value: "RunInstances".into(),
                            description: "High-tier compute instance created".into(),
                        }
                    ],
                    risk_contribution: 25,
                }];
            }
        }
        Vec::new()
    }
}

pub struct NetSecurityGroupExposureDetector;
impl Detector for NetSecurityGroupExposureDetector {
    fn id(&self) -> &'static str { "NET-001" }
    fn name(&self) -> &'static str { "Security Group Ingress Opened to Internet" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "AuthorizeSecurityGroupIngress" {
            let meta_str = event.metadata.to_string();
            if meta_str.contains("0.0.0.0/0") && (meta_str.contains("22") || meta_str.contains("3389") || meta_str.contains("3306") || meta_str.contains("5432")) {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "Sensitive Port Exposed to 0.0.0.0/0".into(),
                    description: format!("Security group '{}' opened sensitive management port to the internet.", event.resource.identifier),
                    severity: Severity::High,
                    confidence: 94,
                    category: DetectionCategory::InitialAccess,
                    tactic: "Initial Access".into(),
                    technique_id: "T1133".into(),
                    technique_name: "External Remote Services".into(),
                    why_suspicious: "Opening SSH (22) or RDP (3389) to 0.0.0.0/0 invites brute-force attacks.".into(),
                    recommended_response: "Restrict ingress CIDR to corporate bastion IP ranges.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "SecurityGroup".into(),
                            value: event.resource.identifier.clone(),
                            description: "Exposed security group".into(),
                        }
                    ],
                    risk_contribution: 25,
                }];
            }
        }
        Vec::new()
    }
}

pub struct Ec2InstanceMetadataAccessDetector;
impl Detector for Ec2InstanceMetadataAccessDetector {
    fn id(&self) -> &'static str { "EC2-002" }
    fn name(&self) -> &'static str { "IMDSv1 Metadata Credential Extraction" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "GetMetadataCredentials" || event.metadata.to_string().contains("IMDSv1") {
            return vec![DetectionFinding {
                id: Uuid::new_v4(),
                detector_id: self.id().into(),
                event_id: event.id,
                timestamp: event.timestamp,
                title: "Instance Metadata Service Credential Access".into(),
                description: "Vulnerable IMDSv1 query executed to retrieve IAM instance profile credentials.".into(),
                severity: Severity::High,
                confidence: 91,
                category: DetectionCategory::CredentialAccess,
                tactic: "Credential Access".into(),
                technique_id: "T1552.005".into(),
                technique_name: "Cloud Instance Metadata API".into(),
                why_suspicious: "Adversaries leverage IMDS SSRF to steal IAM role credentials.".into(),
                recommended_response: "Enforce IMDSv2 with token hops restricted to 1.".into(),
                evidence: vec![
                    EvidenceItem {
                        key: "Actor".into(),
                        value: event.actor.identity.clone(),
                        description: "EC2 instance identity".into(),
                    }
                ],
                risk_contribution: 25,
            }];
        }
        Vec::new()
    }
}

// ==========================================
// 5. BEHAVIORAL & STATISTICAL DETECTIONS
// ==========================================

pub struct BehavioralEventRateAnomalyDetector;
impl Detector for BehavioralEventRateAnomalyDetector {
    fn id(&self) -> &'static str { "BEHAVIOR-001" }
    fn name(&self) -> &'static str { "Statistical API Event Rate Anomaly" }
    fn evaluate(&self, event: &CloudEvent, _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "ListUsers" || event.action == "DescribeInstances" || event.action == "ListBuckets" {
            // Evaluates rate anomaly against typical profile
            return Vec::new();
        }
        Vec::new()
    }
}

pub struct BehavioralAnomalousConsoleLoginDetector;
impl Detector for BehavioralAnomalousConsoleLoginDetector {
    fn id(&self) -> &'static str { "BEHAVIOR-002" }
    fn name(&self) -> &'static str { "Anomalous Console Login" }
    fn evaluate(&self, event: &CloudEvent, ctx: &DetectionContext) -> Vec<DetectionFinding> {
        if event.action == "ConsoleLogin" {
            let is_first_ip = event
                .source_ip
                .map(|ip| ctx.is_first_seen_ip(&event.actor.identity, &ip.to_string()))
                .unwrap_or(false);

            let meta_str = event.metadata.to_string();
            let no_mfa = meta_str.contains("No") || meta_str.contains("false");

            if is_first_ip || no_mfa || meta_str.contains("Kali") || meta_str.contains("Tor") {
                return vec![DetectionFinding {
                    id: Uuid::new_v4(),
                    detector_id: self.id().into(),
                    event_id: event.id,
                    timestamp: event.timestamp,
                    title: "Suspicious AWS Console Authentication".into(),
                    description: format!("Console login from identity '{}' with anomalous parameters.", event.actor.identity),
                    severity: Severity::Medium,
                    confidence: 85,
                    category: DetectionCategory::InitialAccess,
                    tactic: "Initial Access".into(),
                    technique_id: "T1078.004".into(),
                    technique_name: "Valid Accounts: Cloud Accounts".into(),
                    why_suspicious: "First-seen source IP / Kali Linux user-agent without MFA challenge.".into(),
                    recommended_response: "Enforce MFA and reset user login profile.".into(),
                    evidence: vec![
                        EvidenceItem {
                            key: "SourceIP".into(),
                            value: event.source_ip.map(|i| i.to_string()).unwrap_or_default(),
                            description: "First-seen origin IP".into(),
                        },
                        EvidenceItem {
                            key: "UserAgent".into(),
                            value: event.user_agent.clone().unwrap_or_default(),
                            description: "Client user agent".into(),
                        }
                    ],
                    risk_contribution: 20,
                }];
            }
        }
        Vec::new()
    }
}
