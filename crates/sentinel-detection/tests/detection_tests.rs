use sentinel_core::{DetectionCategory, Severity};
use sentinel_detection::DetectorRegistry;
use sentinel_normalizer::CloudTrailParser;

#[test]
fn test_iam_admin_policy_attachment_detector() {
    let registry = DetectorRegistry::new();
    let json = r#"{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA12345EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/attacker-demo",
            "userName": "attacker-demo"
        },
        "eventTime": "2026-10-07T09:35:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "requestParameters": {
            "userName": "attacker-demo",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        "responseElements": null
    }"#;

    let events = CloudTrailParser::parse_str(json).unwrap();
    let findings = registry.evaluate_event(&events[0]);

    assert!(!findings.is_empty(), "Should trigger IAM-001");
    let f = &findings[0];
    assert_eq!(f.detector_id, "IAM-001");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.category, DetectionCategory::PrivilegeEscalation);
    assert_eq!(f.technique_id, "T1098");
}

#[test]
fn test_cloudtrail_stop_logging_detector() {
    let registry = DetectorRegistry::new();
    let json = r#"{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "attacker-demo"
        },
        "eventTime": "2026-10-07T09:45:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "ap-south-1",
        "requestParameters": {
            "name": "prod-audit-trail"
        }
    }"#;

    let events = CloudTrailParser::parse_str(json).unwrap();
    let findings = registry.evaluate_event(&events[0]);

    assert!(!findings.is_empty(), "Should trigger CT-001");
    assert_eq!(findings[0].detector_id, "CT-001");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn test_s3_mass_download_detector() {
    let registry = DetectorRegistry::new();
    let json = r#"{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "attacker-demo"
        },
        "eventTime": "2026-10-07T09:40:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "ap-south-1",
        "requestParameters": {
            "bucketName": "sentinel-customer-pii-production",
            "key": "financial_records.csv"
        },
        "additionalEventData": { "bytesTransferred": 500000000 }
    }"#;

    let events = CloudTrailParser::parse_str(json).unwrap();
    let findings = registry.evaluate_event(&events[0]);

    assert!(!findings.is_empty(), "Should trigger S3-002");
    assert_eq!(findings[0].detector_id, "S3-002");
}
