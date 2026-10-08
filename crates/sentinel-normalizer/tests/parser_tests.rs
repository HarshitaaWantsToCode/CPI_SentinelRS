use sentinel_normalizer::{CloudTrailParser, NormalizationError};

#[test]
fn test_parse_single_valid_cloudtrail_event() {
    let raw = r#"{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA123456789EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/attacker-demo",
            "accountId": "123456789012",
            "userName": "attacker-demo"
        },
        "eventTime": "2026-10-07T09:30:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.42",
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": {
            "userName": "attacker-demo"
        },
        "responseElements": null
    }"#;

    let events = CloudTrailParser::parse_str(raw).expect("Should parse single valid event");
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.action, "CreateAccessKey");
    assert_eq!(ev.actor.identity, "attacker-demo");
    assert_eq!(ev.source_ip.unwrap().to_string(), "198.51.100.42");
    assert_eq!(ev.region.as_deref(), Some("us-east-1"));
}

#[test]
fn test_parse_records_array() {
    let raw = include_str!("../../../data/demo/normal.json");
    let events = CloudTrailParser::parse_str(raw).expect("Should parse Records array");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].action, "ListBuckets");
    assert_eq!(events[1].action, "DescribeInstances");
}

#[test]
fn test_malformed_json_returns_error_without_panic() {
    let raw = "{ this is malformed json }";
    let res = CloudTrailParser::parse_str(raw);
    assert!(res.is_err());
}

#[test]
fn test_missing_timestamp_field() {
    let raw = r#"{
        "eventName": "ListBuckets"
    }"#;
    let res = CloudTrailParser::parse_str(raw);
    assert!(res.is_err());
    match res.unwrap_err() {
        NormalizationError::MissingField(field) => assert_eq!(field, "eventTime"),
        _ => panic!("Expected MissingField error"),
    }
}
