use sentinel_correlation::DeepAttackGraph;

#[test]
fn test_find_shortest_attack_path_to_critical_bucket() {
    let graph = DeepAttackGraph::new();

    let path_opt = graph.find_shortest_attack_path("ip-198-51-100-42", "s3-customer-pii-production", 6);
    assert!(path_opt.is_some(), "Should find lateral movement path to sensitive bucket");

    let res = path_opt.unwrap();
    assert_eq!(res.path.len(), 4);
    assert_eq!(res.path[0], "ip-198-51-100-42");
    assert_eq!(res.path[1], "user-attacker-demo");
    assert_eq!(res.path[2], "role-admin-prod");
    assert_eq!(res.path[3], "s3-customer-pii-production");

    assert!(res.path_risk_score >= 80, "Path risk score must be high/critical");
}

#[test]
fn test_unreachable_target_returns_none() {
    let graph = DeepAttackGraph::new();
    let path_opt = graph.find_shortest_attack_path("ip-198-51-100-42", "non-existent-node", 6);
    assert!(path_opt.is_none());
}
