use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "Actor", "Role", "Policy", "S3Bucket", "CloudTrail", "IpAddress"
    pub risk_score: u8,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphEdge {
    pub source: String,
    pub target: String,
    pub action: String, // "ASSUMED", "CREATED", "ACCESSED", "ESCALATED", "DISABLED"
    pub timestamp: String,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphData {
    pub nodes: Vec<AttackGraphNode>,
    pub edges: Vec<AttackGraphEdge>,
}

pub struct AttackGraphBuilder {
    graph: DiGraph<AttackGraphNode, AttackGraphEdge>,
    node_map: HashMap<String, NodeIndex>,
}

impl AttackGraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: AttackGraphNode) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&node.id) {
            idx
        } else {
            let id = node.id.clone();
            let idx = self.graph.add_node(node);
            self.node_map.insert(id, idx);
            idx
        }
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str, edge: AttackGraphEdge) {
        if let (Some(&src_idx), Some(&tgt_idx)) = (self.node_map.get(source_id), self.node_map.get(target_id)) {
            self.graph.add_edge(src_idx, tgt_idx, edge);
        }
    }

    pub fn graph(&self) -> &DiGraph<AttackGraphNode, AttackGraphEdge> {
        &self.graph
    }

    pub fn node_map(&self) -> &HashMap<String, NodeIndex> {
        &self.node_map
    }

    pub fn get_demo_attack_graph() -> AttackGraphData {
        AttackGraphData {
            nodes: vec![
                AttackGraphNode {
                    id: "ip-198-51-100-42".into(),
                    label: "198.51.100.42 (Attacker IP)".into(),
                    node_type: "IpAddress".into(),
                    risk_score: 95,
                    details: serde_json::json!({ "country": "RU", "asn": "AS12345", "threat_reputation": "Malicious" }),
                },
                AttackGraphNode {
                    id: "user-attacker-demo".into(),
                    label: "attacker-demo (Compromised IAM)".into(),
                    node_type: "Actor".into(),
                    risk_score: 94,
                    details: serde_json::json!({ "mfa_enabled": false, "created": "2026-09-12" }),
                },
                AttackGraphNode {
                    id: "policy-admin-access".into(),
                    label: "AdministratorAccess Policy".into(),
                    node_type: "Policy".into(),
                    risk_score: 90,
                    details: serde_json::json!({ "arn": "arn:aws:iam::aws:policy/AdministratorAccess" }),
                },
                AttackGraphNode {
                    id: "key-akia-iosfodnn7".into(),
                    label: "AccessKey AKIAIOSFODNN7EXAMPLE".into(),
                    node_type: "AccessKey".into(),
                    risk_score: 85,
                    details: serde_json::json!({ "status": "Active" }),
                },
                AttackGraphNode {
                    id: "s3-customer-pii".into(),
                    label: "s3://sentinel-customer-pii-production".into(),
                    node_type: "S3Bucket".into(),
                    risk_score: 98,
                    details: serde_json::json!({ "classification": "Confidential PII", "encryption": "AES256" }),
                },
                AttackGraphNode {
                    id: "trail-prod-audit".into(),
                    label: "prod-audit-trail (CloudTrail)".into(),
                    node_type: "CloudTrail".into(),
                    risk_score: 92,
                    details: serde_json::json!({ "status": "STOPPED", "multi_region": true }),
                },
            ],
            edges: vec![
                AttackGraphEdge {
                    source: "ip-198-51-100-42".into(),
                    target: "user-attacker-demo".into(),
                    action: "AUTHENTICATED".into(),
                    timestamp: "09:31:04".into(),
                    technique: "T1078.004".into(),
                },
                AttackGraphEdge {
                    source: "user-attacker-demo".into(),
                    target: "policy-admin-access".into(),
                    action: "ATTACHED_POLICY".into(),
                    timestamp: "09:32:03".into(),
                    technique: "T1098".into(),
                },
                AttackGraphEdge {
                    source: "user-attacker-demo".into(),
                    target: "key-akia-iosfodnn7".into(),
                    action: "CREATED_KEY".into(),
                    timestamp: "09:32:41".into(),
                    technique: "T1098.001".into(),
                },
                AttackGraphEdge {
                    source: "user-attacker-demo".into(),
                    target: "s3-customer-pii".into(),
                    action: "EXFILTRATED_DATA".into(),
                    timestamp: "09:34:02".into(),
                    technique: "T1537".into(),
                },
                AttackGraphEdge {
                    source: "user-attacker-demo".into(),
                    target: "trail-prod-audit".into(),
                    action: "STOPPED_LOGGING".into(),
                    timestamp: "09:34:31".into(),
                    technique: "T1562.008".into(),
                },
            ],
        }
    }
}

impl Default for AttackGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
