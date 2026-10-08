use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathQueryRequest {
    pub source: String,
    pub target: String,
    pub max_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathResult {
    pub path: Vec<String>,
    pub node_labels: Vec<String>,
    pub path_risk_score: u8,
    pub justification: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "Actor", "Role", "Policy", "S3Bucket", "EC2", "IpAddress"
    pub layer: String,     // "Infrastructure" or "Activity"
    pub criticality: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub action: String, // "CAN_ASSUME", "ATTACHED_TO", "ACCESSED", "CONTAINS"
    pub edge_type: String, // "Infrastructure" or "AttackSequence"
    pub confidence: u8,
}

pub struct DeepAttackGraph {
    graph: DiGraph<GraphNode, GraphEdge>,
    node_indices: HashMap<String, NodeIndex>,
}

impl DeepAttackGraph {
    pub fn new() -> Self {
        let mut dag = Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        };
        dag.seed_hybrid_graph();
        dag
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeIndex {
        if let Some(&idx) = self.node_indices.get(&node.id) {
            idx
        } else {
            let id = node.id.clone();
            let idx = self.graph.add_node(node);
            self.node_indices.insert(id, idx);
            idx
        }
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str, edge: GraphEdge) {
        if let (Some(&src_idx), Some(&tgt_idx)) = (self.node_indices.get(source_id), self.node_indices.get(target_id)) {
            self.graph.add_edge(src_idx, tgt_idx, edge);
        }
    }

    pub fn find_shortest_attack_path(&self, source_id: &str, target_id: &str, max_depth: usize) -> Option<AttackPathResult> {
        let src_idx = *self.node_indices.get(source_id)?;
        let tgt_idx = *self.node_indices.get(target_id)?;

        let paths: Vec<Vec<NodeIndex>> = all_simple_paths(&self.graph, src_idx, tgt_idx, 0, Some(max_depth)).collect();

        if let Some(shortest) = paths.into_iter().min_by_key(|p| p.len()) {
            let mut path_ids = Vec::new();
            let mut labels = Vec::new();
            let mut total_crit = 0;

            for idx in shortest {
                let node = &self.graph[idx];
                path_ids.push(node.id.clone());
                labels.push(node.label.clone());
                total_crit += node.criticality;
            }

            let path_risk = ((total_crit / (path_ids.len() as u8).max(1)) + 20).min(100);

            Some(AttackPathResult {
                path: path_ids,
                node_labels: labels,
                path_risk_score: path_risk,
                justification: vec![
                    "Shortest traversal from untrusted origin to critical cloud data store".into(),
                    "Adversary traverses privilege escalation path via AdministratorAccess".into(),
                ],
            })
        } else {
            None
        }
    }

    fn seed_hybrid_graph(&mut self) {
        let ip_node = GraphNode {
            id: "ip-198-51-100-42".into(),
            label: "198.51.100.42 (Attacker IP)".into(),
            node_type: "IpAddress".into(),
            layer: "Activity".into(),
            criticality: 95,
        };
        let user_node = GraphNode {
            id: "user-attacker-demo".into(),
            label: "attacker-demo (Compromised IAM)".into(),
            node_type: "IamUser".into(),
            layer: "Infrastructure".into(),
            criticality: 85,
        };
        let role_node = GraphNode {
            id: "role-admin-prod".into(),
            label: "AdministratorRole".into(),
            node_type: "IamRole".into(),
            layer: "Infrastructure".into(),
            criticality: 95,
        };
        let s3_node = GraphNode {
            id: "s3-customer-pii-production".into(),
            label: "s3://sentinel-customer-pii-production".into(),
            node_type: "S3Bucket".into(),
            layer: "Infrastructure".into(),
            criticality: 99,
        };

        self.add_node(ip_node);
        self.add_node(user_node);
        self.add_node(role_node);
        self.add_node(s3_node);

        self.add_edge(
            "ip-198-51-100-42",
            "user-attacker-demo",
            GraphEdge {
                source: "ip-198-51-100-42".into(),
                target: "user-attacker-demo".into(),
                action: "AUTHENTICATED".into(),
                edge_type: "AttackSequence".into(),
                confidence: 95,
            },
        );

        self.add_edge(
            "user-attacker-demo",
            "role-admin-prod",
            GraphEdge {
                source: "user-attacker-demo".into(),
                target: "role-admin-prod".into(),
                action: "CAN_ASSUME".into(),
                edge_type: "Infrastructure".into(),
                confidence: 99,
            },
        );

        self.add_edge(
            "role-admin-prod",
            "s3-customer-pii-production",
            GraphEdge {
                source: "role-admin-prod".into(),
                target: "s3-customer-pii-production".into(),
                action: "ACCESSES_DATA".into(),
                edge_type: "Infrastructure".into(),
                confidence: 98,
            },
        );
    }
}

impl Default for DeepAttackGraph {
    fn default() -> Self {
        Self::new()
    }
}
