use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechniqueInfo {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub observed_count: u32,
    pub active_in_incidents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMatrixData {
    pub tactics: Vec<String>,
    pub techniques: Vec<MitreTechniqueInfo>,
}

pub struct MitreMapper;

impl MitreMapper {
    pub fn get_matrix_data() -> MitreMatrixData {
        MitreMatrixData {
            tactics: vec![
                "Initial Access".into(),
                "Persistence".into(),
                "Privilege Escalation".into(),
                "Defense Evasion".into(),
                "Credential Access".into(),
                "Discovery".into(),
                "Collection".into(),
                "Exfiltration".into(),
            ],
            techniques: vec![
                MitreTechniqueInfo {
                    id: "T1078.004".into(),
                    name: "Valid Accounts: Cloud Accounts".into(),
                    tactic: "Initial Access".into(),
                    description: "Adversaries may obtain and abuse credentials of existing cloud accounts.".into(),
                    observed_count: 3,
                    active_in_incidents: vec!["SR-1042".into()],
                },
                MitreTechniqueInfo {
                    id: "T1098".into(),
                    name: "Account Manipulation".into(),
                    tactic: "Privilege Escalation".into(),
                    description: "Adversaries may manipulate accounts to maintain access of higher privileges.".into(),
                    observed_count: 5,
                    active_in_incidents: vec!["SR-1042".into()],
                },
                MitreTechniqueInfo {
                    id: "T1098.001".into(),
                    name: "Additional Cloud Credentials".into(),
                    tactic: "Persistence".into(),
                    description: "Adversaries may generate secondary API keys for persistence.".into(),
                    observed_count: 2,
                    active_in_incidents: vec!["SR-1042".into()],
                },
                MitreTechniqueInfo {
                    id: "T1562.008".into(),
                    name: "Disable Cloud Logs".into(),
                    tactic: "Defense Evasion".into(),
                    description: "Adversaries may disable or delete CloudTrail trails to evade logging.".into(),
                    observed_count: 1,
                    active_in_incidents: vec!["SR-1042".into()],
                },
                MitreTechniqueInfo {
                    id: "T1537".into(),
                    name: "Transfer Data to Cloud Account".into(),
                    tactic: "Exfiltration".into(),
                    description: "Adversaries may exfiltrate data by transferring it to an external account or downloading bulk objects.".into(),
                    observed_count: 4,
                    active_in_incidents: vec!["SR-1042".into()],
                },
            ],
        }
    }
}
