use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailCheckpoint {
    pub last_event_id: Option<String>,
    pub last_event_time: Option<DateTime<Utc>>,
    pub total_polled_count: usize,
}

impl CloudTrailCheckpoint {
    pub fn new() -> Self {
        Self {
            last_event_id: None,
            last_event_time: None,
            total_polled_count: 0,
        }
    }
}

impl Default for CloudTrailCheckpoint {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AwsCloudTrailCollector {
    checkpoint: Arc<RwLock<CloudTrailCheckpoint>>,
    poll_interval_seconds: u64,
}

impl AwsCloudTrailCollector {
    pub fn new(poll_interval_seconds: u64) -> Self {
        Self {
            checkpoint: Arc::new(RwLock::new(CloudTrailCheckpoint::new())),
            poll_interval_seconds: poll_interval_seconds.max(5),
        }
    }

    pub fn poll_interval_seconds(&self) -> u64 {
        self.poll_interval_seconds
    }

    pub async fn get_checkpoint(&self) -> CloudTrailCheckpoint {
        self.checkpoint.read().await.clone()
    }

    pub async fn update_checkpoint(&self, event_id: String, event_time: DateTime<Utc>) {
        let mut cp = self.checkpoint.write().await;
        cp.last_event_id = Some(event_id);
        cp.last_event_time = Some(event_time);
        cp.total_polled_count += 1;
    }
}
