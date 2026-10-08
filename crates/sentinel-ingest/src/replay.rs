use crate::source::{EventSource, IngestError};
use sentinel_core::CloudEvent;
use sentinel_normalizer::CloudTrailParser;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct DatasetReplayer {
    file_path: PathBuf,
    events: Vec<CloudEvent>,
    current_index: usize,
    speed_multiplier: f64,
    loop_playback: bool,
}

impl DatasetReplayer {
    pub fn new(path: impl AsRef<Path>, speed_multiplier: f64, loop_playback: bool) -> Result<Self, IngestError> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let events = CloudTrailParser::parse_str(&content)
            .map_err(|e| IngestError::Normalization(e.to_string()))?;

        Ok(Self {
            file_path: path.as_ref().to_path_buf(),
            events,
            current_index: 0,
            speed_multiplier: speed_multiplier.max(0.01),
            loop_playback,
        })
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[async_trait::async_trait]
impl EventSource for DatasetReplayer {
    async fn next_event(&mut self) -> Result<Option<CloudEvent>, IngestError> {
        if self.events.is_empty() {
            return Ok(None);
        }

        if self.current_index >= self.events.len() {
            if self.loop_playback {
                self.current_index = 0;
            } else {
                return Ok(None);
            }
        }

        let event = self.events[self.current_index].clone();
        self.current_index += 1;

        // Apply realistic replay timing interval (e.g. 500ms scaled by speed)
        let delay_ms = (500.0 / self.speed_multiplier) as u64;
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        Ok(Some(event))
    }
}
