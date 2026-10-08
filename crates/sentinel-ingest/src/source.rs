use sentinel_core::CloudEvent;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Normalization error: {0}")]
    Normalization(String),
    #[error("Source depleted")]
    Depleted,
}

#[async_trait::async_trait]
pub trait EventSource: Send + Sync {
    /// Returns the next parsed and normalized canonical event in the stream
    async fn next_event(&mut self) -> Result<Option<CloudEvent>, IngestError>;
}
