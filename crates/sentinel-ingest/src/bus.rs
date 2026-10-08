use sentinel_core::CloudEvent;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<CloudEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: CloudEvent) -> Result<usize, broadcast::error::SendError<CloudEvent>> {
        self.sender.send(event)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CloudEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(2048)
    }
}
