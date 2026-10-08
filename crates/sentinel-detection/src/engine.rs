use crate::context::DetectionContext;
use sentinel_core::{CloudEvent, DetectionFinding};

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn evaluate(&self, event: &CloudEvent, context: &DetectionContext) -> Vec<DetectionFinding>;
}
