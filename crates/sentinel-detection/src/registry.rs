use crate::context::DetectionContext;
use crate::engine::Detector;
use crate::rules::*;
use sentinel_core::{CloudEvent, DetectionFinding};
use std::collections::HashMap;

pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
    enabled_flags: HashMap<&'static str, bool>,
    pub context: DetectionContext,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            detectors: Vec::new(),
            enabled_flags: HashMap::new(),
            context: DetectionContext::new(),
        };
        registry.register_all_builtins();
        registry
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        let id = detector.id();
        self.enabled_flags.insert(id, true);
        self.detectors.push(detector);
    }

    pub fn set_enabled(&mut self, id: &'static str, enabled: bool) {
        self.enabled_flags.insert(id, enabled);
    }

    pub fn evaluate_event(&self, event: &CloudEvent) -> Vec<DetectionFinding> {
        self.context.update_with_event(event);

        let mut findings = Vec::new();
        for detector in &self.detectors {
            let is_enabled = *self.enabled_flags.get(detector.id()).unwrap_or(&true);
            if is_enabled {
                let results = detector.evaluate(event, &self.context);
                findings.extend(results);
            }
        }
        findings
    }

    fn register_all_builtins(&mut self) {
        // IAM Detections
        self.register(Box::new(IamAdminPolicyAttachmentDetector));
        self.register(Box::new(IamPrivilegeEscalationDetector));
        self.register(Box::new(IamAccessKeyCreationDetector));
        self.register(Box::new(IamMfaDeactivationDetector));
        self.register(Box::new(IamSuspiciousAssumeRoleDetector));

        // CloudTrail Detections
        self.register(Box::new(CloudTrailLoggingDisabledDetector));
        self.register(Box::new(CloudTrailTrailModifiedDetector));
        self.register(Box::new(CloudTrailTrailDeletedDetector));

        // S3 Detections
        self.register(Box::new(S3SuspiciousBucketAccessDetector));
        self.register(Box::new(S3MassObjectAccessDetector));
        self.register(Box::new(S3PotentialExfiltrationDetector));
        self.register(Box::new(S3PublicBucketExposureDetector));

        // EC2 & Network Detections
        self.register(Box::new(Ec2SuspiciousInstanceCreationDetector));
        self.register(Box::new(NetSecurityGroupExposureDetector));
        self.register(Box::new(Ec2InstanceMetadataAccessDetector));

        // Behavioral & Statistical Detections
        self.register(Box::new(BehavioralEventRateAnomalyDetector));
        self.register(Box::new(BehavioralAnomalousConsoleLoginDetector));
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
