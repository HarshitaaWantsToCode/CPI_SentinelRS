use dashmap::DashMap;
use sentinel_core::CloudEvent;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ActorProfile {
    pub identity: String,
    pub known_ips: HashSet<String>,
    pub known_regions: HashSet<String>,
    pub known_services: HashSet<String>,
    pub known_actions: HashSet<String>,
    pub total_event_count: usize,
    pub hourly_distribution: [usize; 24],
}

impl ActorProfile {
    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            known_ips: HashSet::new(),
            known_regions: HashSet::new(),
            known_services: HashSet::new(),
            known_actions: HashSet::new(),
            total_event_count: 0,
            hourly_distribution: [0; 24],
        }
    }
}

#[derive(Clone)]
pub struct DetectionContext {
    profiles: Arc<DashMap<String, ActorProfile>>,
    rate_trackers: Arc<DashMap<String, Vec<i64>>>, // Actor/Service -> Timestamps (seconds)
}

impl DetectionContext {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(DashMap::new()),
            rate_trackers: Arc::new(DashMap::new()),
        }
    }

    pub fn update_with_event(&self, event: &CloudEvent) {
        let mut profile = self
            .profiles
            .entry(event.actor.identity.clone())
            .or_insert_with(|| ActorProfile::new(event.actor.identity.clone()));

        if let Some(ip) = event.source_ip {
            profile.known_ips.insert(ip.to_string());
        }
        if let Some(ref reg) = event.region {
            profile.known_regions.insert(reg.clone());
        }
        profile.known_actions.insert(event.action.clone());
        profile.total_event_count += 1;

        let hour = chrono::Timelike::hour(&event.timestamp) as usize;
        if hour < 24 {
            profile.hourly_distribution[hour] += 1;
        }

        // Update rate tracker
        let key = format!("{}:{}", event.actor.identity, event.action);
        let mut tracker = self.rate_trackers.entry(key).or_insert_with(Vec::new);
        tracker.push(event.timestamp.timestamp());
        if tracker.len() > 200 {
            tracker.remove(0);
        }
    }

    pub fn is_first_seen_ip(&self, identity: &str, ip_str: &str) -> bool {
        if let Some(profile) = self.profiles.get(identity) {
            if profile.total_event_count > 1 {
                return !profile.known_ips.contains(ip_str);
            }
        }
        false
    }

    pub fn is_first_seen_region(&self, identity: &str, region_str: &str) -> bool {
        if let Some(profile) = self.profiles.get(identity) {
            if profile.total_event_count > 1 {
                return !profile.known_regions.contains(region_str);
            }
        }
        false
    }

    pub fn get_profile(&self, identity: &str) -> Option<ActorProfile> {
        self.profiles.get(identity).map(|p| p.value().clone())
    }
}

impl Default for DetectionContext {
    fn default() -> Self {
        Self::new()
    }
}
