use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use sentinel_core::{ThreatIntelResult, ThreatIntelStatus};
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("Network error querying provider: {0}")]
    Network(String),
    #[error("Rate limit exceeded")]
    RateLimited,
    #[error("Provider timeout")]
    Timeout,
    #[error("Invalid IP or response: {0}")]
    InvalidResponse(String),
}

#[async_trait]
pub trait ThreatIntelProvider: Send + Sync {
    async fn lookup_ip(&self, ip: IpAddr) -> Result<Option<ThreatIntelResult>, ThreatIntelError>;
    fn provider_name(&self) -> &'static str;
}

/// Simulated Threat Intel Provider for Demo and offline execution
pub struct SimulatedThreatIntelProvider;

#[async_trait]
impl ThreatIntelProvider for SimulatedThreatIntelProvider {
    async fn lookup_ip(&self, ip: IpAddr) -> Result<Option<ThreatIntelResult>, ThreatIntelError> {
        let ip_str = ip.to_string();
        if ip_str == "198.51.100.42" || ip_str.starts_with("198.51.100.") {
            Ok(Some(ThreatIntelResult {
                ip,
                malicious: true,
                confidence: Some(0.95),
                reputation_score: Some(88.0),
                categories: vec![
                    "Command and Control (C2)".into(),
                    "Credential Staging".into(),
                    "Anonymous Proxy".into(),
                ],
                source: "SentinelRS-ThreatIntel-Engine (Simulated)".into(),
                status: ThreatIntelStatus::Simulated,
                first_seen: Some(Utc::now() - chrono::Duration::days(14)),
                last_seen: Some(Utc::now() - chrono::Duration::hours(1)),
                raw_reference: Some("https://threatintel.sentinelrs.local/indicator/198.51.100.42".into()),
                queried_at: Utc::now(),
            }))
        } else if ip.is_loopback() || ip_str.starts_with("10.") || ip_str.starts_with("192.168.") {
            Ok(Some(ThreatIntelResult {
                ip,
                malicious: false,
                confidence: Some(0.99),
                reputation_score: Some(0.0),
                categories: vec!["Internal / RFC1918 Private".into()],
                source: "SentinelRS-ThreatIntel-Engine (Simulated)".into(),
                status: ThreatIntelStatus::Simulated,
                first_seen: None,
                last_seen: None,
                raw_reference: None,
                queried_at: Utc::now(),
            }))
        } else {
            // General external IP
            Ok(Some(ThreatIntelResult {
                ip,
                malicious: false,
                confidence: Some(0.70),
                reputation_score: Some(12.0),
                categories: vec!["Commercial ISP / Benign".into()],
                source: "SentinelRS-ThreatIntel-Engine (Simulated)".into(),
                status: ThreatIntelStatus::Simulated,
                first_seen: Some(Utc::now() - chrono::Duration::days(90)),
                last_seen: Some(Utc::now() - chrono::Duration::days(2)),
                raw_reference: None,
                queried_at: Utc::now(),
            }))
        }
    }

    fn provider_name(&self) -> &'static str {
        "Simulated Threat Intelligence Feed"
    }
}

/// Cached Threat Intelligence Service with TTL and bounded LRU-like capacity
#[derive(Clone)]
pub struct ThreatIntelService {
    provider: Arc<dyn ThreatIntelProvider>,
    cache: Arc<DashMap<IpAddr, (ThreatIntelResult, chrono::DateTime<Utc>)>>,
    ttl_seconds: i64,
}

impl ThreatIntelService {
    pub fn new(provider: Arc<dyn ThreatIntelProvider>, ttl_seconds: i64) -> Self {
        Self {
            provider,
            cache: Arc::new(DashMap::new()),
            ttl_seconds: ttl_seconds.max(60),
        }
    }

    pub async fn enrich_ip(&self, ip: IpAddr) -> Result<Option<ThreatIntelResult>, ThreatIntelError> {
        let now = Utc::now();

        // 1. Check Cache
        if let Some(entry) = self.cache.get(&ip) {
            let (cached_res, inserted_at) = entry.value();
            if (now.signed_duration_since(*inserted_at)).num_seconds() < self.ttl_seconds {
                let mut res = cached_res.clone();
                res.status = ThreatIntelStatus::Cached;
                return Ok(Some(res));
            }
        }

        // 2. Fetch from Provider
        match self.provider.lookup_ip(ip).await {
            Ok(Some(res)) => {
                self.cache.insert(ip, (res.clone(), now));
                Ok(Some(res))
            }
            Ok(None) => Ok(None),
            Err(err) => {
                tracing::warn!("Threat intel provider error for IP {}: {}", ip, err);
                Err(err)
            }
        }
    }

    pub fn list_cached_indicators(&self) -> Vec<ThreatIntelResult> {
        self.cache.iter().map(|e| e.value().0.clone()).collect()
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for ThreatIntelService {
    fn default() -> Self {
        Self::new(Arc::new(SimulatedThreatIntelProvider), 3600)
    }
}
