//! DNS Resolver Pool Implementation
//!
//! This module provides a thread-safe pool of DNS resolvers for efficient DNS query distribution.
//! It supports multiple DNS servers, connection reuse, and comprehensive error handling.

use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

/// Configuration for DNS resolver pool
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// List of DNS server addresses to use
    pub servers: Vec<SocketAddr>,
    /// Number of resolver instances to maintain in the pool
    pub pool_size: usize,
    /// Timeout for DNS queries in seconds
    pub query_timeout: Duration,
    /// Maximum number of retries for failed queries
    pub max_retries: usize,
    /// Cache size for DNS responses
    pub cache_size: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53),
            ],
            pool_size: 10,
            query_timeout: Duration::from_secs(5),
            max_retries: 3,
            cache_size: 1024,
        }
    }
}

/// Statistics for monitoring DNS resolver pool performance
#[derive(Debug, Default, Clone)]
pub struct DnsPoolStats {
    /// Total number of DNS queries made
    pub total_queries: u64,
    /// Number of successful queries
    pub successful_queries: u64,
    /// Number of failed queries
    pub failed_queries: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Current pool utilization percentage
    pub pool_utilization_percent: f32,
}

impl DnsPoolStats {
    /// Calculate cache hit rate as a percentage
    pub fn cache_hit_rate(&self) -> f32 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f32 / total as f32) * 100.0
        }
    }

    /// Calculate success rate as a percentage
    pub fn success_rate(&self) -> f32 {
        let total = self.successful_queries + self.failed_queries;
        if total == 0 {
            0.0
        } else {
            (self.successful_queries as f32 / total as f32) * 100.0
        }
    }
}

/// Thread-safe DNS resolver pool with advanced features
pub struct DnsResolverPool {
    /// Pool of DNS resolver instances
    resolvers: Vec<Arc<TokioAsyncResolver>>,
    /// Round-robin index for load distribution
    index: AtomicUsize,
    /// Configuration settings
    config: DnsConfig,
    /// Performance statistics (protected by mutex for interior mutability)
    stats: Arc<Mutex<DnsPoolStats>>,
    /// Health status of each resolver
    health_status: Arc<Mutex<Vec<ResolverHealth>>>,
    /// Per-resolver healthy flag — lock-free, used in hot-path selection.
    /// Updated via update_resolver_health(), read by get_resolver().
    health_flags: Vec<std::sync::atomic::AtomicBool>,
    /// Number of queries currently in-flight (incremented on checkout, decremented on result).
    active_queries: AtomicUsize,
}

/// Health status for individual resolvers
#[derive(Debug, Clone, Default)]
struct ResolverHealth {
    /// Last successful operation timestamp
    last_success: Option<Instant>,
    /// Number of consecutive failures
    failure_count: u32,
    /// Whether this resolver is currently healthy
    is_healthy: bool,
}

impl DnsResolverPool {
    /// Create a new DNS resolver pool with the specified configuration
    ///
    /// # Arguments
    /// * `config` - Configuration for the DNS pool
    ///
    /// # Returns
    /// * `anyhow::Result<Self>` - The configured pool or an error
    ///
    /// # Errors
    /// * Returns an error if pool_size is 0
    /// * Returns an error if no valid DNS servers are provided
    /// * Returns an error if resolver creation fails
    pub fn new(config: DnsConfig) -> anyhow::Result<Self> {
        // Validate configuration
        if config.pool_size == 0 {
            return Err(anyhow::anyhow!("Pool size must be greater than 0"));
        }

        if config.servers.is_empty() {
            return Err(anyhow::anyhow!("At least one DNS server must be provided"));
        }

        let mut resolvers = Vec::with_capacity(config.pool_size);
        let mut health_status = Vec::with_capacity(config.pool_size);
        let mut health_flags = Vec::with_capacity(config.pool_size);

        // Create resolver instances for the pool
        for _ in 0..config.pool_size {
            let resolver = Self::create_resolver(&config)?;
            resolvers.push(Arc::new(resolver));
            health_status.push(ResolverHealth::default());
            health_flags.push(AtomicBool::new(true)); // All start healthy
        }

        Ok(Self {
            resolvers,
            index: AtomicUsize::new(0),
            config,
            stats: Arc::new(Mutex::new(DnsPoolStats::default())),
            health_status: Arc::new(Mutex::new(health_status)),
            health_flags,
            active_queries: AtomicUsize::new(0),
        })
    }

    /// Create a single DNS resolver with the given configuration
    fn create_resolver(config: &DnsConfig) -> anyhow::Result<TokioAsyncResolver> {
        let mut resolver_config = ResolverConfig::new();

        // Add all configured DNS servers
        for server in &config.servers {
            resolver_config.add_name_server(NameServerConfig {
                socket_addr: *server,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                tls_config: None,
                bind_addr: None,
            });
        }

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = config.query_timeout;
        resolver_opts.attempts = config.max_retries;
        resolver_opts.ndots = 0; // Don't append search domains from /etc/resolv.conf

        Ok(TokioAsyncResolver::tokio(resolver_config, resolver_opts))
    }

    /// Get a resolver from the pool along with its index for health tracking.
    ///
    /// Returns `(resolver_index, resolver)`. Callers **must** call
    /// `update_resolver_health(resolver_index, success, response_time)` after
    /// each query so circuit-breaker flags stay accurate.
    ///
    /// Uses the same health-aware round-robin strategy as `get_resolver`.
    pub async fn get_resolver_with_index(&self) -> (usize, Arc<TokioAsyncResolver>) {
        let len = self.resolvers.len();
        assert!(len > 0, "DNS resolver pool is empty");

        self.active_queries.fetch_add(1, Ordering::Relaxed);
        let start = self.index.fetch_add(1, Ordering::Relaxed);

        // Prefer a healthy resolver via lock-free AtomicBool scan.
        for offset in 0..len {
            let i = (start + offset) % len;
            if self.health_flags[i].load(Ordering::Relaxed) {
                return (i, self.resolvers[i].clone());
            }
        }

        // All resolvers are unhealthy — fall back to round-robin anyway.
        let i = start % len;
        (i, self.resolvers[i].clone())
    }

    /// Get a resolver from the pool using health-aware round-robin distribution.
    ///
    /// P1-6 FIX: No Mutex in hot path. Uses lock-free AtomicBool per resolver for
    /// health checks and AtomicUsize for round-robin.
    ///
    /// Health-aware: skips resolvers marked unhealthy (via AtomicBool flags).
    /// If ALL resolvers are unhealthy, falls back to pure round-robin (better to
    /// try a potentially-recovered resolver than fail completely).
    ///
    /// # Returns
    /// * `Arc<TokioAsyncResolver>` - A resolver instance from the pool
    ///
    /// # Panics
    /// * Panics if the pool is empty (should never happen in normal operation)
    pub async fn get_resolver(&self) -> Arc<TokioAsyncResolver> {
        let (_, resolver) = self.get_resolver_with_index().await;
        resolver
    }

    /// Perform a DNS lookup with automatic health tracking.
    ///
    /// This is the preferred way to query the pool: it selects a resolver via
    /// health-aware round-robin, executes the lookup, and records the outcome
    /// (success/failure and response time) via `update_resolver_health()`.
    ///
    /// # Arguments
    /// * `domain` - The domain name to resolve
    ///
    /// # Returns
    /// * `anyhow::Result<Vec<std::net::IpAddr>>` - resolved addresses or an error
    pub async fn resolve_with_health(&self, domain: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        let start_time = Instant::now();
        let (resolver_index, resolver) = self.get_resolver_with_index().await;

        match resolver.lookup_ip(domain).await {
            Ok(lookup) => {
                let elapsed = start_time.elapsed();
                self.update_resolver_health(resolver_index, true, Some(elapsed));
                Ok(lookup.iter().collect())
            }
            Err(e) => {
                self.update_resolver_health(resolver_index, false, None);
                Err(anyhow::anyhow!("DNS lookup failed for '{}': {}", domain, e))
            }
        }
    }

    /// Update resolver health status based on query results
    ///
    /// # Arguments
    /// * `resolver_index` - Index of the resolver that was used
    /// * `success` - Whether the query was successful
    /// * `response_time` - How long the query took (optional)
    pub fn update_resolver_health(&self, resolver_index: usize, success: bool, response_time: Option<Duration>) {
        let mut health_status = self.health_status.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();

        if let Some(health) = health_status.get_mut(resolver_index) {
            if success {
                health.last_success = Some(Instant::now());
                health.failure_count = 0;
                health.is_healthy = true;

                stats.successful_queries += 1;

                if let Some(rt) = response_time {
                    let rt_ms = rt.as_millis() as u64;
                    // Update rolling average (simplified)
                    stats.avg_response_time_ms =
                        (stats.avg_response_time_ms + rt_ms) / 2;
                }
            } else {
                health.failure_count += 1;
                stats.failed_queries += 1;

                // Mark as unhealthy after 3 consecutive failures
                if health.failure_count >= 3 {
                    health.is_healthy = false;
                }
            }

            // Sync lock-free health flag for hot-path selection
            if let Some(flag) = self.health_flags.get(resolver_index) {
                flag.store(health.is_healthy, Ordering::Relaxed);
            }

            stats.total_queries += 1;
            let pool_size = self.resolvers.len().max(1);
            let prev_active = self.active_queries.fetch_sub(1, Ordering::Relaxed);
            let active = prev_active.saturating_sub(1);
            stats.pool_utilization_percent = ((active * 100) / pool_size).min(100) as f32;
        }
    }

    /// Get comprehensive statistics about the DNS pool
    pub fn stats(&self) -> DnsPoolStats {
        let stats = self.stats.lock().unwrap();
        (*stats).clone()
    }

    /// Get the current configuration
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Get the number of resolvers in the pool
    pub fn pool_size(&self) -> usize {
        self.resolvers.len()
    }

    /// Check if the pool has any healthy resolvers
    pub fn has_healthy_resolvers(&self) -> bool {
        let health_status = self.health_status.lock().unwrap();
        health_status.iter().any(|h| h.is_healthy)
    }

    /// Get detailed health information for all resolvers
    pub fn resolver_health(&self) -> Vec<ResolverHealth> {
        let health_status = self.health_status.lock().unwrap();
        health_status.clone()
    }
}

impl Default for DnsResolverPool {
    fn default() -> Self {
        Self::new(DnsConfig::default()).expect("Failed to create default DNS resolver pool")
    }
}

// Global DNS pool instance with proper error handling
use lazy_static::lazy_static;

lazy_static! {
    /// Global DNS resolver pool instance
    ///
    /// This is the main entry point for DNS resolution in the application.
    /// It's configured with sensible defaults but can be overridden by
    /// creating a custom pool instance.
    pub static ref DNS_POOL: DnsResolverPool = DnsResolverPool::default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_config_validation() {
        // Test empty servers
        let invalid_config = DnsConfig {
            servers: vec![],
            pool_size: 1,
            ..Default::default()
        };
        assert!(DnsResolverPool::new(invalid_config).is_err());

        // Test zero pool size
        let invalid_config = DnsConfig {
            servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)],
            pool_size: 0,
            ..Default::default()
        };
        assert!(DnsResolverPool::new(invalid_config).is_err());
    }

    #[test]
    fn test_stats_calculations() {
        let mut stats = DnsPoolStats::default();
        stats.successful_queries = 80;
        stats.failed_queries = 20;
        stats.cache_hits = 60;
        stats.cache_misses = 40;

        assert_eq!(stats.success_rate(), 80.0);
        assert_eq!(stats.cache_hit_rate(), 60.0);
    }
}