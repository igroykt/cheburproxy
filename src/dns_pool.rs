//! DNS Resolver Pool Implementation
//!
//! This module provides a thread-safe pool of DNS resolvers for efficient DNS query distribution.
//! It supports multiple DNS servers, connection reuse, and comprehensive error handling.

use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::{
    net::SocketAddr,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, AtomicU32, AtomicUsize, Ordering},
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
/// This is the snapshot struct returned by `stats()` — NOT used for hot-path storage.
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

/// Lock-free atomic statistics counters for hot-path updates.
/// Avoids Mutex contention that previously occurred on every DNS query.
struct AtomicDnsStats {
    total_queries: AtomicU64,
    successful_queries: AtomicU64,
    failed_queries: AtomicU64,
    /// Exponential moving average of response time, stored as milliseconds.
    avg_response_time_ms: AtomicU64,
}

impl AtomicDnsStats {
    fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            successful_queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            avg_response_time_ms: AtomicU64::new(0),
        }
    }

    /// Snapshot current counters into a DnsPoolStats struct (cold path).
    fn snapshot(&self, active_queries: usize, pool_size: usize) -> DnsPoolStats {
        DnsPoolStats {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            successful_queries: self.successful_queries.load(Ordering::Relaxed),
            failed_queries: self.failed_queries.load(Ordering::Relaxed),
            avg_response_time_ms: self.avg_response_time_ms.load(Ordering::Relaxed),
            cache_hits: 0,
            cache_misses: 0,
            pool_utilization_percent: ((active_queries * 100) / pool_size.max(1)).min(100) as f32,
        }
    }
}

/// Thread-safe DNS resolver pool with advanced features.
///
/// Hot-path operations (get_resolver, update_resolver_health) are fully lock-free,
/// using AtomicBool health flags, AtomicU32 failure counters, and AtomicU64 stats.
pub struct DnsResolverPool {
    /// Pool of DNS resolver instances
    resolvers: Vec<Arc<TokioAsyncResolver>>,
    /// Round-robin index for load distribution
    index: AtomicUsize,
    /// Configuration settings
    config: DnsConfig,
    /// Lock-free performance statistics (hot path)
    atomic_stats: Arc<AtomicDnsStats>,
    /// Per-resolver healthy flag — lock-free, used in hot-path selection.
    health_flags: Vec<AtomicBool>,
    /// Per-resolver consecutive failure counter — lock-free.
    failure_counts: Vec<AtomicU32>,
    /// Number of queries currently in-flight.
    active_queries: AtomicUsize,
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
        let mut health_flags = Vec::with_capacity(config.pool_size);
        let mut failure_counts = Vec::with_capacity(config.pool_size);

        // Create resolver instances for the pool
        for _ in 0..config.pool_size {
            let resolver = Self::create_resolver(&config)?;
            resolvers.push(Arc::new(resolver));
            health_flags.push(AtomicBool::new(true)); // All start healthy
            failure_counts.push(AtomicU32::new(0));
        }

        Ok(Self {
            resolvers,
            index: AtomicUsize::new(0),
            config,
            atomic_stats: Arc::new(AtomicDnsStats::new()),
            health_flags,
            failure_counts,
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

    /// Update resolver health status based on query results.
    ///
    /// **Fully lock-free** — uses atomic counters and flags only.
    /// Previously this method acquired two Mutex locks on every DNS query,
    /// causing contention under load.
    ///
    /// # Arguments
    /// * `resolver_index` - Index of the resolver that was used
    /// * `success` - Whether the query was successful
    /// * `response_time` - How long the query took (optional)
    pub fn update_resolver_health(&self, resolver_index: usize, success: bool, response_time: Option<Duration>) {
        if resolver_index >= self.resolvers.len() {
            return;
        }

        if success {
            // Reset failure counter
            self.failure_counts[resolver_index].store(0, Ordering::Relaxed);
            self.health_flags[resolver_index].store(true, Ordering::Relaxed);

            self.atomic_stats.successful_queries.fetch_add(1, Ordering::Relaxed);

            if let Some(rt) = response_time {
                let rt_ms = rt.as_millis() as u64;
                // Approximate exponential moving average without locks.
                // load + store is not perfectly atomic but acceptable for stats.
                let prev = self.atomic_stats.avg_response_time_ms.load(Ordering::Relaxed);
                let new_avg = if prev == 0 { rt_ms } else { (prev + rt_ms) / 2 };
                self.atomic_stats.avg_response_time_ms.store(new_avg, Ordering::Relaxed);
            }
        } else {
            let failures = self.failure_counts[resolver_index].fetch_add(1, Ordering::Relaxed) + 1;
            self.atomic_stats.failed_queries.fetch_add(1, Ordering::Relaxed);

            // Mark as unhealthy after 3 consecutive failures
            if failures >= 3 {
                self.health_flags[resolver_index].store(false, Ordering::Relaxed);
            }
        }

        self.atomic_stats.total_queries.fetch_add(1, Ordering::Relaxed);
        self.active_queries.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get comprehensive statistics about the DNS pool (cold path)
    pub fn stats(&self) -> DnsPoolStats {
        let active = self.active_queries.load(Ordering::Relaxed);
        self.atomic_stats.snapshot(active, self.resolvers.len())
    }

    /// Get the current configuration
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Get the number of resolvers in the pool
    pub fn pool_size(&self) -> usize {
        self.resolvers.len()
    }

    /// Check if the pool has any healthy resolvers (lock-free)
    pub fn has_healthy_resolvers(&self) -> bool {
        self.health_flags.iter().any(|f| f.load(Ordering::Relaxed))
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

        assert!((stats.success_rate() - 80.0).abs() < 0.01);
        assert!((stats.cache_hit_rate() - 60.0).abs() < 0.01);
    }
}