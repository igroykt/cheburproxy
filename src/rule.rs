use crate::router::{Proxy, Router, Rule};
use anyhow::anyhow;
use dashmap::DashMap;
use log::{debug, info, warn};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::Instant as TokioInstant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt};
use tokio_rustls::{TlsConnector, rustls::ClientConfig};
use crate::client_context::get_top_level_domain;
use crate::transparent::connect_tcp_with_mark;
// Структура для игнорирования валидности сертификатов
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

use geosite_rs::{decode_geosite, decode_geoip};
use geosite_rs::GeoSiteList;
use geosite_rs::GeoIpList;
use hickory_resolver::{config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol}, TokioAsyncResolver};

// Constants for better maintainability
const CACHE_DURATION_SECONDS: u64 = 600;
const DEFAULT_GEOIP_PATH: &str = "geoip.dat";
const DEFAULT_GEOSITE_PATH: &str = "geosite.dat";
const MAX_DEBUG_PATTERN_SAMPLES: usize = 5;
const AVAILABILITY_MAX_PARALLEL: usize = 2048;
const AVAILABILITY_FAILURE_SHORT_TTL_SECS: u64 = 15;
const AVAILABILITY_SERVER_ERROR_TTL_SECS: u64 = 60;

// Default availability check timeouts (milliseconds)
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 800;
const DEFAULT_TLS_TIMEOUT_MS: u64 = 1200;
const DEFAULT_TTFB_TIMEOUT_MS: u64 = 1200;
const DEFAULT_READ_TIMEOUT_MS: u64 = 800;
const DEFAULT_OVERALL_BUDGET_MS: u64 = 3000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 5000;
const DEFAULT_MAX_REDIRECTS: u8 = 2;
const DEFAULT_MIN_BYTES: usize = 512;
const DEFAULT_MAX_BYTES: usize = 16384;


/// Custom error types for better error handling and debugging
#[derive(Debug)]
pub enum RuleEngineError {
    InvalidDomain(String),
    InvalidIpAddress(String),
    GeoIpLoadError(String),
    GeoSiteLoadError(String),
    RegexCompilationError(String),
    MissingConfiguration(String),
}

impl fmt::Display for RuleEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleEngineError::InvalidDomain(msg) => write!(f, "Invalid domain: {}", msg),
            RuleEngineError::InvalidIpAddress(msg) => write!(f, "Invalid IP address: {}", msg),
            RuleEngineError::GeoIpLoadError(msg) => write!(f, "Failed to load GeoIP data: {}", msg),
            RuleEngineError::GeoSiteLoadError(msg) => write!(f, "Failed to load GeoSite data: {}", msg),
            RuleEngineError::RegexCompilationError(msg) => write!(f, "Failed to compile regex: {}", msg),
            RuleEngineError::MissingConfiguration(msg) => write!(f, "Missing configuration: {}", msg),
        }
    }
}

impl std::error::Error for RuleEngineError {}

/// Configuration for availability check V2 with granular timeouts
#[derive(Debug, Clone)]
pub struct AvailabilityCheckConfig {
    /// TCP connection timeout
    pub connect_timeout: Duration,
    /// TLS handshake timeout (HTTPS only)
    pub tls_timeout: Duration,
    /// Time to first byte timeout
    pub ttfb_timeout: Duration,
    /// Time to read min_bytes of body
    pub read_timeout: Duration,
    /// Hard deadline for entire operation
    pub overall_budget: Duration,
    /// Maximum redirects to follow
    pub max_redirects: u8,
    /// Minimum body bytes to confirm availability
    pub min_bytes: usize,
    /// Maximum bytes to read (memory protection)
    pub max_bytes: usize,
    /// Status codes that mean blocked/unavailable (401, 403, 429, 451)
    pub blocked_status_codes: Vec<u16>,
    /// Status codes that mean server error (5xx)
    pub server_error_codes: Vec<u16>,
}

impl Default for AvailabilityCheckConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            tls_timeout: Duration::from_millis(DEFAULT_TLS_TIMEOUT_MS),
            ttfb_timeout: Duration::from_millis(DEFAULT_TTFB_TIMEOUT_MS),
            read_timeout: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
            overall_budget: Duration::from_millis(DEFAULT_OVERALL_BUDGET_MS),
            max_redirects: DEFAULT_MAX_REDIRECTS,
            min_bytes: DEFAULT_MIN_BYTES,
            max_bytes: DEFAULT_MAX_BYTES,
            blocked_status_codes: vec![401, 403, 429, 451],
            server_error_codes: vec![500, 501, 502, 503, 504, 520, 521, 522, 523, 524],
        }
    }
}

impl AvailabilityCheckConfig {
    /// Create config from legacy single timeout (backward compatibility)
    pub fn from_legacy_timeout(overall_timeout: Duration) -> Self {
        let total_ms = overall_timeout.as_millis() as u64;
        Self {
            connect_timeout: Duration::from_millis(total_ms * 25 / 100),   // 25%
            tls_timeout: Duration::from_millis(total_ms * 35 / 100),      // 35%
            ttfb_timeout: Duration::from_millis(total_ms * 30 / 100),     // 30%
            read_timeout: Duration::from_millis(total_ms * 25 / 100),     // 25%
            overall_budget: overall_timeout,
            ..Default::default()
        }
    }
}

/// Configuration for RuleEngine to make it more flexible
#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    pub geoip_path: String,
    pub geosite_path: String,
    pub cache_duration_seconds: u64,
    pub enable_detailed_logging: bool,
    pub availability_check: bool,
    pub availability_check_timeout: Duration,  // Legacy, kept for backward compatibility
    pub availability_config: AvailabilityCheckConfig,  // New V2 config
    pub dns_cache_ttl: u64,
    pub availability_cache_ttl: u64,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            geoip_path: DEFAULT_GEOIP_PATH.to_string(),
            geosite_path: DEFAULT_GEOSITE_PATH.to_string(),
            cache_duration_seconds: CACHE_DURATION_SECONDS,
            enable_detailed_logging: true,
            availability_check: true,
            availability_check_timeout: Duration::from_secs(5),
            availability_config: AvailabilityCheckConfig::default(),
            dns_cache_ttl: 3600,
            availability_cache_ttl: 300,
        }
    }
}

/// Optimized GeoSite data with HashSet for fast O(1) lookups
/// and regex only for patterns that require it
#[derive(Clone, Debug)]
pub struct OptimizedGeoSite {
    /// Exact domain matches (e.g., "example.com") - O(1) lookup
    pub exact_domains: HashSet<String>,
    /// Domain suffix matches (e.g., ".example.com" matches "sub.example.com") - O(n) but smaller n
    pub suffix_domains: Vec<String>,
    /// Regex patterns for complex patterns - only used when necessary
    pub regex_patterns: Vec<Regex>,
}

impl OptimizedGeoSite {
    pub fn new() -> Self {
        Self {
            exact_domains: HashSet::new(),
            suffix_domains: Vec::new(),
            regex_patterns: Vec::new(),
        }
    }

    /// Check if domain matches any pattern in this category
    #[inline]
    pub fn matches(&self, domain: &str) -> bool {
        // First check exact match - O(1)
        if self.exact_domains.contains(domain) {
            return true;
        }

        // Then check suffix matches - O(n) but usually small n
        for suffix in &self.suffix_domains {
            if domain.ends_with(suffix) {
                return true;
            }
            // Also check if domain equals suffix without leading dot
            if suffix.starts_with('.') && domain == &suffix[1..] {
                return true;
            }
        }

        // Finally check regex patterns - slowest, but rarely needed
        for pattern in &self.regex_patterns {
            if pattern.is_match(domain) {
                return true;
            }
        }

        false
    }
}

/// High-performance rule engine for proxy routing decisions.
/// Handles domain/IP matching with support for geosite and geoip databases.
#[derive(Clone)]
pub struct RuleEngine {
    /// Processed routing rules with optimized matching patterns
    rules: Arc<Vec<ProcessedRule>>,
    /// GeoIP database mapping country codes to CIDR blocks
    geoip_countries: Arc<HashMap<String, Vec<CidrBlock>>>,
    /// GeoSite database mapping categories to optimized lookup structures
    geosite_categories: Arc<HashMap<String, OptimizedGeoSite>>,
    /// Available proxy configurations keyed by tag
    proxies: Arc<HashMap<String, Proxy>>,
    /// Cache for routing decisions to improve performance
    cache: Arc<DashMap<String, (RoutingDecision, Instant)>>,
    /// DNS resolver for SNI domain resolution
    resolver: Arc<TokioAsyncResolver>,
    /// Cache for DNS resolutions
    dns_cache: Arc<DashMap<String, (IpAddr, Instant)>>,
    /// Cache for availability checks
    availability_cache: Arc<DashMap<String, (bool, Instant, u64)>>,
    /// Limit concurrent availability checks (DoS safety)
    availability_sem: Arc<Semaphore>,
    /// Deduplicate in-flight checks (singleflight)
    availability_inflight: Arc<DashMap<String, Vec<oneshot::Sender<bool>>>>,
    /// Configuration settings
    config: RuleEngineConfig,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AvailabilityResult {
    Available,
    Unavailable,
    Blocked,           // 401, 403, 429, 451
    ServerError,       // 5xx
    InsufficientData,  // Got < min_bytes before timeout
    Timeout,
    DnsFail,
    TooManyRedirects,
}

impl AvailabilityResult {
    /// Convert result to boolean for cache
    fn is_available(&self) -> bool {
        matches!(self, AvailabilityResult::Available)
    }
    
    /// Get appropriate cache TTL for this result type
    fn cache_ttl(&self, config: &RuleEngineConfig) -> u64 {
        match self {
            AvailabilityResult::Available => config.availability_cache_ttl,
            AvailabilityResult::Blocked => config.availability_cache_ttl,
            AvailabilityResult::TooManyRedirects => config.availability_cache_ttl,
            AvailabilityResult::ServerError => AVAILABILITY_SERVER_ERROR_TTL_SECS,
            AvailabilityResult::DnsFail => 30, // DNS can recover quickly
            _ => AVAILABILITY_FAILURE_SHORT_TTL_SECS, // Timeout, Unavailable, InsufficientData
        }
    }
}

/// Internal result type for single HTTP check attempt
#[derive(Debug)]
enum HttpCheckResult {
    Available,
    Unavailable,
    Blocked,
    ServerError,
    InsufficientData,
    Timeout,
    DnsFail,
    TlsFailed,
    Redirect(String),
}

/// CIDR block representation for both IPv4 and IPv6
#[derive(Clone, Debug)]
pub enum CidrBlock {
    /// IPv4 CIDR: base IP as u32, prefix length
    V4(u32, u8),
    /// IPv6 CIDR: base IP as u128, prefix length
    V6(u128, u8),
}

/// Internal representation of a processed rule with optimized matching
#[derive(Clone, Debug)]
struct ProcessedRule {
    /// Rule identifier tag
    pub tag: String,
    /// Plain domain patterns (exact/suffix matches)
    pub domain_patterns: Vec<DomainPattern>,
    /// Geosite categories for this rule
    pub geosite_categories: Option<Vec<String>>,
    /// GeoIP country codes for this rule
    pub geoip_countries: Option<Vec<String>>,
}

/// Optimized domain pattern for fast matching
#[derive(Clone, Debug)]
enum DomainPattern {
    /// Suffix match (e.g., ".example.com")
    //Suffix(String),
    DomainAndSubs(String),
}

/*impl DomainPattern {
    /// Check if the pattern matches the given domain
    fn matches(&self, domain: &str) -> bool {
        match self {
            DomainPattern::Exact(pattern) => pattern.eq_ignore_ascii_case(domain),
            DomainPattern::Suffix(pattern) => {
                domain.len() >= pattern.len() &&
                domain[domain.len() - pattern.len()..].eq_ignore_ascii_case(pattern)
            }
        }
    }
}*/

impl DomainPattern {
    fn normalize(s: &str) -> String {
        let s = s.trim_end_matches('.');
        s.to_ascii_lowercase()
    }

    #[inline]
    fn ends_with_domain_boundary(domain: &str, pat: &str) -> bool {
        if domain.eq_ignore_ascii_case(pat) {
            return true;
        }
        if domain.len() <= pat.len() {
            return false;
        }
        // Проверяем, что domain заканчивается на pat и перед ним стоит '.'
        // Без аллокаций.
        let dbytes = domain.as_bytes();
        let pbytes = pat.as_bytes();
        let start = domain.len() - pat.len();

        // Сначала быстрая проверка суффикса
        if &dbytes[start..] != pbytes {
            return false;
        }
        // Теперь граница поддомена
        dbytes.get(start - 1) == Some(&b'.')
    }

    /// Check if the pattern matches the given domain
    fn matches(&self, domain: &str) -> bool {
        // Нормализуем входной домен один раз
        let domain = Self::normalize(domain);
        match self {
            DomainPattern::DomainAndSubs(p) => Self::ends_with_domain_boundary(&domain, p),
        }
    }
}

impl From<&str> for DomainPattern {
    /// Пример парсинга правил:
    /// - ".apple.com" можно трактовать как ровно поддомены (исключая сам apple.com), если нужно
    /// - "apple.com" → DomainAndSubs("apple.com")
    fn from(s: &str) -> Self {
        let s = DomainPattern::normalize(s);
        // Если хотите особую семантику для лидирующей точки — раскомментируйте и расширьте.
        // if s.starts_with('.') {
        //     return DomainPattern::SubdomainsOnly(s.trim_start_matches('.').to_string());
        // }
        DomainPattern::DomainAndSubs(s)
    }
}

#[derive(Clone, Debug)]
pub enum RoutingDecision {
    Direct,
    Proxy(Proxy),
}

impl RuleEngine {
    /// Create a new RuleEngine from configuration with default settings
    pub fn from_config(cfg: Router) -> anyhow::Result<Self> {
        Self::from_config_with_options(cfg, RuleEngineConfig::default())
    }

    /// Create a new RuleEngine with custom configuration
    pub fn from_config_with_options(cfg: Router, config: RuleEngineConfig) -> anyhow::Result<Self> {
        let proxies = Self::load_proxies(&cfg.upstream_proxy, &config)?;
        let geoip_countries = Self::load_geoip_data(&config)?;
        let geosite_categories = Self::load_geosite_data(&config)?;
        let rules = Self::process_rules(cfg.rules, &config)?;

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(NameServerConfig::new("8.8.8.8:53".parse().unwrap(), Protocol::Udp));
        let resolver_opts = ResolverOpts::default();
        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

        Ok(RuleEngine {
            rules: Arc::new(rules),
            geoip_countries,
            geosite_categories,
            proxies: Arc::new(proxies),
            cache: Arc::new(DashMap::new()),
            resolver: Arc::new(resolver),
            dns_cache: Arc::new(DashMap::new()),
            availability_cache: Arc::new(DashMap::new()),
            availability_sem: Arc::new(Semaphore::new(AVAILABILITY_MAX_PARALLEL)),
            availability_inflight: Arc::new(DashMap::new()),
            config,
        })
    }

    /// Create a new RuleEngine reusing existing GeoIP/GeoSite databases (for hot-reload)
    /// This prevents memory duplication when reloading configuration
    pub fn from_config_with_shared_geodata(
        cfg: Router,
        config: RuleEngineConfig,
        geoip_countries: Arc<HashMap<String, Vec<CidrBlock>>>,
        geosite_categories: Arc<HashMap<String, OptimizedGeoSite>>,
        resolver: Arc<TokioAsyncResolver>,
    ) -> anyhow::Result<Self> {
        let proxies = Self::load_proxies(&cfg.upstream_proxy, &config)?;
        let rules = Self::process_rules(cfg.rules, &config)?;

        info!("Creating RuleEngine with shared GeoIP/GeoSite databases (memory-efficient reload)");

        Ok(RuleEngine {
            rules: Arc::new(rules),
            geoip_countries, // Reuse existing Arc - no memory duplication
            geosite_categories, // Reuse existing Arc - no memory duplication
            proxies: Arc::new(proxies),
            cache: Arc::new(DashMap::new()),
            resolver, // Reuse existing Arc resolver
            dns_cache: Arc::new(DashMap::new()),
            availability_cache: Arc::new(DashMap::new()),
            availability_sem: Arc::new(Semaphore::new(AVAILABILITY_MAX_PARALLEL)),
            availability_inflight: Arc::new(DashMap::new()),
            config,
        })
    }

    /// Extract static GeoIP/GeoSite data for reuse during hot-reloads
    /// Returns Arc clones (cheap - only increments reference count)
    pub fn extract_static_geodata(&self) -> (
        Arc<HashMap<String, Vec<CidrBlock>>>,
        Arc<HashMap<String, OptimizedGeoSite>>,
        Arc<TokioAsyncResolver>,
    ) {
        (
            self.geoip_countries.clone(),
            self.geosite_categories.clone(),
            self.resolver.clone(),
        )
    }

    /// Load and validate proxy configurations
    fn load_proxies(upstream_proxies: &HashMap<String, Proxy>, config: &RuleEngineConfig) -> anyhow::Result<HashMap<String, Proxy>> {
        let mut tag_to_proxy = HashMap::new();

        for (name, proxy) in upstream_proxies {
            if proxy.tag.is_empty() {
                return Err(anyhow!(RuleEngineError::MissingConfiguration(
                    format!("Proxy '{}' has empty tag", name)
                )));
            }

            if config.enable_detailed_logging {
                info!("Loading upstream proxy '{}' with tag '{}': {}:{}",
                     name, proxy.tag, proxy.server_addr, proxy.server_port);
            }

            tag_to_proxy.insert(proxy.tag.clone(), proxy.clone());
        }

        info!("Loaded {} upstream proxies with tags: {:?}",
              tag_to_proxy.len(), tag_to_proxy.keys().collect::<Vec<_>>());

        Ok(tag_to_proxy)
    }

    /// Load GeoIP data with error handling
    fn load_geoip_data(config: &RuleEngineConfig) -> anyhow::Result<Arc<HashMap<String, Vec<CidrBlock>>>> {
        match load_geoip(&config.geoip_path) {
            Ok(data) => {
                info!("Loaded {} GeoIP countries from {}", data.len(), config.geoip_path);
                Ok(Arc::new(data))
            },
            Err(e) => {
                debug!("Failed to load GeoIP data from {}: {}", config.geoip_path, e);
                Ok(Arc::new(HashMap::new()))
            }
        }
    }

    /// Load GeoSite data with error handling
    fn load_geosite_data(config: &RuleEngineConfig) -> anyhow::Result<Arc<HashMap<String, OptimizedGeoSite>>> {
        match load_geosite_optimized(&config.geosite_path) {
            Ok(data) => {
                if data.is_empty() {
                    debug!("GeoSite data loaded but empty - parser may not support format");
                } else if config.enable_detailed_logging {
                    debug!("Loaded {} geosite categories: {:?}",
                          data.len(), data.keys().collect::<Vec<_>>());
                }
                Ok(Arc::new(data))
            },
            Err(e) => {
                debug!("Failed to load GeoSite data from {}: {}", config.geosite_path, e);
                Ok(Arc::new(HashMap::new()))
            }
        }
    }

    /// Process and optimize rules for efficient matching
    fn process_rules(raw_rules: Vec<Rule>, config: &RuleEngineConfig) -> anyhow::Result<Vec<ProcessedRule>> {
        let mut processed_rules = Vec::new();

        for rule in raw_rules {
            let processed_rule = Self::process_single_rule(rule, config)?;
            processed_rules.push(processed_rule);
        }

        info!("Loaded and processed {} rules", processed_rules.len());
        Ok(processed_rules)
    }

    /// Process a single rule into optimized format
    fn process_single_rule(rule: Rule, config: &RuleEngineConfig) -> anyhow::Result<ProcessedRule> {
        let mut domain_patterns = Vec::new();
        let mut geosite_categories = Vec::new();
        let mut geoip_countries = Vec::new();

        // Parse domain patterns
        for domain in &rule.domains {
            match Self::parse_domain_pattern(domain) {
                Ok(pattern) => domain_patterns.push(pattern),
                Err(e) => {
                    debug!("Skipping invalid domain pattern '{}': {}", domain, e);
                    continue;
                }
            }
        }

        // Extract geosite categories from domains
        for domain in &rule.domains {
            if let Some(cat) = domain.strip_prefix("geosite:") {
                if !cat.is_empty() {
                    geosite_categories.push(cat.to_string());
                }
            }
        }

        // Extract geoip countries from domains
        for domain in &rule.domains {
            if let Some(code) = domain.strip_prefix("geoip:") {
                if !code.is_empty() {
                    geoip_countries.push(code.to_string());
                }
            }
        }

        // Merge with existing geosite/geoip if present
        let final_geosite = Self::merge_geosite_categories(&rule.geosite, &geosite_categories);
        let final_geoip = Self::merge_geoip_countries(&rule.geoip, &geoip_countries);

        if config.enable_detailed_logging {
            debug!("Processed rule tag '{}': {} domain patterns, geosite categories: {:?}, geoip countries: {:?}",
                   rule.tag, domain_patterns.len(), final_geosite, final_geoip);
        }

        Ok(ProcessedRule {
            tag: rule.tag,
            domain_patterns,
            geosite_categories: final_geosite,
            geoip_countries: final_geoip,
        })
    }

    /// Parse a domain pattern into optimized format
    fn parse_domain_pattern(domain: &str) -> anyhow::Result<DomainPattern> {
        if domain.is_empty() {
            return Err(anyhow!(RuleEngineError::InvalidDomain(
                "Empty domain pattern".to_string()
            )));
        }

        /*if domain.starts_with('.') {
            Ok(DomainPattern::Suffix(domain.to_lowercase()))
        } else {
            Ok(DomainPattern::Exact(domain.to_lowercase()))
        }*/
        Ok(DomainPattern::DomainAndSubs(domain.to_lowercase()))
    }

    /// Merge geosite categories from JSON config and domain patterns
    fn merge_geosite_categories(
        existing: &Option<Vec<String>>,
        extracted: &[String]
    ) -> Option<Vec<String>> {
        match existing {
            Some(existing_cats) => {
                let mut merged = existing_cats.clone();
                merged.extend(extracted.iter().cloned());
                Some(merged)
            },
            None if extracted.is_empty() => None,
            None => Some(extracted.to_vec()),
        }
    }

    /// Merge geoip countries from JSON config and domain patterns
    fn merge_geoip_countries(
        existing: &Option<Vec<String>>,
        extracted: &[String]
    ) -> Option<Vec<String>> {
        match existing {
            Some(existing_codes) => {
                let mut merged = existing_codes.clone();
                merged.extend(extracted.iter().cloned());
                Some(merged)
            },
            None if extracted.is_empty() => None,
            None => Some(extracted.to_vec()),
        }
    }

    /// Get routing decision for a domain with caching and optimized matching
    pub fn get_routing_decision(&self, domain: &str) -> Option<RoutingDecision> {
        // Input validation
        if domain.is_empty() {
            return None;
        }

        let domain_lower = domain.to_lowercase();

        // Check cache first
        if let Some(cached) = self.cache.get(&domain_lower) {
            if cached.1.elapsed() < Duration::from_secs(self.config.cache_duration_seconds) {
                if self.config.enable_detailed_logging {
                    debug!("Routing cache hit for domain '{}': {:?}", domain, cached.0);
                }
                return Some(cached.0.clone());
            }
        }

        let decision = if let Ok(ip) = domain.parse::<IpAddr>() {
            self.get_ip_routing_decision(ip)
        } else {
            self.get_domain_routing_decision(&domain_lower)
        };

        // Cache the result
        if let Some(dec) = &decision {
            self.cache.insert(domain_lower, (dec.clone(), Instant::now()));
            if self.config.enable_detailed_logging {
                debug!("Final decision from rules for '{}': {:?}", domain, dec);
            }
        } else if self.config.enable_detailed_logging {
            debug!("No match found for '{}', will use default", domain);
        }

        decision
    }

    /// Get routing decision for IP addresses
    fn get_ip_routing_decision(&self, ip: IpAddr) -> Option<RoutingDecision> {
        for rule in self.rules.iter() {
            if let Some(ref country_codes) = &rule.geoip_countries {
                for code in country_codes {
                    if self.ip_matches_country(ip, code) {
                        if self.config.enable_detailed_logging {
                            debug!("GeoIP match for IP '{}' (country: {}) in rule tag '{}'",
                                  ip, code, rule.tag);
                        }
                        return Some(self.tag_to_decision(&rule.tag));
                    }
                }
            }
        }
        None
    }

    /// Get routing decision for domain names
    /// Priority: explicit domain patterns > geosite categories
    /// This ensures that explicitly listed domains always take precedence
    /// over broader geosite category matches, regardless of rule order.
    fn get_domain_routing_decision(&self, domain: &str) -> Option<RoutingDecision> {
        // Pass 1: Check ALL rules for explicit domain pattern match
        // Explicit domains have highest priority regardless of rule order
        for rule in self.rules.iter() {
            if self.domain_matches(&rule.domain_patterns, domain) {
                if self.config.enable_detailed_logging {
                    debug!("Explicit domain match for '{}' in rule tag '{}'", domain, rule.tag);
                }
                return Some(self.tag_to_decision(&rule.tag));
            }
        }

        // Pass 2: Check ALL rules for geosite category match
        // Geosite matches have lower priority than explicit domains
        for rule in self.rules.iter() {
            if let Some(ref categories) = &rule.geosite_categories {
                if self.geosite_matches(categories, domain) {
                    if self.config.enable_detailed_logging {
                        debug!("Geosite category match for '{}' in rule tag '{}'", domain, rule.tag);
                    }
                    return Some(self.tag_to_decision(&rule.tag));
                }
            }
        }

        None
    }

    /// Fast domain pattern matching
    fn domain_matches(&self, patterns: &[DomainPattern], domain: &str) -> bool {
        patterns.iter().any(|pattern| pattern.matches(domain))
    }

    /// Geosite category matching - optimized with HashSet + suffix matching
    fn geosite_matches(&self, categories: &[String], domain: &str) -> bool {
        let geosite_map = self.geosite_categories.as_ref();

        for category in categories {
            if let Some(optimized) = geosite_map.get(&category.to_lowercase()) {
                if optimized.matches(domain) {
                    if self.config.enable_detailed_logging {
                        debug!("Geosite match for '{}' in category '{}'", domain, category);
                    }
                    return true;
                }
            } else if self.config.enable_detailed_logging {
                debug!("Geosite category '{}' not found in loaded categories", category);
            }
        }
        false
    }

    /// Check if an IP address matches a country code using CIDR blocks
    fn ip_matches_country(&self, ip: IpAddr, country_code: &str) -> bool {
        if let Some(cidrs) = self.geoip_countries.get(&country_code.to_lowercase()) {
            if cidrs.is_empty() && self.config.enable_detailed_logging {
                debug!("No CIDRs loaded for country {}", country_code);
            }

            match ip {
                IpAddr::V4(ipv4) => {
                    let ip_num = u32::from_be_bytes(ipv4.octets());
                    for cidr in cidrs {
                        if let CidrBlock::V4(base_ip, prefix) = cidr {
                            let mask = if *prefix == 0 { 0u32 } else { !((1u32 << (32 - *prefix as u32)) - 1) };
                            if (ip_num & mask) == (*base_ip & mask) {
                                if self.config.enable_detailed_logging {
                                    debug!("IP {} matches country {} CIDR {}/{}",
                                          ipv4, country_code, IpAddr::V4(Ipv4Addr::from(*base_ip)), prefix);
                                }
                                return true;
                            }
                        }
                    }
                }
                IpAddr::V6(ipv6) => {
                    let ip_num = u128::from_be_bytes(ipv6.octets());
                    for cidr in cidrs {
                        if let CidrBlock::V6(base_ip, prefix) = cidr {
                            let mask = if *prefix == 0 { 0u128 } else { !((1u128 << (128 - *prefix as u32)) - 1) };
                            if (ip_num & mask) == (*base_ip & mask) {
                                if self.config.enable_detailed_logging {
                                    debug!("IP {} matches country {} CIDR {}/{}",
                                          ipv6, country_code, IpAddr::V6(Ipv6Addr::from(*base_ip)), prefix);
                                }
                                return true;
                            }
                        }
                    }
                }
            }
        } else if self.config.enable_detailed_logging {
            debug!("No country entry found for code {} in geoip", country_code);
        }

        false
    }

    /// Convert a rule tag to a routing decision
    fn tag_to_decision(&self, tag: &str) -> RoutingDecision {
        if tag.eq_ignore_ascii_case("direct") {
            if self.config.enable_detailed_logging {
                debug!("Tag '{}' resolved to Direct", tag);
            }
            RoutingDecision::Direct
        } else if let Some(proxy) = self.proxies.get(tag) {
            if self.config.enable_detailed_logging {
                debug!("Tag '{}' resolved to Proxy {}:{} (tag: {})",
                     tag, proxy.server_addr, proxy.server_port, proxy.tag);
            }
            RoutingDecision::Proxy(proxy.clone())
        } else {
            warn!("Unknown proxy tag '{}', falling back to Direct routing", tag);
            RoutingDecision::Direct
        }
    }

    /// Get proxy configuration by tag
    pub fn get_proxy_by_tag(&self, tag: &str) -> Option<&Proxy> {
        self.proxies.get(tag)
    }

    /// Get all top-level domains from rules
    pub fn get_top_level_domains(&self) -> Vec<String> {
        self.rules.iter()
            .flat_map(|rule| {
                rule.domain_patterns.iter().filter_map(|pattern| {
                    match pattern {
                        DomainPattern::DomainAndSubs(domain) => Some(get_top_level_domain(domain)),
                    }
                })
            })
            .collect::<HashSet<_>>()  // Убрать дубликаты
            .into_iter()
            .collect()
    }

    /// Get cache statistics for monitoring
    pub fn get_cache_stats(&self) -> (usize, usize, usize, usize) {
        (self.cache.len(), self.dns_cache.len(), self.availability_cache.len(), self.availability_inflight.len())
    }

    /// Clear the routing cache
    pub fn clear_cache(&self) {
        self.cache.clear();
        debug!("Routing cache cleared");
    }

    /// Clear expired entries from DNS cache
    pub fn clear_dns_cache(&self) {
        let ttl = Duration::from_secs(self.config.dns_cache_ttl);
        let now = Instant::now();
        self.dns_cache.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < ttl);
        debug!("DNS cache cleaned up");
    }

    /// Clear expired entries from availability cache
    pub fn clear_availability_cache(&self) {
        let now = Instant::now();
        self.availability_cache.retain(|_, (_, timestamp, ttl)| now.duration_since(*timestamp) < Duration::from_secs(*ttl));
        debug!("Availability cache cleaned up");
    }

    /// Get configuration information
    pub fn get_config(&self) -> &RuleEngineConfig {
        &self.config
    }

    /// Async version of get_routing_decision for compatibility
    pub async fn get_routing_decision_async(&self, domain: &str) -> Option<RoutingDecision> {
        self.get_routing_decision(domain)
    }

    /// Resolve domain to IP with caching
    async fn resolve_domain(&self, domain: &str) -> Option<IpAddr> {
        if let Some(cached) = self.dns_cache.get(domain) {
            if cached.1.elapsed() < Duration::from_secs(self.config.dns_cache_ttl) {
                return Some(cached.0);
            }
        }

        match tokio::time::timeout(
            Duration::from_millis(DEFAULT_DNS_TIMEOUT_MS),
            self.resolver.lookup_ip(domain)
        ).await {
            Ok(Ok(response)) => {
                if let Some(ip) = response.iter().next() {
                    self.dns_cache.insert(domain.to_string(), (ip, Instant::now()));
                    Some(ip)
                } else {
                    None
                }
            }
            Ok(Err(_)) => None, // Resolver error
            Err(_) => {
                debug!("DNS lookup for '{}' timed out after {}ms", domain, DEFAULT_DNS_TIMEOUT_MS);
                None
            }
        }
    }

    /// Check domain availability by attempting TLS handshake to specified port
    /// Uses: domain:port cache key, singleflight, bounded concurrency, overall deadline.
    async fn check_availability(&self, domain: &str, port: u16) -> bool {
        let key = format!("{}:{}", domain, port);

        if let Some(cached) = self.availability_cache.get(&key) {
            let ttl = cached.2;
            if cached.1.elapsed() < Duration::from_secs(ttl) {
                return cached.0;
            }
        }

        // P3 FIX: Use DashMap entry API for atomic check-and-insert (eliminates TOCTOU race)
        let (tx, rx) = oneshot::channel::<bool>();
        {
            use dashmap::mapref::entry::Entry;
            match self.availability_inflight.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(tx);
                    drop(entry);
                    return rx.await.unwrap_or(false);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![tx]);
                }
            }
        }

        // P1-4 FIX: Use a Drop guard to ensure the inflight map entry is always cleaned up,
        // even if this future is cancelled (e.g., connection dropped mid-check).
        // Previously, cancelled futures left orphan entries that leaked permanently.
        struct InFlightCleanup<'a> {
            map: &'a DashMap<String, Vec<oneshot::Sender<bool>>>,
            key: String,
            completed: bool,
        }
        impl<'a> Drop for InFlightCleanup<'a> {
            fn drop(&mut self) {
                if !self.completed {
                    // Future was cancelled — clean up the entry and notify waiters with false
                    if let Some((_, waiters)) = self.map.remove(&self.key) {
                        for w in waiters {
                            let _ = w.send(false);
                        }
                    }
                    debug!("Availability check for '{}' was cancelled, inflight entry cleaned up", self.key);
                }
            }
        }
        let mut guard = InFlightCleanup {
            map: &self.availability_inflight,
            key: key.clone(),
            completed: false,
        };

        // overall deadline for the whole operation
        let deadline = TokioInstant::now() + self.config.availability_check_timeout;

        // bounded concurrency (DoS safety)
        let permit = match tokio::time::timeout_at(deadline, self.availability_sem.acquire()).await {
            Ok(Ok(p)) => p,
             _ => {
                guard.completed = true; // prevent double cleanup
                self.finish_availability_inflight(&key, false);
                return false;
             }
        };

        let res = self.perform_http_availability_check(domain, port, deadline).await;
        drop(permit);

        let available = res.is_available();
        let ttl = res.cache_ttl(&self.config);

        self.availability_cache.insert(key.clone(), (available, Instant::now(), ttl));
        guard.completed = true; // prevent guard from cleaning up — we'll do it manually
        self.finish_availability_inflight(&key, available);
        available
    }

    fn finish_availability_inflight(&self, key: &str, value: bool) {
        if let Some((_, waiters)) = self.availability_inflight.remove(key) {
            for w in waiters {
                let _ = w.send(value);
            }
        }
    }

    /// Resolve domain to IP with caching, preferring IPv4 over IPv6
    async fn resolve_domain_prefer_ipv4(&self, domain: &str) -> Option<IpAddr> {
        if let Some(cached) = self.dns_cache.get(domain) {
            if cached.1.elapsed() < Duration::from_secs(self.config.dns_cache_ttl) {
                return Some(cached.0);
            }
        }

        match self.resolver.lookup_ip(domain).await {
            Ok(response) => {
                // Prefer IPv4 over IPv6 for faster and more reliable connections
                let ipv4 = response.iter().find(|ip| ip.is_ipv4());
                let ipv6 = response.iter().find(|ip| ip.is_ipv6());
                
                if let Some(ip) = ipv4.or(ipv6) {
                    self.dns_cache.insert(domain.to_string(), (ip, Instant::now()));
                    Some(ip)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Build HTTP GET request for availability check
    fn build_http_request(domain: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\r\n",
            domain
        )
    }

    /// Parse HTTP status line and return status code
    fn parse_status_line(line: &str) -> Option<u16> {
        // Format: HTTP/1.1 200 OK
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
            parts[1].parse().ok()
        } else {
            None
        }
    }

    /// Parse HTTP headers and return Content-Length and Location if present
    fn parse_headers(headers: &[String]) -> (Option<usize>, Option<String>) {
        let mut content_length = None;
        let mut location = None;
        
        for header in headers {
            let lower = header.to_lowercase();
            if lower.starts_with("content-length:") {
                if let Some(val) = header.splitn(2, ':').nth(1) {
                    content_length = val.trim().parse().ok();
                }
            } else if lower.starts_with("location:") {
                if let Some(val) = header.splitn(2, ':').nth(1) {
                    location = Some(val.trim().to_string());
                }
            }
        }
        
        (content_length, location)
    }

    /// Perform HTTP availability check with granular timeouts
    /// This is the V2 implementation that:
    /// 1. Performs TCP connect with connect_timeout
    /// 2. Optional TLS handshake with tls_timeout
    /// 3. Sends HTTP GET and waits for TTFB with ttfb_timeout
    /// 4. Checks status code for blocks (401, 403, 429, 451, 5xx)
    /// 5. Reads body until min_bytes received with read_timeout
    /// 6. Supports HTTP fallback if HTTPS fails on port 443
    async fn perform_http_availability_check(&self, domain: &str, port: u16, deadline: TokioInstant) -> AvailabilityResult {
        let config = &self.config.availability_config;
        let mut redirects = 0u8;
        let mut current_domain = domain.to_string();
        let mut current_port = port;
        
        loop {
            let result = self.single_http_check_attempt(&current_domain, current_port, deadline, false).await;
            
            match result {
                HttpCheckResult::Available => return AvailabilityResult::Available,
                HttpCheckResult::Redirect(location) if redirects < config.max_redirects => {
                    redirects += 1;
                    // Parse redirect URL
                    if let Some((new_domain, new_port)) = Self::parse_redirect_url(&location, &current_domain, current_port) {
                        debug!("Following redirect {} -> {}:{}", redirects, new_domain, new_port);
                        current_domain = new_domain;
                        current_port = new_port;
                        continue;
                    } else {
                        return AvailabilityResult::TooManyRedirects;
                    }
                }
                HttpCheckResult::Redirect(_) => return AvailabilityResult::TooManyRedirects,
                HttpCheckResult::TlsFailed if port == 443 => {
                    // Try HTTP fallback on port 80
                    debug!("HTTPS failed for {}, trying HTTP fallback on port 80", domain);
                    match self.single_http_check_attempt(domain, 80, deadline, true).await {
                        HttpCheckResult::Available => return AvailabilityResult::Available,
                        HttpCheckResult::Blocked => return AvailabilityResult::Blocked,
                        HttpCheckResult::ServerError => return AvailabilityResult::ServerError,
                        _ => return AvailabilityResult::Unavailable,
                    }
                }
                HttpCheckResult::Blocked => return AvailabilityResult::Blocked,
                HttpCheckResult::ServerError => return AvailabilityResult::ServerError,
                HttpCheckResult::InsufficientData => return AvailabilityResult::InsufficientData,
                HttpCheckResult::Timeout => return AvailabilityResult::Timeout,
                HttpCheckResult::DnsFail => return AvailabilityResult::DnsFail,
                HttpCheckResult::Unavailable | HttpCheckResult::TlsFailed => return AvailabilityResult::Unavailable,
            }
        }
    }

    /// Parse redirect URL and extract domain and port
    fn parse_redirect_url(location: &str, current_domain: &str, current_port: u16) -> Option<(String, u16)> {
        // Handle absolute URLs: http://example.com/path or https://example.com:8080/path
        if location.starts_with("http://") || location.starts_with("https://") {
            let is_https = location.starts_with("https://");
            let url_without_scheme = if is_https {
                &location[8..]
            } else {
                &location[7..]
            };
            
            // Split host and path
            let host_part = url_without_scheme.split('/').next()?;
            
            // Check for port
            if let Some(colon_pos) = host_part.rfind(':') {
                let domain = &host_part[..colon_pos];
                let port: u16 = host_part[colon_pos + 1..].parse().ok()?;
                Some((domain.to_string(), port))
            } else {
                let port = if is_https { 443 } else { 80 };
                Some((host_part.to_string(), port))
            }
        } else if location.starts_with('/') {
            // Relative URL: /path - use current domain
            Some((current_domain.to_string(), current_port))
        } else {
            // Relative URL without leading slash
            Some((current_domain.to_string(), current_port))
        }
    }

    /// Perform a single HTTP check attempt
    async fn single_http_check_attempt(&self, domain: &str, port: u16, deadline: TokioInstant, force_http: bool) -> HttpCheckResult {
        let config = &self.config.availability_config;
        
        // Check deadline
        if TokioInstant::now() >= deadline {
            return HttpCheckResult::Timeout;
        }
        
        // Step 1: DNS resolve with deadline check
        let dns_timeout = std::cmp::min(
            config.connect_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let ip = match tokio::time::timeout(dns_timeout, self.resolve_domain_prefer_ipv4(domain)).await {
            Ok(Some(ip)) => ip,
            Ok(None) => return HttpCheckResult::DnsFail,
            Err(_) => return HttpCheckResult::Timeout,
        };
        
        let addr = SocketAddr::new(ip, port);
    
        // Step 2: TCP connect with connect_timeout and SO_MARK=2 (0x2: proxy-originated traffic, avoids TPROXY re-interception)
        let connect_timeout = std::cmp::min(
            config.connect_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let tcp_stream = match tokio::time::timeout(connect_timeout, connect_tcp_with_mark(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("TCP (marked) connect failed to {}:{}: {}", domain, port, e);
                return HttpCheckResult::Unavailable;
            }
            Err(_) => return HttpCheckResult::Timeout,
        };
        
        // Step 3: TLS handshake if HTTPS (port 443 or not forced HTTP)
        let use_tls = port == 443 && !force_http;
        
        if use_tls {
            let tls_timeout = std::cmp::min(
                config.tls_timeout,
                deadline.saturating_duration_since(TokioInstant::now())
            );
            
            // Create TLS config without certificate validation
            let tls_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            
            let connector = TlsConnector::from(Arc::new(tls_config));
            
            let server_name = match rustls_pki_types::ServerName::try_from(domain.to_string()) {
                Ok(name) => name,
                Err(_) => return HttpCheckResult::TlsFailed,
            };
            
            match tokio::time::timeout(tls_timeout, connector.connect(server_name, tcp_stream)).await {
                Ok(Ok(tls_stream)) => {
                    // TLS succeeded, now do HTTP over TLS
                    return self.perform_http_exchange_tls(tls_stream, domain, deadline).await;
                }
                Ok(Err(e)) => {
                    debug!("TLS handshake failed for {}: {}", domain, e);
                    return HttpCheckResult::TlsFailed;
                }
                Err(_) => return HttpCheckResult::Timeout,
            }
        } else {
            // Plain HTTP
            return self.perform_http_exchange_plain(tcp_stream, domain, deadline).await;
        }
    }

    /// Perform HTTP exchange over TLS stream
    async fn perform_http_exchange_tls<S>(&self, mut stream: tokio_rustls::client::TlsStream<S>, domain: &str, deadline: TokioInstant) -> HttpCheckResult
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let config = &self.config.availability_config;
        let request = Self::build_http_request(domain);
        
        // Send request
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            debug!("Failed to send HTTP request to {}: {}", domain, e);
            return HttpCheckResult::Unavailable;
        }
        
        // TTFB timeout - wait for first bytes
        let ttfb_timeout = std::cmp::min(
            config.ttfb_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let mut buffer = vec![0u8; 4096];
        let mut total_received = 0usize;
        let mut status_code: Option<u16> = None;
        let mut headers = Vec::new();
        let mut body_bytes = 0usize;
        let mut header_buffer = String::new();
        
        // Read first chunk (TTFB)
        let first_read = match tokio::time::timeout(ttfb_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => return HttpCheckResult::Unavailable, // Connection closed
            Ok(Err(e)) => {
                debug!("Read error from {}: {}", domain, e);
                return HttpCheckResult::Unavailable;
            }
            Err(_) => return HttpCheckResult::Timeout,
        };
        
        total_received += first_read;
        header_buffer.push_str(&String::from_utf8_lossy(&buffer[..first_read]));
        
        // Parse status line
        if let Some(status_line_end) = header_buffer.find("\r\n") {
            let status_line = &header_buffer[..status_line_end];
            status_code = Self::parse_status_line(status_line);
        }
        
        // Check for blocking status codes immediately
        if let Some(code) = status_code {
            if config.blocked_status_codes.contains(&code) {
                debug!("Blocked status code {} from {}", code, domain);
                return HttpCheckResult::Blocked;
            }
            if config.server_error_codes.contains(&code) {
                debug!("Server error {} from {}", code, domain);
                return HttpCheckResult::ServerError;
            }
        }
        
        // Find headers end
        if let Some(headers_end) = header_buffer.find("\r\n\r\n") {
            let header_section = &header_buffer[..headers_end];
            headers = header_section.lines().skip(1).map(|s| s.to_string()).collect();
            body_bytes = total_received - (headers_end + 4);
        }
        
        // Parse headers for Content-Length and Location
        let (content_length, location) = Self::parse_headers(&headers);
        
        // Handle redirects (3xx)
        if let Some(code) = status_code {
            if (300..400).contains(&code) {
                if let Some(loc) = location {
                    return HttpCheckResult::Redirect(loc);
                }
            }
        }
        
        // Special case: 2xx with small or zero Content-Length
        if let Some(code) = status_code {
            if (200..300).contains(&code) {
                if let Some(cl) = content_length {
                    if cl == 0 || cl < config.min_bytes {
                        // Small valid response, consider available
                        debug!("Small valid response from {} (Content-Length: {})", domain, cl);
                        return HttpCheckResult::Available;
                    }
                }
                // 204 No Content is valid
                if code == 204 {
                    return HttpCheckResult::Available;
                }
            }
        }
        
        // If already have enough body bytes
        if body_bytes >= config.min_bytes {
            return HttpCheckResult::Available;
        }
        
        // Read more body with read_timeout
        let read_timeout = std::cmp::min(
            config.read_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let read_start = TokioInstant::now();
        
        while body_bytes < config.min_bytes && body_bytes < config.max_bytes {
            if TokioInstant::now() >= deadline || read_start.elapsed() >= read_timeout {
                break;
            }
            
            let remaining_time = std::cmp::min(
                read_timeout.saturating_sub(read_start.elapsed()),
                deadline.saturating_duration_since(TokioInstant::now())
            );
            
            match tokio::time::timeout(remaining_time, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    body_bytes += n;
                }
                Ok(Ok(_)) => break, // EOF
                Ok(Err(_)) => break,
                Err(_) => break, // Timeout
            }
        }
        
        if body_bytes >= config.min_bytes {
            HttpCheckResult::Available
        } else {
            debug!("Insufficient data from {}: got {} bytes, need {}", domain, body_bytes, config.min_bytes);
            HttpCheckResult::InsufficientData
        }
    }

    /// Perform HTTP exchange over plain TCP stream
    async fn perform_http_exchange_plain(&self, mut stream: TcpStream, domain: &str, deadline: TokioInstant) -> HttpCheckResult {
        let config = &self.config.availability_config;
        let request = Self::build_http_request(domain);
        
        // Send request
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            debug!("Failed to send HTTP request to {}: {}", domain, e);
            return HttpCheckResult::Unavailable;
        }
        
        // TTFB timeout - wait for first bytes
        let ttfb_timeout = std::cmp::min(
            config.ttfb_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let mut buffer = vec![0u8; 4096];
        let mut total_received = 0usize;
        let mut status_code: Option<u16> = None;
        let mut headers = Vec::new();
        let mut body_bytes = 0usize;
        let mut header_buffer = String::new();
        
        // Read first chunk (TTFB)
        let first_read = match tokio::time::timeout(ttfb_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => return HttpCheckResult::Unavailable, // Connection closed
            Ok(Err(e)) => {
                debug!("Read error from {}: {}", domain, e);
                return HttpCheckResult::Unavailable;
            }
            Err(_) => return HttpCheckResult::Timeout,
        };
        
        total_received += first_read;
        header_buffer.push_str(&String::from_utf8_lossy(&buffer[..first_read]));
        
        // Parse status line
        if let Some(status_line_end) = header_buffer.find("\r\n") {
            let status_line = &header_buffer[..status_line_end];
            status_code = Self::parse_status_line(status_line);
        }
        
        // Check for blocking status codes immediately
        if let Some(code) = status_code {
            if config.blocked_status_codes.contains(&code) {
                debug!("Blocked status code {} from {}", code, domain);
                return HttpCheckResult::Blocked;
            }
            if config.server_error_codes.contains(&code) {
                debug!("Server error {} from {}", code, domain);
                return HttpCheckResult::ServerError;
            }
        }
        
        // Find headers end
        if let Some(headers_end) = header_buffer.find("\r\n\r\n") {
            let header_section = &header_buffer[..headers_end];
            headers = header_section.lines().skip(1).map(|s| s.to_string()).collect();
            body_bytes = total_received - (headers_end + 4);
        }
        
        // Parse headers for Content-Length and Location
        let (content_length, location) = Self::parse_headers(&headers);
        
        // Handle redirects (3xx)
        if let Some(code) = status_code {
            if (300..400).contains(&code) {
                if let Some(loc) = location {
                    return HttpCheckResult::Redirect(loc);
                }
            }
        }
        
        // Special case: 2xx with small or zero Content-Length
        if let Some(code) = status_code {
            if (200..300).contains(&code) {
                if let Some(cl) = content_length {
                    if cl == 0 || cl < config.min_bytes {
                        // Small valid response, consider available
                        debug!("Small valid response from {} (Content-Length: {})", domain, cl);
                        return HttpCheckResult::Available;
                    }
                }
                // 204 No Content is valid
                if code == 204 {
                    return HttpCheckResult::Available;
                }
            }
        }
        
        // If already have enough body bytes
        if body_bytes >= config.min_bytes {
            return HttpCheckResult::Available;
        }
        
        // Read more body with read_timeout
        let read_timeout = std::cmp::min(
            config.read_timeout,
            deadline.saturating_duration_since(TokioInstant::now())
        );
        
        let read_start = TokioInstant::now();
        
        while body_bytes < config.min_bytes && body_bytes < config.max_bytes {
            if TokioInstant::now() >= deadline || read_start.elapsed() >= read_timeout {
                break;
            }
            
            let remaining_time = std::cmp::min(
                read_timeout.saturating_sub(read_start.elapsed()),
                deadline.saturating_duration_since(TokioInstant::now())
            );
            
            match tokio::time::timeout(remaining_time, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    body_bytes += n;
                }
                Ok(Ok(_)) => break, // EOF
                Ok(Err(_)) => break,
                Err(_) => break, // Timeout
            }
        }
        
        if body_bytes >= config.min_bytes {
            HttpCheckResult::Available
        } else {
            debug!("Insufficient data from {}: got {} bytes, need {}", domain, body_bytes, config.min_bytes);
            HttpCheckResult::InsufficientData
        }
    }

    /// Get routing decision for SNI domains with enhanced logic
    pub async fn get_sni_routing_decision_async(&self, domain: &str, port: u16) -> Option<RoutingDecision> {
        // First, check domain rules
        if let Some(dec) = self.get_routing_decision(domain) {
            return Some(dec);
        }

        // Resolve IP
        if let Some(ip) = self.resolve_domain(domain).await {
            // Check geoip
            if let Some(dec) = self.get_ip_routing_decision(ip) {
                return Some(dec);
            }
        }

        if self.config.availability_check {
            // Check availability on specified port for top-level domain
            let tld = get_top_level_domain(domain);
            if self.check_availability(&tld, port).await {
                Some(RoutingDecision::Direct)
            } else {
                // Use default proxy
                self.proxies.get("default").map(|p| RoutingDecision::Proxy(p.clone()))
            }
        } else {
            None
        }
    }
}

/// Load and parse GeoIP data from file
fn load_geoip(path: &str) -> anyhow::Result<HashMap<String, Vec<CidrBlock>>> {
    let data = tokio::task::block_in_place(|| std::fs::read(path))
        .map_err(|e| RuleEngineError::GeoIpLoadError(format!("Failed to read {}: {}", path, e)))?;

    if data.is_empty() {
        return Err(anyhow!(RuleEngineError::GeoIpLoadError(
            format!("{} is empty", path)
        )));
    }

    info!("Loading GeoIP data from {} ({} bytes)", path, data.len());

    let geoip_list: GeoIpList = decode_geoip(&data)
        .map_err(|e| RuleEngineError::GeoIpLoadError(format!("Failed to decode {}: {}", path, e)))?;

    if geoip_list.entry.is_empty() {
        debug!("No country entries found in {}", path);
        return Ok(HashMap::new());
    }

    info!("Processing {} GeoIP countries", geoip_list.entry.len());

    let mut map = HashMap::new();
    let mut total_cidrs = 0usize;
    let mut valid_cidrs = 0usize;

    for entry in geoip_list.entry {
        let country_code = entry.country_code.to_lowercase();
        let num_cidrs = entry.cidr.len();

        if country_code.is_empty() {
            debug!("Skipping country with empty code ({} CIDRs)", num_cidrs);
            continue;
        }

        if num_cidrs == 0 {
            debug!("Country '{}' has no CIDRs", country_code);
            continue;
        }

        total_cidrs += num_cidrs;

        let cidrs = process_geoip_cidrs_impl(&country_code, entry.cidr)?;
        valid_cidrs += cidrs.len();

        if !cidrs.is_empty() {
            map.insert(country_code, cidrs);
        }
    }

    info!("Loaded {} countries with {}/{} valid CIDRs from {}",
          map.len(), valid_cidrs, total_cidrs, path);

    Ok(map)
}

/// Process CIDR blocks for a country, filtering out invalid entries
fn process_geoip_cidrs_impl(country_code: &str, cidrs: Vec<geosite_rs::Cidr>) -> anyhow::Result<Vec<CidrBlock>> {
    let mut processed_cidrs = Vec::new();

    for cidr in cidrs {
        match cidr.ip.len() {
            4 => {
                // IPv4
                if cidr.prefix > 32 {
                    debug!("Skipping invalid IPv4 prefix for country {}: {} > 32", country_code, cidr.prefix);
                    continue;
                }
                let ip_bytes: [u8; 4] = match cidr.ip.as_slice().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        debug!("Invalid IPv4 bytes for country {}: {:?}", country_code, cidr.ip);
                        continue;
                    }
                };
                let base_ip = u32::from_be_bytes(ip_bytes);
                processed_cidrs.push(CidrBlock::V4(base_ip, cidr.prefix as u8));
            }
            16 => {
                // IPv6
                if cidr.prefix > 128 {
                    debug!("Skipping invalid IPv6 prefix for country {}: {} > 128", country_code, cidr.prefix);
                    continue;
                }
                let ip_bytes: [u8; 16] = match cidr.ip.as_slice().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        debug!("Invalid IPv6 bytes for country {}: {:?}", country_code, cidr.ip);
                        continue;
                    }
                };
                let base_ip = u128::from_be_bytes(ip_bytes);
                processed_cidrs.push(CidrBlock::V6(base_ip, cidr.prefix as u8));
            }
            _ => {
                debug!("Skipping CIDR with invalid IP length for country {}: {} bytes", country_code, cidr.ip.len());
                continue;
            }
        }
    }

    Ok(processed_cidrs)
}

/// Load and parse GeoSite data from file with optimized data structures
/// Uses HashSet for exact matches (O(1)) and Vec for suffix matches
fn load_geosite_optimized(path: &str) -> anyhow::Result<HashMap<String, OptimizedGeoSite>> {
    let data = tokio::task::block_in_place(|| std::fs::read(path))
        .map_err(|e| RuleEngineError::GeoSiteLoadError(format!("Failed to read {}: {}", path, e)))?;

    if data.is_empty() {
        return Err(anyhow!(RuleEngineError::GeoSiteLoadError(
            format!("{} is empty", path)
        )));
    }

    info!("Loading GeoSite data from {} ({} bytes) with optimized structures", path, data.len());

    let geosite_list: GeoSiteList = decode_geosite(&data)
        .map_err(|e| RuleEngineError::GeoSiteLoadError(format!("Failed to decode {}: {}", path, e)))?;

    if geosite_list.entry.is_empty() {
        debug!("No category entries found in {}", path);
        return Ok(HashMap::new());
    }

    info!("Processing {} GeoSite categories", geosite_list.entry.len());

    let mut map = HashMap::new();
    let mut total_domains = 0usize;
    let mut exact_count = 0usize;
    let mut suffix_count = 0usize;
    let mut regex_count = 0usize;

    for entry in geosite_list.entry {
        let category = entry.country_code.to_lowercase();
        let num_domains = entry.domain.len();

        if category.is_empty() {
            debug!("Skipping category with empty name ({} domains)", num_domains);
            continue;
        }

        if num_domains == 0 {
            debug!("Category '{}' has no domains", category);
            continue;
        }

        total_domains += num_domains;

        let mut optimized = OptimizedGeoSite::new();

        for domain in entry.domain {
            if domain.value.is_empty() {
                continue;
            }

            let domain_str = domain.value.to_lowercase();

            match domain.r#type {
                // Type 3: Full/exact match - use HashSet for O(1)
                3 => {
                    optimized.exact_domains.insert(domain_str);
                    exact_count += 1;
                }
                // Type 1: Regex match - compile as actual regex pattern
                1 => {
                    if let Ok(re) = Regex::new(&domain_str) {
                        optimized.regex_patterns.push(re);
                        regex_count += 1;
                    }
                }
                // Type 2: Domain suffix - use suffix array
                2 => {
                    // Add as suffix with leading dot for proper matching
                    let suffix = if domain_str.starts_with('.') {
                        domain_str
                    } else {
                        format!(".{}", domain_str)
                    };
                    optimized.suffix_domains.push(suffix);
                    // Also add exact match for base domain
                    optimized.exact_domains.insert(domain.value.to_lowercase().trim_start_matches('.').to_string());
                    suffix_count += 1;
                }
                // Type 0: Plain text - domain suffix match (anchored to prevent false positives)
                0 => {
                    let escaped = regex::escape(&domain_str);
                    let pattern = format!("(^|\\.){escaped}$");
                    if let Ok(re) = Regex::new(&pattern) {
                        optimized.regex_patterns.push(re);
                        regex_count += 1;
                    }
                }
                _ => {
                    debug!("Skipping unknown domain type {} for '{}' in category {}",
                          domain.r#type, domain_str, category);
                }
            }
        }

        if !optimized.exact_domains.is_empty() || !optimized.suffix_domains.is_empty() || !optimized.regex_patterns.is_empty() {
            map.insert(category, optimized);
        }
    }

    info!("Loaded {} categories from {} - {} exact (O(1)), {} suffix, {} regex patterns",
          map.len(), path, exact_count, suffix_count, regex_count);

    Ok(map)
}