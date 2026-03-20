//! Router configuration and loading utilities
//!
//! This module provides data structures and functionality for loading and validating
//! proxy router configuration from JSON files. It includes comprehensive validation,
//! error handling, and performance optimizations.

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::{
    collections::HashMap,
    fmt,
    path::Path,
};
use tokio::io::AsyncReadExt;

/// Maximum allowed configuration file size (10MB) to prevent memory exhaustion attacks
const MAX_CONFIG_SIZE: usize = 10 * 1024 * 1024;

/// Router configuration containing upstream proxies and routing rules
#[derive(Debug, Clone, Deserialize)]
pub struct Router {
    /// Map of proxy tags to their configurations
    /// Each proxy represents an upstream server that can handle requests
    pub upstream_proxy: HashMap<String, Proxy>,

    /// Ordered list of routing rules
    /// Rules are evaluated in order, first match wins
    pub rules: Vec<Rule>,
}

impl Router {
    /// Validate the router configuration for logical consistency
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Check for duplicate proxy tags
        let mut proxy_tags = std::collections::HashSet::new();
        for proxy in self.upstream_proxy.values() {
            if !proxy_tags.insert(&proxy.tag) {
                anyhow::bail!("Duplicate proxy tag: {}", proxy.tag);
            }
        }

        // Check for duplicate rule tags
        let mut rule_tags = std::collections::HashSet::new();
        for rule in &self.rules {
            if !rule_tags.insert(&rule.tag) {
                anyhow::bail!("Duplicate rule tag: {}", rule.tag);
            }
        }

        // Validate that all rule tags reference existing proxies (except for special "direct" tag)
        for rule in &self.rules {
            if rule.tag.eq_ignore_ascii_case("direct") {
                continue; // "direct" is a special built-in tag that means no proxy
            }
            if !self.upstream_proxy.values().any(|proxy| proxy.tag == rule.tag) {
                anyhow::bail!(
                    "Rule '{}' references non-existent proxy '{}'",
                    rule.tag, rule.tag
                );
            }
        }

        // Validate individual components
        for (tag, proxy) in &self.upstream_proxy {
            proxy.validate().with_context(|| format!("Invalid proxy '{}'", tag))?;
        }

        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().with_context(|| format!("Invalid rule at index {}", i))?;
        }

        Ok(())
    }
}

/// UDP proxy mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpMode {
    /// Standard SOCKS5 UDP ASSOCIATE (requires separate UDP channel)
    UdpAssociate,
    /// UDP-over-TCP tunnel (works through firewalls and Yggdrasil)
    TcpTunnel,
}

impl Default for UdpMode {
    fn default() -> Self {
        UdpMode::UdpAssociate
    }
}

impl<'de> Deserialize<'de> for UdpMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "udp_associate" | "udpassociate" | "associate" => Ok(UdpMode::UdpAssociate),
            "tcp_tunnel" | "tcptunnel" | "tunnel" => Ok(UdpMode::TcpTunnel),
            other => Err(serde::de::Error::custom(format!(
                "Unknown udp_mode '{}': expected 'udp_associate' or 'tcp_tunnel'",
                other
            ))),
        }
    }
}

/// Upstream proxy configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Proxy {
    /// Server hostname or IP address
    pub server_addr: String,

    /// Server port number (1-65535)
    pub server_port: u16,

    /// Authentication credentials
    pub auth: Auth,

    /// Unique identifier for this proxy
    pub tag: String,

    /// UDP proxy mode: "udp_associate" (default) or "tcp_tunnel"
    #[serde(default)]
    pub udp_mode: UdpMode,
}

impl Proxy {
    /// Validate proxy configuration
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate server address
        if self.server_addr.trim().is_empty() {
            anyhow::bail!("Server address cannot be empty");
        }

        if self.server_addr.len() > 253 {
            anyhow::bail!("Server address too long (max 253 characters)");
        }

        // Validate port
        if self.server_port == 0 || self.server_port > 65535 {
            anyhow::bail!("Invalid port number: {} (must be 1-65535)", self.server_port);
        }

        // Validate tag
        if self.tag.trim().is_empty() {
            anyhow::bail!("Proxy tag cannot be empty");
        }

        if self.tag.len() > 100 {
            anyhow::bail!("Proxy tag too long (max 100 characters)");
        }

        // Validate auth credentials
        self.auth.validate().context("Invalid authentication credentials")?;

        Ok(())
    }
}

/// Authentication credentials for proxy servers
#[derive(Debug, Clone, Deserialize)]
pub struct Auth {
    /// Username for authentication
    pub username: String,

    /// Password for authentication
    pub pass: String,
}

impl Auth {
    /// Validate authentication credentials
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // If both username and password are empty, it's valid (no auth)
        if self.username.trim().is_empty() && self.pass.is_empty() {
            return Ok(());
        }

        // If password is provided but username is empty, that's invalid
        if !self.pass.is_empty() && self.username.trim().is_empty() {
            anyhow::bail!("Username cannot be empty when password is provided");
        }

        // If username is provided, validate it
        if !self.username.trim().is_empty() {
            if self.username.len() > 255 {
                anyhow::bail!("Username too long (max 255 characters)");
            }
        }

        if self.pass.len() > 255 {
            anyhow::bail!("Password too long (max 255 characters)");
        }

        Ok(())
    }
}

/// Routing rule configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// List of domain names this rule applies to
    /// Supports wildcards (e.g., "*.example.com")
    pub domains: Vec<String>,

    /// Geographic site codes for geolocation-based routing
    /// Optional - if provided, request must match one of these sites
    pub geosite: Option<Vec<String>>,

    /// Geographic IP codes for geolocation-based routing
    /// Optional - if provided, request source IP must match one of these countries/codes
    pub geoip: Option<Vec<String>>,

    /// Tag of the proxy to use for matching requests
    /// Must reference an existing proxy in upstream_proxies
    pub tag: String,
}

impl Rule {
    /// Validate rule configuration
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // A rule is valid if at least one matching criterion is provided:
        // explicit domains, geosite codes, or geoip codes.
        let has_geosite = self.geosite.as_ref().map_or(false, |v| !v.is_empty());
        let has_geoip = self.geoip.as_ref().map_or(false, |v| !v.is_empty());
        if self.domains.is_empty() && !has_geosite && !has_geoip {
            anyhow::bail!("Rule must have at least one matching criterion (domains, geosite, or geoip)");
        }

        for domain in &self.domains {
            if domain.trim().is_empty() {
                anyhow::bail!("Domain cannot be empty");
            }

            if domain.len() > 253 {
                anyhow::bail!("Domain too long (max 253 characters): {}", domain);
            }
        }

        // Validate tag
        if self.tag.trim().is_empty() {
            anyhow::bail!("Rule tag cannot be empty");
        }

        if self.tag.len() > 100 {
            anyhow::bail!("Rule tag too long (max 100 characters)");
        }

        Ok(())
    }
}

/// Load and parse router configuration from a JSON file with comprehensive validation
///
/// # Arguments
/// * `path` - Path to the JSON configuration file
///
/// # Returns
/// * `Ok(Router)` - Parsed and validated configuration
/// * `Err(anyhow::Error)` - Various error conditions (file not found, invalid JSON, validation errors)
///
/// # Examples
/// ```
/// let router = load_config("config/router.json").await?;
/// ```
pub async fn load_config<P: AsRef<Path>>(path: P) -> Result<Router> {
    let path = path.as_ref();

    // Open file with better error context
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open config file: {}", path.display()))?;

    // Check file size before reading to prevent memory exhaustion
    let metadata = file.metadata().await
        .with_context(|| format!("Failed to read metadata for config file: {}", path.display()))?;

    let file_size = metadata.len() as usize;
    if file_size > MAX_CONFIG_SIZE {
        anyhow::bail!("Configuration file too large: {} bytes (max: {} bytes)", file_size, MAX_CONFIG_SIZE);
    }

    if file_size == 0 {
        anyhow::bail!("Configuration file is empty or contains no valid data");
    }

    // Read file content efficiently with pre-allocation
    let mut content = String::with_capacity(file_size.min(8192)); // Pre-allocate reasonable size
    file.read_to_string(&mut content).await
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    // Parse JSON with better error context
    let cfg: Router = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON in config file: {}", path.display()))?;

    // Validate the configuration
    cfg.validate().context("Configuration validation failed")?;

    Ok(cfg)
}
