//! Shared proxy health tracking and circuit breaker for TCP and UDP paths.
//!
//! When an upstream SOCKS5 proxy becomes unreachable, the circuit breaker trips
//! so that subsequent connections fail fast (< 1ms) instead of waiting for
//! the full upstream_proxy_timeout (10-30s). A background health probe
//! periodically tests connectivity and resets the breaker on recovery.
//!
//! State machine:
//!   Healthy → Degraded (on failure) → CircuitOpen (threshold reached)
//!   CircuitOpen → HalfOpen (cooldown expires, probe starts) → SoftRecovery (probe OK)
//!   SoftRecovery → Healthy (N successes) | CircuitOpen (failure)
//!   HalfOpen → CircuitOpen (probe fails)
//!
//! Safety mechanisms:
//!   - Max open duration: force-resets circuit after configurable timeout (default 5min)
//!   - SOCKS5 handshake probe: validates proxy is truly functional
//!   - HalfOpen protection: stale failures from old connections are ignored
//!   - Exponential backoff: probe interval grows after repeated failures
//!   - Jitter: randomized timing prevents thundering herd on recovery
//!   - SoftRecovery: gradual traffic ramp-up prevents re-tripping after recovery
//!   - Failure classification: auth errors trip immediately, all others use threshold-based tripping
//!   - Recovery notifications: subscribers notified when proxy recovers

use dashmap::DashMap;
use log::{debug, info, warn};
use rand::Rng;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::transparent::connect_tcp_with_mark;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

// ── Configuration ────────────────────────────────────────────────────────────

/// Circuit breaker configuration (parsed from config.toml `[client]` section).
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Whether the circuit breaker is enabled at all (default true).
    /// Set to false to completely disable fast-failing and health probes.
    /// When disabled, all proxies are always treated as healthy, and no
    /// failures are recorded — connections simply time out naturally.
    pub enabled: bool,
    /// Seconds before probing a failed proxy again (default 30).
    pub cooldown: Duration,
    /// Consecutive failures required to trip the circuit (default 5).
    pub failure_threshold: u32,
    /// Seconds between background health probes when circuit is open (default 10).
    pub probe_interval: Duration,
    /// Timeout for TCP connect health probe (default 3s).
    pub probe_timeout: Duration,
    /// Maximum duration circuit can stay open before forced reset (default 300s / 5min).
    /// After this time, the circuit resets to allow trial connections.
    pub max_open_duration: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown: Duration::from_secs(30),
            failure_threshold: 5,
            probe_interval: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(3),
            max_open_duration: Duration::from_secs(300),
        }
    }
}

// ── Failure classification ───────────────────────────────────────────────────

/// Classification of proxy failures for smarter circuit breaker behavior.
///
/// Auth errors trip the circuit immediately since retrying a bad password won't help.
/// Protocol errors use the normal threshold-based approach: a single garbled SOCKS5
/// response can be a transient TCP corruption, not necessarily a permanent misconfiguration.
/// Transient/network errors also use the threshold-based approach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
    /// Timeout, temporary network issue — use threshold-based tripping
    Transient,
    /// SOCKS5 authentication rejected — immediate trip (config error)
    AuthFailure,
    /// Invalid SOCKS5 response / protocol mismatch — threshold-based
    /// (a single garbled packet shouldn't take down the whole proxy)
    ProtocolError,
    /// Connection refused, unreachable, network errors — threshold-based
    NetworkError,
}

impl FailureType {
    /// Classify an error string into a failure type using heuristics.
    pub fn classify(error: &str) -> Self {
        // Simple case-insensitive check without to_lowercase() allocation for common patterns
        let is_match = |patterns: &[&str]| {
            patterns.iter().any(|&p| {
                error.as_bytes().windows(p.len()).any(|w| w.eq_ignore_ascii_case(p.as_bytes()))
            })
        };

        if is_match(&["auth", "authentication failed"]) {
            FailureType::AuthFailure
        } else if is_match(&["invalid socks5", "protocol error", "unexpected version", "unsupported"]) {
            FailureType::ProtocolError
        } else if is_match(&["timeout", "timed out"]) {
            FailureType::Transient
        } else {
            FailureType::NetworkError
        }
    }

    /// Whether this failure type should trip the circuit immediately
    /// (bypassing the consecutive failure threshold).
    ///
    /// Only `AuthFailure` trips immediately: a wrong password will never succeed,
    /// so there is no point in accumulating failures toward a threshold.
    /// `ProtocolError` uses threshold-based tripping since a single malformed
    /// SOCKS5 response can be a transient TCP corruption, not a misconfiguration.
    pub fn is_immediate_trip(&self) -> bool {
        matches!(self, FailureType::AuthFailure)
    }
}

// ── Per-proxy state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    /// All good – connections are attempted normally.
    Healthy,
    /// Some failures, but threshold not yet reached.
    Degraded,
    /// Threshold crossed – all connections fast-fail.
    CircuitOpen,
    /// Cooldown expired, a probe is in progress.
    HalfOpen,
    /// Probe succeeded — gradually ramping up traffic before full Healthy.
    /// Only a fraction of connections are allowed through.
    SoftRecovery,
}

impl fmt::Display for ProxyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyStatus::Healthy => write!(f, "HEALTHY"),
            ProxyStatus::Degraded => write!(f, "DEGRADED"),
            ProxyStatus::CircuitOpen => write!(f, "CIRCUIT_OPEN"),
            ProxyStatus::HalfOpen => write!(f, "HALF_OPEN"),
            ProxyStatus::SoftRecovery => write!(f, "SOFT_RECOVERY"),
        }
    }
}

/// Number of successes required in SoftRecovery to transition to Healthy.
/// Lowered from 10 to 5: UDP is inherently lossy (especially through
/// MTU-constrained tunnels), so requiring fewer successes allows recovery
/// in degraded conditions. Combined with failure-ratio tolerance (not
/// just consecutive successes), this is still a strong recovery signal.
const SOFT_RECOVERY_SUCCESS_THRESHOLD: u32 = 5;
/// In SoftRecovery, allow 1 out of every N calls through (25% traffic).
const SOFT_RECOVERY_TRAFFIC_RATIO: u64 = 4;
/// Maximum backoff multiplier for probe intervals (caps at 8x base interval).
const MAX_PROBE_BACKOFF_MULTIPLIER: u32 = 8;
/// Maximum jitter as percentage of cooldown (25%).
const JITTER_PERCENT: u32 = 25;
/// Minimum sample size before evaluating failure ratio in SoftRecovery.
/// Below this, individual failures are tolerated to avoid noise from a few packets.
const SOFT_RECOVERY_MIN_SAMPLE: u32 = 5;
/// Maximum failure rate in SoftRecovery before re-opening circuit (50%).
/// If more than half of trial traffic fails, the proxy is genuinely unhealthy.
const SOFT_RECOVERY_MAX_FAILURE_RATE: f64 = 0.5;
/// Minimum interval between counted failures (prevents burst-tripping).
/// A tunnel blip causing 10 rapid failures within 100ms should count as 1,
/// not trip the circuit breaker with threshold=3.
const FAILURE_DEDUP_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct ProxyState {
    pub status: ProxyStatus,
    pub consecutive_failures: u32,
    pub last_failure: Option<Instant>,
    pub last_success: Option<Instant>,
    pub last_error: Option<String>,
    /// When the circuit was first opened (for duration reporting and max-open reset).
    pub circuit_opened_at: Option<Instant>,
    /// When the current probe started (to protect HalfOpen from stale failures).
    pub probe_started_at: Option<Instant>,
    /// How many times this circuit has been force-reset (for logging).
    pub force_reset_count: u32,
    /// Exponential backoff multiplier for probe intervals (1, 2, 4, 8).
    /// Grows on each probe failure, resets to 1 on success.
    pub probe_backoff_multiplier: u32,
    /// When the proxy last recovered from CircuitOpen/HalfOpen/SoftRecovery → Healthy.
    /// Used by external components (e.g., TCP tunnel pool) to detect recovery.
    pub last_recovery_at: Option<Instant>,
    /// Successes counted during SoftRecovery state.
    pub soft_recovery_successes: u32,
    /// Failures counted during SoftRecovery state (for ratio-based evaluation).
    /// Unlike the old behavior (single failure → CircuitOpen), we now track both
    /// successes and failures and use the failure ratio to decide.
    pub soft_recovery_failures: u32,
    /// Jitter (ms) applied to force-reset threshold for this circuit-open period.
    /// Generated ONCE when the circuit transitions to Open and reused by every
    /// subsequent is_healthy() call (M24 fix: prevents re-randomisation per call).
    pub force_reset_jitter_ms: u64,
}

impl ProxyState {
    fn new() -> Self {
        Self {
            status: ProxyStatus::Healthy,
            consecutive_failures: 0,
            last_failure: None,
            last_success: None,
            last_error: None,
            circuit_opened_at: None,
            probe_started_at: None,
            force_reset_count: 0,
            probe_backoff_multiplier: 1,
            last_recovery_at: None,
            soft_recovery_successes: 0,
            soft_recovery_failures: 0,
            force_reset_jitter_ms: 0,
        }
    }

    /// How long the circuit has been open (for logging).
    fn outage_duration(&self) -> Option<Duration> {
        self.circuit_opened_at.map(|t| t.elapsed())
    }
}

// ── Global tracker ───────────────────────────────────────────────────────────

/// Global singleton initialised via `init()`.
static INSTANCE: std::sync::OnceLock<Arc<ProxyHealthTracker>> = std::sync::OnceLock::new();

/// Initialise the global tracker with the given config. Safe to call once.
pub fn init(config: HealthConfig) {
    let tracker = Arc::new(ProxyHealthTracker {
        states: DashMap::new(),
        config,
        recovery_tx: DashMap::new(),
        soft_recovery_counter: AtomicU64::new(0),
    });
    let _ = INSTANCE.set(tracker);
}

/// Get a reference to the global tracker. Panics if `init()` was not called.
pub fn get() -> &'static Arc<ProxyHealthTracker> {
    INSTANCE.get().expect("ProxyHealthTracker not initialised – call proxy_health::init() first")
}

/// Convenience: check if a proxy address (e.g. "10.14.0.4:1070") is healthy.
pub fn is_healthy(proxy_addr: &str) -> bool {
    get().is_healthy(proxy_addr)
}

/// Convenience: record a connection failure for a proxy.
/// Automatically classifies the failure type from the error message.
/// Record a proxy failure and classify it automatically.
pub fn record_failure(proxy_addr: &str, error: &dyn fmt::Display) {
    let err_str = error.to_string(); // Single allocation for classification and storage
    let failure_type = FailureType::classify(&err_str);
    get().record_failure(proxy_addr, &err_str, failure_type);
}

/// Record a proxy failure with a pre-classified type.
pub fn record_failure_typed(proxy_addr: &str, error: &dyn fmt::Display, failure_type: FailureType) {
    get().record_failure(proxy_addr, &error.to_string(), failure_type);
}

/// Convenience: record a successful connection through a proxy.
pub fn record_success(proxy_addr: &str) {
    get().record_success(proxy_addr);
}

/// Convenience: get a one-line status summary for all tracked proxies.
pub fn status_summary() -> String {
    get().status_summary()
}

/// Subscribe to recovery events for a specific proxy address.
/// Returns a watch receiver that changes to `true` when the proxy recovers.
/// The receiver will get a notification each time the proxy transitions to Healthy.
pub fn subscribe_recovery(proxy_addr: &str) -> watch::Receiver<bool> {
    get().subscribe_recovery(proxy_addr)
}

/// Check when a proxy last recovered (for components that poll instead of subscribe).
pub fn last_recovery_at(proxy_addr: &str) -> Option<Instant> {
    get().last_recovery_at(proxy_addr)
}

// ── Tracker implementation ───────────────────────────────────────────────────

pub struct ProxyHealthTracker {
    states: DashMap<String, ProxyState>,
    config: HealthConfig,
    /// Recovery notification channels: proxy_addr → watch sender.
    /// When a proxy recovers, we send `true` to notify subscribers.
    recovery_tx: DashMap<String, watch::Sender<bool>>,
    /// Global counter for SoftRecovery traffic admission (used with modulo).
    soft_recovery_counter: AtomicU64,
}

impl ProxyHealthTracker {
    /// Check if the proxy is available for new connections.
    ///
    /// Returns `true` for Healthy, Degraded.
    /// Returns `false` for CircuitOpen and HalfOpen.
    /// For SoftRecovery: allows 25% of traffic through (1 in SOFT_RECOVERY_TRAFFIC_RATIO=4).
    /// For CircuitOpen: force-resets after max_open_duration with jitter.
    /// When `config.enabled = false`, always returns `true` unconditionally.
    pub fn is_healthy(&self, proxy_addr: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        if let Some(mut state) = self.states.get_mut(proxy_addr) {
            match state.status {
                ProxyStatus::CircuitOpen => {
                    // Check if max open duration exceeded → force reset (with jitter)
                    if let Some(opened_at) = state.circuit_opened_at {
                        // Use the jitter that was generated ONCE when the circuit opened
                        // (M24 fix: avoids re-randomising on every is_healthy() call).
                        let effective_max = self.config.max_open_duration
                            + Duration::from_millis(state.force_reset_jitter_ms);

                        if opened_at.elapsed() >= effective_max {
                            state.force_reset_count += 1;
                            let reset_num = state.force_reset_count;
                            let open_secs = opened_at.elapsed().as_secs();
                            
                            // FIX: Instead of Degraded, transition to HalfOpen so that 
                            // a background probe can verify the proxy before allowing 
                            // all traffic through. This prevents thundering herd if 
                            // the proxy is still dead.
                            state.status = ProxyStatus::HalfOpen;
                            state.probe_started_at = Some(Instant::now());
                            
                            warn!(
                                "Circuit breaker FORCE RESET #{} for proxy {} after {}s open \
                                 (max_open_duration={}s) — transitioned to HALF_OPEN for probing",
                                reset_num, proxy_addr, open_secs,
                                self.config.max_open_duration.as_secs()
                            );
                            return false; // Still block normal traffic until probe succeeds
                        }
                    }
                    false
                }
                ProxyStatus::HalfOpen => {
                    // Probe in progress – block normal traffic, let the probe verify.
                    false
                }
                ProxyStatus::SoftRecovery => {
                    // Allow 25% of traffic through during soft recovery (1 in 4).
                    // Uses a global atomic counter for fairness across concurrent calls.
                    let count = self.soft_recovery_counter.fetch_add(1, Ordering::Relaxed);
                    count % SOFT_RECOVERY_TRAFFIC_RATIO == 0
                }
                _ => true,
            }
        } else {
            // Unknown proxy – treat as healthy (first contact).
            true
        }
    }

    /// Record a connection failure. May trip the circuit breaker.
    ///
    /// `failure_type` controls whether the circuit trips immediately (auth errors)
    /// or uses the threshold-based approach (all other types).
    /// When `config.enabled = false`, this is a no-op.
    pub fn record_failure(&self, proxy_addr: &str, error: &str, failure_type: FailureType) {
        if !self.config.enabled {
            return;
        }
        let mut entry = self.states.entry(proxy_addr.to_string()).or_insert_with(ProxyState::new);
        let state = entry.value_mut();

        match state.status {
            ProxyStatus::Healthy | ProxyStatus::Degraded => {
                // FIX 4: Time-window deduplication — ignore rapid-fire failures.
                // A single tunnel blip can produce many UDP errors within milliseconds.
                // Only count failures separated by FAILURE_DEDUP_WINDOW (1s).
                // Auth errors (immediate trip) bypass dedup since they indicate real config issues.
                if !failure_type.is_immediate_trip() {
                    if let Some(last_fail) = state.last_failure {
                        if last_fail.elapsed() < FAILURE_DEDUP_WINDOW {
                            // Update error info but don't increment failure counter
                            state.last_failure = Some(Instant::now());
                            state.last_error = Some(error.to_string());
                            debug!(
                                "Ignoring rapid failure for {} (within {}ms dedup window): {}",
                                proxy_addr, FAILURE_DEDUP_WINDOW.as_millis(), error
                            );
                            return;
                        }
                    }
                }

                state.consecutive_failures += 1;
                state.last_failure = Some(Instant::now());
                state.last_error = Some(error.to_string());

                // Auth errors trip immediately — retrying a bad password won't fix misconfiguration.
                // All other types (ProtocolError, Transient, NetworkError) use the threshold.
                let should_trip = if failure_type.is_immediate_trip() {
                    warn!(
                        "Proxy {} {:?} failure — immediate circuit trip: {}",
                        proxy_addr, failure_type, error
                    );
                    true
                } else {
                    state.consecutive_failures >= self.config.failure_threshold
                };

                if should_trip {
                    let was = state.status;
                    state.status = ProxyStatus::CircuitOpen;
                    state.circuit_opened_at = Some(Instant::now());
                    state.probe_backoff_multiplier = 1; // Reset backoff on new circuit open
                    // Generate force-reset jitter once at circuit-open time (M24 fix).
                    let max_jitter = self.config.max_open_duration.as_millis() as u64
                        * JITTER_PERCENT as u64 / 100;
                    state.force_reset_jitter_ms = if max_jitter > 0 {
                        rand::thread_rng().gen_range(0..max_jitter)
                    } else {
                        0
                    };
                    warn!(
                        "Circuit breaker OPEN for proxy {} after {} failures (was {:?}): {}",
                        proxy_addr, state.consecutive_failures, was, error
                    );
                } else {
                    if state.status == ProxyStatus::Healthy {
                        state.status = ProxyStatus::Degraded;
                    }
                    warn!(
                        "Proxy {} failure ({}/{}, {:?}): {}",
                        proxy_addr, state.consecutive_failures, self.config.failure_threshold,
                        failure_type, error
                    );
                }
            }
            ProxyStatus::SoftRecovery => {
                // FIX 2: Ratio-based SoftRecovery tolerance instead of immediate re-open.
                //
                // Old behavior: any single failure → CircuitOpen. This made recovery
                // impossible through lossy connections (e.g., MTU-constrained tunnels
                // with 20% packet loss).
                //
                // New behavior: track failure ratio. Only re-open the circuit if the
                // failure rate exceeds SOFT_RECOVERY_MAX_FAILURE_RATE (50%) after
                // collecting SOFT_RECOVERY_MIN_SAMPLE (5) data points.
                state.soft_recovery_failures += 1;
                state.last_failure = Some(Instant::now());
                state.last_error = Some(error.to_string());

                let total = state.soft_recovery_successes + state.soft_recovery_failures;
                let failure_rate = state.soft_recovery_failures as f64 / total.max(1) as f64;

                if total >= SOFT_RECOVERY_MIN_SAMPLE && failure_rate > SOFT_RECOVERY_MAX_FAILURE_RATE {
                    // Failure rate too high — proxy is genuinely unhealthy.
                    state.status = ProxyStatus::CircuitOpen;
                    state.circuit_opened_at = Some(Instant::now());
                    state.consecutive_failures = self.config.failure_threshold;
                    state.soft_recovery_successes = 0;
                    state.soft_recovery_failures = 0;
                    state.probe_backoff_multiplier = 1;
                    // Generate force-reset jitter once at circuit-open time (M24 fix).
                    let max_jitter = self.config.max_open_duration.as_millis() as u64
                        * JITTER_PERCENT as u64 / 100;
                    state.force_reset_jitter_ms = if max_jitter > 0 {
                        rand::thread_rng().gen_range(0..max_jitter)
                    } else {
                        0
                    };
                    warn!(
                        "Proxy {} FAILED during soft recovery (failure rate {:.0}% > {:.0}% after {} samples) \
                         — circuit breaker re-OPENED: {}",
                        proxy_addr, failure_rate * 100.0,
                        SOFT_RECOVERY_MAX_FAILURE_RATE * 100.0, total, error
                    );
                } else {
                    debug!(
                        "Proxy {} soft recovery: tolerating failure ({}/{} total, {:.0}% failure rate, \
                         threshold {:.0}% after {} samples): {}",
                        proxy_addr, state.soft_recovery_failures, total,
                        failure_rate * 100.0, SOFT_RECOVERY_MAX_FAILURE_RATE * 100.0,
                        SOFT_RECOVERY_MIN_SAMPLE, error
                    );
                }
            }
            ProxyStatus::HalfOpen => {
                // PROTECTION: Ignore stale failures from old connections while
                // the health probe is in progress. Only the probe task itself
                // calls record_probe_failure() which can transition HalfOpen → CircuitOpen.
                debug!(
                    "Ignoring stale failure for proxy {} while health probe is in progress: {}",
                    proxy_addr, error
                );
            }
            ProxyStatus::CircuitOpen => {
                // Already open – just update timestamp.
                state.last_failure = Some(Instant::now());
                state.last_error = Some(error.to_string());
                debug!("Proxy {} still unreachable: {}", proxy_addr, error);
            }
        }
    }

    /// Record a probe failure (only called from the health probe task).
    /// This CAN transition HalfOpen → CircuitOpen, unlike regular record_failure.
    /// Also increases the exponential backoff multiplier.
    fn record_probe_failure(&self, proxy_addr: &str, error: &str) {
        if let Some(mut entry) = self.states.get_mut(proxy_addr) {
            let state = entry.value_mut();
            state.last_failure = Some(Instant::now());
            state.last_error = Some(error.to_string());

            match state.status {
                ProxyStatus::HalfOpen => {
                        state.status = ProxyStatus::CircuitOpen;
                        state.circuit_opened_at = Some(Instant::now());
                        state.probe_started_at = None;
    
                        // Exponential backoff: double the multiplier (capped at MAX)
                        state.probe_backoff_multiplier =
                            (state.probe_backoff_multiplier * 2).min(MAX_PROBE_BACKOFF_MULTIPLIER);
    
                        // Generate force-reset jitter once at circuit-open time (M24 fix).
                        let max_jitter = self.config.max_open_duration.as_millis() as u64
                            * JITTER_PERCENT as u64 / 100;
                        state.force_reset_jitter_ms = if max_jitter > 0 {
                            rand::thread_rng().gen_range(0..max_jitter)
                        } else {
                            0
                        };

                    warn!(
                        "Proxy {} health probe FAILED, circuit breaker remains OPEN \
                         (next probe backoff: {}x): {}",
                        proxy_addr, state.probe_backoff_multiplier, error
                    );
                }
                _ => {
                    debug!("Probe failure for proxy {} (status={}): {}", proxy_addr, state.status, error);
                }
            }
        }
    }

    /// Record a successful connection through a proxy.
    ///
    /// In SoftRecovery: counts successes toward full recovery.
    /// In CircuitOpen/HalfOpen: transitions to SoftRecovery (not directly to Healthy).
    /// In Degraded: resets to Healthy immediately.
    /// When `config.enabled = false`, this is a no-op.
    pub fn record_success(&self, proxy_addr: &str) {
        if !self.config.enabled {
            return;
        }
        let mut entry = self.states.entry(proxy_addr.to_string()).or_insert_with(ProxyState::new);
        let state = entry.value_mut();

        match state.status {
            ProxyStatus::SoftRecovery => {
                state.soft_recovery_successes += 1;
                state.last_success = Some(Instant::now());
                state.consecutive_failures = 0;

                if state.soft_recovery_successes >= SOFT_RECOVERY_SUCCESS_THRESHOLD {
                    // Enough successes — fully recover
                    let outage = state.outage_duration();
                    let failures = state.soft_recovery_failures;
                    state.status = ProxyStatus::Healthy;
                    state.circuit_opened_at = None;
                    state.probe_started_at = None;
                    state.probe_backoff_multiplier = 1;
                    state.last_error = None;
                    state.last_recovery_at = Some(Instant::now());
                    state.soft_recovery_successes = 0;
                    state.soft_recovery_failures = 0;

                    let duration_str = outage
                        .map(|d| format!("{}s", d.as_secs()))
                        .unwrap_or_else(|| "unknown".to_string());
                    warn!(
                        "Proxy {} FULLY RECOVERED after {} downtime ({} successes, {} failures during recovery)",
                        proxy_addr, duration_str, SOFT_RECOVERY_SUCCESS_THRESHOLD, failures
                    );

                    // Notify recovery subscribers
                    drop(entry); // Release DashMap lock before notifying
                    self.notify_recovery(proxy_addr);
                } else {
                    debug!(
                        "Proxy {} soft recovery progress: {}/{} successes ({} failures)",
                        proxy_addr, state.soft_recovery_successes, SOFT_RECOVERY_SUCCESS_THRESHOLD,
                        state.soft_recovery_failures
                    );
                }
            }
            ProxyStatus::CircuitOpen | ProxyStatus::HalfOpen => {
                // Transition to SoftRecovery instead of directly to Healthy
                // to prevent thundering herd on recovery.
                let outage = state.outage_duration();
                state.status = ProxyStatus::SoftRecovery;
                state.consecutive_failures = 0;
                state.last_success = Some(Instant::now());
                state.last_error = None;
                state.probe_started_at = None;
                state.probe_backoff_multiplier = 1;
                state.soft_recovery_successes = 1; // This success counts
                state.soft_recovery_failures = 0;  // Reset failure counter for new recovery attempt

                let duration_str = outage
                    .map(|d| format!("{}s", d.as_secs()))
                    .unwrap_or_else(|| "unknown".to_string());
                warn!(
                    "Proxy {} entering SOFT RECOVERY after {} downtime — ramping up traffic gradually",
                    proxy_addr, duration_str
                );
            }
            ProxyStatus::Degraded => {
                // FIX (Phase 7): Don't instantly reset failure counter on a single success.
                // A partially-failing proxy (e.g. TCP works but UDP fails) would never
                // trip the circuit breaker because each TCP success reset consecutive_failures.
                //
                // New behavior: only transition Degraded → Healthy if no failures have
                // occurred for the full cooldown_duration (30s). Otherwise, just record
                // the success without resetting the failure counter — failures can still
                // accumulate towards the threshold.
                let recovered = state.last_failure
                    .map(|t| t.elapsed() >= self.config.cooldown)
                    .unwrap_or(true);
                if recovered {
                    state.status = ProxyStatus::Healthy;
                    state.consecutive_failures = 0;
                    state.last_success = Some(Instant::now());
                    state.last_error = None;
                    debug!("Proxy {} recovered from Degraded (no failures for {}s)",
                        proxy_addr, self.config.cooldown.as_secs());
                } else {
                    // Still unstable — record success but keep failure counter intact
                    state.last_success = Some(Instant::now());
                }
            }
            ProxyStatus::Healthy => {
                // Already healthy — just update success timestamp
                state.last_success = Some(Instant::now());
            }
        }
    }

    /// Subscribe to recovery notifications for a proxy address.
    /// Returns a `watch::Receiver<bool>` that receives `true` when the proxy recovers.
    pub fn subscribe_recovery(&self, proxy_addr: &str) -> watch::Receiver<bool> {
        let entry = self.recovery_tx.entry(proxy_addr.to_string()).or_insert_with(|| {
            let (tx, _rx) = watch::channel(false);
            tx
        });
        entry.value().subscribe()
    }

    /// Notify all recovery subscribers for a proxy.
    fn notify_recovery(&self, proxy_addr: &str) {
        if let Some(tx) = self.recovery_tx.get(proxy_addr) {
            let _ = tx.send(true);
            info!("Recovery notification sent for proxy {}", proxy_addr);
        }
    }

    /// Check when a proxy last recovered (for polling-based components).
    pub fn last_recovery_at(&self, proxy_addr: &str) -> Option<Instant> {
        self.states.get(proxy_addr).and_then(|s| s.last_recovery_at)
    }

    /// Get a human-readable summary of all proxy states for stats logging.
    pub fn status_summary(&self) -> String {
        if self.states.is_empty() {
            return "no proxies tracked".to_string();
        }

        let mut parts = Vec::new();
        for entry in self.states.iter() {
            let addr = entry.key();
            let state = entry.value();
            let extra = match state.status {
                ProxyStatus::CircuitOpen | ProxyStatus::HalfOpen => {
                    let age = state.outage_duration()
                        .map(|d| format!(" {}s", d.as_secs()))
                        .unwrap_or_default();
                    let backoff = if state.probe_backoff_multiplier > 1 {
                        format!(" backoff={}x", state.probe_backoff_multiplier)
                    } else {
                        String::new()
                    };
                    format!("{}{}", age, backoff)
                }
                ProxyStatus::SoftRecovery => {
                    let total = state.soft_recovery_successes + state.soft_recovery_failures;
                    let failure_pct = if total > 0 {
                        state.soft_recovery_failures as f64 / total as f64 * 100.0
                    } else {
                        0.0
                    };
                    format!(" ok={}/{} fail={} ({:.0}%)",
                            state.soft_recovery_successes, SOFT_RECOVERY_SUCCESS_THRESHOLD,
                            state.soft_recovery_failures, failure_pct)
                }
                _ => String::new(),
            };
            parts.push(format!("{}={}{}", addr, state.status, extra));
        }
        parts.join(", ")
    }

    /// Get the current status for a specific proxy.
    #[allow(dead_code)]
    pub fn get_proxy_status(&self, proxy_addr: &str) -> Option<ProxyStatus> {
        self.states.get(proxy_addr).map(|s| s.status)
    }

    /// Run background health probes for all proxies in CircuitOpen state.
    ///
    /// Features:
    /// - Exponential backoff: probe interval grows on repeated failures (10s → 20s → 40s → 80s)
    /// - Jitter: random offset prevents synchronized probe storms
    /// - SOCKS5 handshake validation: confirms proxy is truly functional
    ///
    /// This function runs forever and should be spawned as a background task.
    pub async fn run_health_probes(&self) {
        if !self.config.enabled {
            info!("Proxy health probe task: circuit breaker DISABLED — health probes will not run");
            return;
        }

        info!("Proxy health probe task started (interval={}s, probe_timeout={}s, max_open={}s, \
               max_backoff={}x, jitter={}%)",
              self.config.probe_interval.as_secs(),
              self.config.probe_timeout.as_secs(),
              self.config.max_open_duration.as_secs(),
              MAX_PROBE_BACKOFF_MULTIPLIER,
              JITTER_PERCENT);

        loop {
            sleep(self.config.probe_interval).await;

            // Collect proxies that need probing.
            let to_probe: Vec<(String, Duration, u32)> = self.states.iter()
                .filter_map(|entry| {
                    let state = entry.value();
                    match state.status {
                        ProxyStatus::CircuitOpen => {
                            let open_duration = state.outage_duration().unwrap_or_default();
                            let backoff = state.probe_backoff_multiplier;

                            // Effective cooldown = base cooldown * backoff multiplier + jitter
                            let base_cooldown = self.config.cooldown * backoff;
                            let jitter_ms = {
                                let max_jitter = base_cooldown.as_millis() as u64
                                    * JITTER_PERCENT as u64 / 100;
                                if max_jitter > 0 {
                                    rand::thread_rng().gen_range(0..max_jitter)
                                } else {
                                    0
                                }
                            };
                            let effective_cooldown = base_cooldown
                                + Duration::from_millis(jitter_ms);

                            // Only probe if effective cooldown has expired.
                            if let Some(last_fail) = state.last_failure {
                                if last_fail.elapsed() >= effective_cooldown {
                                    return Some((entry.key().clone(), open_duration, backoff));
                                }
                            }
                            None
                        }
                        ProxyStatus::HalfOpen => {
                            // Proxies forced into HalfOpen state (e.g. by is_healthy force-reset)
                            // need to be picked up by the background probe task.
                            let open_duration = state.outage_duration().unwrap_or_default();
                            let backoff = state.probe_backoff_multiplier;
                            Some((entry.key().clone(), open_duration, backoff))
                        }
                        _ => None,
                    }
                })
                .collect();

            for (addr, open_duration, backoff) in to_probe {
                // Mark as HalfOpen before probing.
                if let Some(mut entry) = self.states.get_mut(&addr) {
                    entry.value_mut().status = ProxyStatus::HalfOpen;
                    entry.value_mut().probe_started_at = Some(Instant::now());
                }

                info!(
                    "Health probe: testing proxy {} with SOCKS5 handshake \
                     (circuit open for {}s, backoff={}x)",
                    addr, open_duration.as_secs(), backoff
                );

                match self.probe_socks5(&addr).await {
                    Ok(()) => {
                        self.record_success(&addr);
                        info!("Health probe: proxy {} probe SUCCESS (SOCKS5 handshake OK)", addr);
                    }
                    Err(e) => {
                        self.record_probe_failure(&addr, &format!("probe failed: {}", e));
                    }
                }
            }
        }
    }

    /// Perform a SOCKS5 handshake probe to validate the proxy is truly functional.
    ///
    /// Steps:
    /// 1. TCP connect to proxy
    /// 2. Send SOCKS5 greeting (version 5, 1 auth method: no auth)
    /// 3. Read SOCKS5 response (expect version 5, method 0)
    ///
    /// This validates the SOCKS5 server is alive and responding, not just TCP-reachable.
    async fn probe_socks5(&self, addr: &str) -> Result<(), String> {
        // Step 1: TCP connect with timeout
        let stream = match timeout(self.config.probe_timeout, connect_tcp_with_mark(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("TCP connect to {}: {}", addr, e)),
            Err(_) => return Err(format!("TCP connect timeout ({}s) to {}", self.config.probe_timeout.as_secs(), addr)),
        };

        // Step 2: SOCKS5 greeting
        // Version 5, 1 method, method 0 (no auth)
        let greeting = [0x05u8, 0x01, 0x00];
        let (mut reader, mut writer) = stream.into_split();

        match timeout(self.config.probe_timeout, writer.write_all(&greeting)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("SOCKS5 greeting write error: {}", e)),
            Err(_) => return Err(format!("SOCKS5 greeting write timeout ({}s)", self.config.probe_timeout.as_secs())),
        }

        // Step 3: Read SOCKS5 response (2 bytes: version, method)
        let mut response = [0u8; 2];
        match timeout(self.config.probe_timeout, reader.read_exact(&mut response)).await {
            Ok(Ok(_)) => {
                if response[0] != 0x05 {
                    return Err(format!("SOCKS5 response: unexpected version {:#x}", response[0]));
                }
                if response[1] == 0xFF {
                    return Err("SOCKS5 response: no acceptable auth methods".to_string());
                }
                // response[1] == 0x00 means no auth (good)
                // response[1] == 0x02 means username/password (also good, proxy is alive)
                debug!("SOCKS5 probe OK: version={:#x}, method={:#x}", response[0], response[1]);
                Ok(())
            }
            Ok(Err(e)) => Err(format!("SOCKS5 response read error: {}", e)),
            Err(_) => Err(format!("SOCKS5 response read timeout ({}s)", self.config.probe_timeout.as_secs())),
        }
    }
}
