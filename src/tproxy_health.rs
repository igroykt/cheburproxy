use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

const STATUS_UNKNOWN: u8 = 0;
const STATUS_OK: u8 = 1;
const STATUS_DEGRADED: u8 = 2;
const STATUS_FAILED: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TproxyHealthStatus {
    Ok,
    Degraded,
    Failed,
    Unknown,
}

impl std::fmt::Display for TproxyHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl TproxyHealthStatus {
    fn to_u8(self) -> u8 {
        match self {
            Self::Unknown => STATUS_UNKNOWN,
            Self::Ok => STATUS_OK,
            Self::Degraded => STATUS_DEGRADED,
            Self::Failed => STATUS_FAILED,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            STATUS_OK => Self::Ok,
            STATUS_DEGRADED => Self::Degraded,
            STATUS_FAILED => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

pub struct TproxyHealthChecker {
    fwmark: u32,
    route_table: u32,
    lan_iface: Option<String>,
    auto_recover: bool,
    recovery_script: Option<String>,
    last_recovery: Mutex<Option<Instant>>,
    recovery_cooldown: Duration,
    status: AtomicU8,
    prev_iface_state: Mutex<Option<String>>,
    /// When true, the iptables check is authoritative for health status.
    /// When false (no recovery_script), iptables failures are logged as warnings
    /// but do not degrade status — built-in recovery can only restore ip rule/route.
    full_health_scope: bool,
}

impl TproxyHealthChecker {
    pub fn new(
        fwmark: u32,
        route_table: u32,
        lan_iface: Option<String>,
        auto_recover: bool,
        recovery_script: Option<String>,
    ) -> Self {
        // Full health scope (including iptables) only if a recovery script can restore them.
        let full_health_scope = recovery_script.is_some();
        Self {
            fwmark,
            route_table,
            lan_iface,
            auto_recover,
            recovery_script,
            last_recovery: Mutex::new(None),
            recovery_cooldown: Duration::from_secs(60),
            status: AtomicU8::new(STATUS_UNKNOWN),
            prev_iface_state: Mutex::new(None),
            full_health_scope,
        }
    }

    pub fn status(&self) -> TproxyHealthStatus {
        TproxyHealthStatus::from_u8(self.status.load(Ordering::Relaxed))
    }

    pub async fn check_health(&self) -> TproxyHealthStatus {
        let (rule_ok, route_ok, iptables_ok) = tokio::join!(
            self.check_ip_rule(),
            self.check_ip_route(),
            self.check_iptables(),
        );

        // When no recovery_script is set, built-in recovery can only restore ip rule/route.
        // Including iptables in the recoverable status would cause a permanent Degraded loop.
        // Log iptables failures as a warning but exclude them from actionable status.
        let new_status = if self.full_health_scope {
            let passed = [rule_ok, route_ok, iptables_ok].iter().filter(|&&x| x).count();
            if passed == 3 {
                TproxyHealthStatus::Ok
            } else if passed == 0 {
                TproxyHealthStatus::Failed
            } else {
                TproxyHealthStatus::Degraded
            }
        } else {
            // Built-in scope: only ip rule + ip route determine actionable status
            if !iptables_ok {
                warn!(
                    "TPROXY iptables check: TPROXY rules missing from mangle table \
                     (fwmark=0x{:x}). Set tproxy_recovery_script for automatic restoration.",
                    self.fwmark
                );
            }
            match (rule_ok, route_ok) {
                (true, true) => TproxyHealthStatus::Ok,
                (false, false) => TproxyHealthStatus::Failed,
                _ => TproxyHealthStatus::Degraded,
            }
        };

        self.status.store(new_status.to_u8(), Ordering::Relaxed);

        debug!(
            "TPROXY health check: ip_rule={}, ip_route={}, iptables={} (scope={}) => {}",
            rule_ok, route_ok, iptables_ok,
            if self.full_health_scope { "full" } else { "routing-only" },
            new_status
        );

        new_status
    }

    async fn check_ip_rule(&self) -> bool {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("ip")
                .args(["rule", "show"])
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let text = String::from_utf8_lossy(&output.stdout);
                let pattern = format!("fwmark 0x{:x} lookup {}", self.fwmark, self.route_table);
                let found = text.contains(&pattern);
                if !found {
                    debug!("ip rule check: pattern '{}' not found", pattern);
                }
                found
            }
            Ok(Err(e)) => {
                error!("Failed to run 'ip rule show': {}", e);
                false
            }
            Err(_) => {
                warn!("'ip rule show' timed out");
                false
            }
        }
    }

    async fn check_ip_route(&self) -> bool {
        let table = self.route_table.to_string();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("ip")
                .args(["route", "show", "table", &table])
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let text = String::from_utf8_lossy(&output.stdout);
                // Check for the specific route that built-in recovery and start.sh add:
                // "local 0.0.0.0/0 dev lo" — avoid matching unrelated routes containing "local".
                let found = text.contains("local 0.0.0.0/0") || text.contains("local default");
                if !found {
                    debug!(
                        "ip route check: 'local 0.0.0.0/0' not found in table {}",
                        self.route_table
                    );
                }
                found
            }
            Ok(Err(e)) => {
                error!("Failed to run 'ip route show table {}': {}", self.route_table, e);
                false
            }
            Err(_) => {
                warn!("'ip route show table {}' timed out", self.route_table);
                false
            }
        }
    }

    async fn check_iptables(&self) -> bool {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("iptables")
                .args(["-t", "mangle", "-S"])
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let text = String::from_utf8_lossy(&output.stdout);
                // Verify TPROXY rule is present AND uses the configured fwmark,
                // to avoid false-positive from an unrelated service's TPROXY rule.
                let fwmark_str = format!("0x{:x}", self.fwmark);
                let found = text.contains("TPROXY") && text.contains(&fwmark_str);
                if !found {
                    debug!(
                        "iptables check: TPROXY rule with fwmark {} not found in mangle table",
                        fwmark_str
                    );
                }
                found
            }
            Ok(Err(e)) => {
                error!("Failed to run 'iptables -t mangle -S': {}", e);
                false
            }
            Err(_) => {
                warn!("'iptables -t mangle -S' timed out");
                false
            }
        }
    }

    /// Attempt TPROXY rule recovery. Returns `false` if still within cooldown period
    /// (recovery was skipped), `true` if a recovery attempt was made (regardless of outcome).
    pub async fn attempt_recovery(&self) -> bool {
        // Atomically check and update the cooldown timestamp in a single lock scope
        // to prevent a TOCTOU race where two concurrent callers both pass the check.
        {
            let mut last = self.last_recovery.lock().await;
            if let Some(t) = *last {
                if t.elapsed() < self.recovery_cooldown {
                    debug!(
                        "Recovery skipped: last attempt was {:.1}s ago (cooldown: {}s)",
                        t.elapsed().as_secs_f64(),
                        self.recovery_cooldown.as_secs()
                    );
                    return false;
                }
            }
            *last = Some(Instant::now());
        } // lock released before executing recovery commands

        if let Some(ref script) = self.recovery_script {
            info!("Running recovery script: {}", script);
            let result = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::process::Command::new(script).output(),
            )
            .await;

            match result {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        info!("Recovery script completed successfully");
                    } else {
                        warn!(
                            "Recovery script exited with status {}: {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
                Ok(Err(e)) => {
                    error!("Failed to run recovery script '{}': {}", script, e);
                }
                Err(_) => {
                    warn!("Recovery script '{}' timed out", script);
                }
            }
        } else {
            info!(
                "Attempting built-in TPROXY recovery (fwmark=0x{:x}, table={})",
                self.fwmark, self.route_table
            );

            // Add ip rule
            let rule_result = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new("ip")
                    .args([
                        "rule",
                        "add",
                        "fwmark",
                        &format!("0x{:x}", self.fwmark),
                        "lookup",
                        &self.route_table.to_string(),
                    ])
                    .output(),
            )
            .await;

            match rule_result {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        info!("Added ip rule: fwmark 0x{:x} lookup {}", self.fwmark, self.route_table);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists") {
                            debug!("ip rule already exists");
                        } else {
                            warn!("ip rule add failed: {}", stderr);
                        }
                    }
                }
                Ok(Err(e)) => error!("Failed to run 'ip rule add': {}", e),
                Err(_) => warn!("'ip rule add' timed out"),
            }

            // Add ip route
            let route_result = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new("ip")
                    .args([
                        "route",
                        "add",
                        "local",
                        "0.0.0.0/0",
                        "dev",
                        "lo",
                        "table",
                        &self.route_table.to_string(),
                    ])
                    .output(),
            )
            .await;

            match route_result {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        info!("Added ip route: local 0.0.0.0/0 dev lo table {}", self.route_table);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists") {
                            debug!("ip route already exists");
                        } else {
                            warn!("ip route add failed: {}", stderr);
                        }
                    }
                }
                Ok(Err(e)) => error!("Failed to run 'ip route add': {}", e),
                Err(_) => warn!("'ip route add' timed out"),
            }
        }

        // Recovery was attempted (commands may have succeeded or failed)
        true
    }

    pub async fn check_interface_state(&self) -> Option<bool> {
        let iface = self.lan_iface.as_deref()?;
        let path = format!("/sys/class/net/{}/operstate", iface);

        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                let state = content.trim().to_string();
                Some(state == "up")
            }
            Err(e) => {
                debug!("Failed to read interface state for {}: {}", iface, e);
                None
            }
        }
    }

    pub async fn monitoring_loop(
        &self,
        health_check_interval: Duration,
        iface_poll_interval: Duration,
    ) {
        let mut health_ticker = tokio::time::interval(health_check_interval);
        let mut iface_ticker = tokio::time::interval(iface_poll_interval);

        // Skip the immediate first tick
        health_ticker.tick().await;
        iface_ticker.tick().await;

        loop {
            tokio::select! {
                _ = health_ticker.tick() => {
                    debug!("Running periodic TPROXY health check");
                    let status = self.check_health().await;
                    match status {
                        TproxyHealthStatus::Ok => {
                            info!("TPROXY health check: {}", status);
                        }
                        TproxyHealthStatus::Degraded | TproxyHealthStatus::Failed => {
                            warn!("TPROXY health check: {} - rules may be missing", status);
                            if self.auto_recover {
                                info!("Auto-recovery enabled, attempting recovery...");
                                if self.attempt_recovery().await {
                                    // Re-check health after recovery
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                    let new_status = self.check_health().await;
                                    info!("TPROXY health after recovery attempt: {}", new_status);
                                }
                            }
                        }
                        TproxyHealthStatus::Unknown => {
                            warn!("TPROXY health check returned UNKNOWN status");
                        }
                    }
                }

                _ = iface_ticker.tick() => {
                    if self.lan_iface.is_none() {
                        continue;
                    }

                    let current_up = match self.check_interface_state().await {
                        Some(v) => v,
                        None => continue,
                    };

                    let current_state = if current_up { "up" } else { "down" };

                    let prev_state = {
                        let guard = self.prev_iface_state.lock().await;
                        guard.clone()
                    };

                    let was_down = prev_state.as_deref() == Some("down");
                    let transition_up = was_down && current_up;

                    if prev_state.as_deref() != Some(current_state) {
                        if let Some(ref iface) = self.lan_iface {
                            info!(
                                "Interface {} state changed: {} -> {}",
                                iface,
                                prev_state.as_deref().unwrap_or("unknown"),
                                current_state
                            );
                        }
                        let mut guard = self.prev_iface_state.lock().await;
                        *guard = Some(current_state.to_string());
                    }

                    if transition_up {
                        if let Some(ref iface) = self.lan_iface {
                            info!(
                                "Interface {} came up, waiting 2s before health check...",
                                iface
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let status = self.check_health().await;
                        info!("TPROXY health after interface up: {}", status);
                        if matches!(status, TproxyHealthStatus::Degraded | TproxyHealthStatus::Failed) && self.auto_recover {
                            info!("Attempting recovery after interface up event...");
                            if self.attempt_recovery().await {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                let new_status = self.check_health().await;
                                info!("TPROXY health after recovery: {}", new_status);
                            }
                        }
                    }
                }
            }
        }
    }
}
