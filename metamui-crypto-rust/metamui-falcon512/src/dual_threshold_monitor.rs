//! Dual-Threshold Monitoring System for Falcon-512
//! 
//! This module implements the dual-threshold monitoring system deployed
//! in June 2025. It runs both the original and optimized threshold systems
//! in parallel to ensure security while improving acceptance rates.

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use crate::threshold_optimization::{
    ThresholdOptimizer,
    OptimizationMode,
    verify_with_optimized_threshold,
};
use alloc::vec::Vec;
use alloc::string::String;

/// Original threshold implementation (pre-optimization)
const ORIGINAL_THRESHOLD: f64 = 1.17 * 1.8205 * 22.627416998;  // 1.17 * 1.8205 * sqrt(512)

/// Dual-threshold monitoring configuration
#[derive(Clone, Debug)]
pub struct DualThresholdConfig {
    /// Enable original threshold checking
    pub use_original: bool,
    /// Enable optimized threshold checking
    pub use_optimized: bool,
    /// Log discrepancies between thresholds
    pub log_discrepancies: bool,
    /// Alert on security violations
    pub alert_on_violations: bool,
    /// Automatic fallback to original on too many discrepancies
    pub auto_fallback: bool,
    /// Maximum allowed discrepancy rate before fallback
    pub max_discrepancy_rate: f64,
    /// Monitoring window size (number of signatures)
    pub window_size: usize,
}

impl Default for DualThresholdConfig {
    fn default() -> Self {
        Self {
            use_original: true,
            use_optimized: true,
            log_discrepancies: true,
            alert_on_violations: true,
            auto_fallback: true,
            max_discrepancy_rate: 0.01,  // 1% discrepancy threshold
            window_size: 10000,
        }
    }
}

/// Monitoring statistics for dual-threshold system
#[derive(Clone, Debug, Default)]
pub struct DualThresholdStats {
    /// Total signatures processed
    pub total_processed: usize,
    /// Signatures accepted by both thresholds
    pub both_accepted: usize,
    /// Signatures rejected by both thresholds
    pub both_rejected: usize,
    /// Accepted by original, rejected by optimized (false negatives)
    pub original_only: usize,
    /// Accepted by optimized, rejected by original (security concern)
    pub optimized_only: usize,
    /// Current discrepancy rate
    pub discrepancy_rate: f64,
    /// Security violations detected
    pub security_violations: usize,
    /// Performance improvements
    pub performance_gain: f64,
}

/// Discrepancy record for analysis
#[derive(Clone, Debug)]
pub struct DiscrepancyRecord {
    /// Signature identifier
    pub signature_id: usize,
    /// Signature norm
    pub norm: f64,
    /// Original threshold result
    pub original_result: bool,
    /// Optimized threshold result
    pub optimized_result: bool,
    /// Discrepancy type
    pub discrepancy_type: DiscrepancyType,
    /// Timestamp (iteration)
    pub timestamp: usize,
}

/// Types of discrepancies
#[derive(Clone, Debug, PartialEq)]
pub enum DiscrepancyType {
    /// Original accepted, optimized rejected
    FalseNegative,
    /// Original rejected, optimized accepted
    PotentialSecurityRisk,
    /// No discrepancy
    None,
}

/// Dual-threshold monitoring system
pub struct DualThresholdMonitor {
    /// Configuration
    config: DualThresholdConfig,
    /// Original threshold parameters
    original_params: OriginalThresholdParams,
    /// Optimized threshold system
    optimizer: ThresholdOptimizer,
    /// Monitoring statistics
    stats: DualThresholdStats,
    /// Discrepancy log
    discrepancy_log: Vec<DiscrepancyRecord>,
    /// Sliding window for rate calculation
    sliding_window: SlidingWindow,
    /// Alert callback
    alert_callback: Option<fn(&str)>,
    /// System state
    pub state: MonitorState,
}

/// Original threshold parameters (for comparison)
#[derive(Clone, Debug)]
struct OriginalThresholdParams {
    threshold: f64,
    strict_mode: bool,
}

impl Default for OriginalThresholdParams {
    fn default() -> Self {
        Self {
            threshold: ORIGINAL_THRESHOLD,
            strict_mode: true,
        }
    }
}

/// Monitor state
#[derive(Clone, Debug, PartialEq)]
pub enum MonitorState {
    /// Normal operation with both thresholds
    Normal,
    /// Degraded - high discrepancy rate
    Degraded,
    /// Fallback - using original only
    Fallback,
    /// Optimized only (after September 2025)
    OptimizedOnly,
}

/// Sliding window for rate calculations
struct SlidingWindow {
    /// Window data
    data: Vec<bool>,
    /// Current position
    position: usize,
    /// Window size
    size: usize,
}

impl SlidingWindow {
    fn new(size: usize) -> Self {
        Self {
            data: vec![false; size],
            position: 0,
            size,
        }
    }
    
    fn add(&mut self, value: bool) {
        self.data[self.position] = value;
        self.position = (self.position + 1) % self.size;
    }
    
    fn get_rate(&self) -> f64 {
        let count = self.data.iter().filter(|&&x| x).count();
        count as f64 / self.size as f64
    }
}

impl DualThresholdMonitor {
    /// Create new dual-threshold monitor
    pub fn new(config: DualThresholdConfig) -> Self {
        Self {
            sliding_window: SlidingWindow::new(config.window_size),
            optimizer: ThresholdOptimizer::new(OptimizationMode::Adaptive),
            config,
            original_params: OriginalThresholdParams::default(),
            stats: DualThresholdStats::default(),
            discrepancy_log: Vec::new(),
            alert_callback: None,
            state: MonitorState::Normal,
        }
    }
    
    /// Set alert callback
    pub fn set_alert_callback(&mut self, callback: fn(&str)) {
        self.alert_callback = Some(callback);
    }
    
    /// Process signature with dual-threshold monitoring
    pub fn verify_signature(
        &mut self,
        s0: &[i16],
        s1: &[i16],
    ) -> Result<(bool, MonitoringResult)> {
        self.stats.total_processed += 1;
        
        // Compute signature norm
        let norm = compute_norm(s0, s1);
        
        // Check with original threshold
        let original_result = if self.config.use_original && self.state != MonitorState::OptimizedOnly {
            verify_original_threshold(s0, s1, &self.original_params)
        } else {
            true  // Default to accept if not checking
        };
        
        // Check with optimized threshold
        let optimized_result = if self.config.use_optimized {
            verify_with_optimized_threshold(s0, s1, &self.optimizer.params)?
        } else {
            original_result  // Use original if optimized disabled
        };
        
        // Update optimizer statistics
        self.optimizer.process_signature(s0, s1, optimized_result);
        
        // Analyze results
        let monitoring_result = self.analyze_results(
            original_result,
            optimized_result,
            norm,
        );
        
        // Determine final result based on state
        let final_result = match self.state {
            MonitorState::Normal => {
                // Both must agree for acceptance in normal mode
                original_result && optimized_result
            }
            MonitorState::Degraded => {
                // Use more conservative result
                original_result && optimized_result
            }
            MonitorState::Fallback => {
                // Use original only
                original_result
            }
            MonitorState::OptimizedOnly => {
                // Use optimized only (post-September 2025)
                optimized_result
            }
        };
        
        Ok((final_result, monitoring_result))
    }
    
    /// Analyze threshold results and update monitoring
    fn analyze_results(
        &mut self,
        original: bool,
        optimized: bool,
        norm: f64,
    ) -> MonitoringResult {
        // Update statistics
        if original && optimized {
            self.stats.both_accepted += 1;
        } else if !original && !optimized {
            self.stats.both_rejected += 1;
        } else if original && !optimized {
            self.stats.original_only += 1;
        } else {
            self.stats.optimized_only += 1;
        }
        
        // Check for discrepancy
        let discrepancy_type = if original != optimized {
            if original && !optimized {
                DiscrepancyType::FalseNegative
            } else {
                DiscrepancyType::PotentialSecurityRisk
            }
        } else {
            DiscrepancyType::None
        };
        
        // Log discrepancy if present
        if discrepancy_type != DiscrepancyType::None {
            self.log_discrepancy(norm, original, optimized, discrepancy_type.clone());
            
            // Update sliding window
            self.sliding_window.add(true);
            
            // Check for security violation
            if discrepancy_type == DiscrepancyType::PotentialSecurityRisk {
                self.stats.security_violations += 1;
                if self.config.alert_on_violations {
                    self.trigger_alert(&format!(
                        "Security violation: Optimized threshold accepted signature with norm {} that original rejected",
                        norm
                    ));
                }
            }
        } else {
            self.sliding_window.add(false);
        }
        
        // Update discrepancy rate
        self.stats.discrepancy_rate = self.sliding_window.get_rate();
        
        // Check for state transitions
        self.check_state_transitions();
        
        // Calculate performance gain
        if self.stats.total_processed > 0 {
            let optimized_acceptance = (self.stats.both_accepted + self.stats.optimized_only) as f64;
            let original_acceptance = (self.stats.both_accepted + self.stats.original_only) as f64;
            self.stats.performance_gain = 
                (optimized_acceptance - original_acceptance) / original_acceptance;
        }
        
        MonitoringResult {
            original_result: original,
            optimized_result: optimized,
            discrepancy: discrepancy_type != DiscrepancyType::None,
            current_state: self.state.clone(),
            performance_gain: self.stats.performance_gain,
        }
    }
    
    /// Log discrepancy for analysis
    fn log_discrepancy(
        &mut self,
        norm: f64,
        original: bool,
        optimized: bool,
        discrepancy_type: DiscrepancyType,
    ) {
        let record = DiscrepancyRecord {
            signature_id: self.stats.total_processed,
            norm,
            original_result: original,
            optimized_result: optimized,
            discrepancy_type,
            timestamp: self.stats.total_processed,
        };
        
        self.discrepancy_log.push(record);
        
        // Limit log size
        if self.discrepancy_log.len() > 10000 {
            self.discrepancy_log.drain(0..5000);
        }
        
        if self.config.log_discrepancies {
            // In production, this would write to a log file
            // For now, we just track in memory
        }
    }
    
    /// Check for state transitions
    fn check_state_transitions(&mut self) {
        match self.state {
            MonitorState::Normal => {
                if self.stats.discrepancy_rate > self.config.max_discrepancy_rate {
                    self.state = MonitorState::Degraded;
                    self.trigger_alert("Entering degraded mode due to high discrepancy rate");
                }
            }
            MonitorState::Degraded => {
                if self.stats.discrepancy_rate > self.config.max_discrepancy_rate * 2.0 {
                    if self.config.auto_fallback {
                        self.state = MonitorState::Fallback;
                        self.trigger_alert("Falling back to original threshold only");
                    }
                } else if self.stats.discrepancy_rate < self.config.max_discrepancy_rate * 0.5 {
                    self.state = MonitorState::Normal;
                    self.trigger_alert("Returning to normal mode");
                }
            }
            MonitorState::Fallback => {
                // Stay in fallback until a real operator-controlled recovery path exists.
            }
            MonitorState::OptimizedOnly => {
                // No transitions from this state
            }
        }
    }
    
    /// Trigger alert
    fn trigger_alert(&self, message: &str) {
        if let Some(callback) = self.alert_callback {
            callback(message);
        }
    }
    
    /// Generate monitoring report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("=== Dual-Threshold Monitoring Report ===\n\n");
        report.push_str(&format!("Current State: {:?}\n", self.state));
        report.push_str(&format!("Total Processed: {}\n", self.stats.total_processed));
        report.push_str("\nAcceptance Statistics:\n");
        report.push_str(&format!("  Both Accept: {} ({:.2}%)\n", 
            self.stats.both_accepted,
            100.0 * self.stats.both_accepted as f64 / self.stats.total_processed.max(1) as f64
        ));
        report.push_str(&format!("  Both Reject: {} ({:.2}%)\n",
            self.stats.both_rejected,
            100.0 * self.stats.both_rejected as f64 / self.stats.total_processed.max(1) as f64
        ));
        report.push_str(&format!("  Original Only: {} ({:.2}%)\n",
            self.stats.original_only,
            100.0 * self.stats.original_only as f64 / self.stats.total_processed.max(1) as f64
        ));
        report.push_str(&format!("  Optimized Only: {} ({:.2}%)\n",
            self.stats.optimized_only,
            100.0 * self.stats.optimized_only as f64 / self.stats.total_processed.max(1) as f64
        ));
        
        report.push_str("\nPerformance Metrics:\n");
        report.push_str(&format!("  Discrepancy Rate: {:.4}%\n", 
            self.stats.discrepancy_rate * 100.0));
        report.push_str(&format!("  Security Violations: {}\n", 
            self.stats.security_violations));
        report.push_str(&format!("  Performance Gain: {:.2}%\n", 
            self.stats.performance_gain * 100.0));
        
        if !self.discrepancy_log.is_empty() {
            report.push_str("\nRecent Discrepancies:\n");
            for record in self.discrepancy_log.iter().rev().take(5) {
                report.push_str(&format!("  ID {}: Norm {:.2}, Type: {:?}\n",
                    record.signature_id,
                    record.norm,
                    record.discrepancy_type
                ));
            }
        }
        
        report.push_str("\nOptimizer Status:\n");
        report.push_str(&self.optimizer.generate_report());
        
        report
    }
    
    /// Transition to optimized-only mode
    pub fn transition_to_optimized_only(&mut self) -> Result<()> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Result from monitoring analysis
#[derive(Clone, Debug)]
pub struct MonitoringResult {
    /// Original threshold result
    pub original_result: bool,
    /// Optimized threshold result
    pub optimized_result: bool,
    /// Whether there was a discrepancy
    pub discrepancy: bool,
    /// Current monitor state
    pub current_state: MonitorState,
    /// Performance gain from optimization
    pub performance_gain: f64,
}

/// Verify with original threshold
fn verify_original_threshold(
    s0: &[i16],
    s1: &[i16],
    params: &OriginalThresholdParams,
) -> bool {
    let norm = compute_norm(s0, s1);
    
    if params.strict_mode {
        // Original strict verification
        norm <= params.threshold
    } else {
        // Slightly relaxed for comparison
        norm <= params.threshold * 1.01
    }
}

/// Compute signature norm
fn compute_norm(s0: &[i16], s1: &[i16]) -> f64 {
    let mut sum = 0.0;
    for i in 0..N {
        sum += (s0[i] as f64).powi(2) + (s1[i] as f64).powi(2);
    }
    sum.sqrt()
}

/// Global monitoring instance (for production use)
static GLOBAL_MONITOR: std::sync::Mutex<Option<DualThresholdMonitor>> = std::sync::Mutex::new(None);

/// Initialize global dual-threshold monitor
pub fn initialize_global_monitor(config: DualThresholdConfig) -> Result<()> {
    let mut guard = GLOBAL_MONITOR.lock().map_err(|_| Falcon512Error::AlreadyInitialized)?;
    if guard.is_some() {
        return Err(Falcon512Error::AlreadyInitialized);
    }
    *guard = Some(DualThresholdMonitor::new(config));
    Ok(())
}

/// Access the global monitor via a closure
pub fn with_global_monitor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut DualThresholdMonitor) -> R,
{
    GLOBAL_MONITOR.lock().ok()
        .and_then(|mut guard| guard.as_mut().map(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_dual_threshold_monitor() {
        let config = DualThresholdConfig::default();
        let monitor = DualThresholdMonitor::new(config);
        
        assert_eq!(monitor.state, MonitorState::Normal);
        assert_eq!(monitor.stats.total_processed, 0);
    }
    
    #[test]
    fn test_signature_verification() {
        let mut monitor = DualThresholdMonitor::new(DualThresholdConfig::default());
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate test signature
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        
        for i in 0..N {
            s0[i] = rng.gen_range(-50..=50);
            s1[i] = rng.gen_range(-50..=50);
        }
        
        let (result, monitoring) = monitor.verify_signature(&s0, &s1)
            .expect("Verification should succeed");
        
        assert_eq!(monitor.stats.total_processed, 1);
        assert_eq!(monitoring.current_state, MonitorState::Normal);
    }
    
    #[test]
    fn test_discrepancy_detection() {
        let mut monitor = DualThresholdMonitor::new(DualThresholdConfig::default());
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Process many signatures to potentially find discrepancies
        for _ in 0..100 {
            let mut s0 = vec![0i16; N];
            let mut s1 = vec![0i16; N];
            
            for i in 0..N {
                s0[i] = rng.gen_range(-100..=100);
                s1[i] = rng.gen_range(-100..=100);
            }
            
            let _ = monitor.verify_signature(&s0, &s1);
        }
        
        // Check that monitoring is working
        assert_eq!(monitor.stats.total_processed, 100);
        let report = monitor.generate_report();
        assert!(report.contains("Dual-Threshold Monitoring Report"));
    }

    #[test]
    fn test_transition_to_optimized_only_fails_closed_until_real_rollout_gate_exists() {
        let mut monitor = DualThresholdMonitor::new(DualThresholdConfig::default());
        monitor.stats.total_processed = 1_000_000;
        monitor.stats.security_violations = 0;

        let err = monitor.transition_to_optimized_only().unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
        assert_eq!(monitor.state, MonitorState::Normal);
        assert!(monitor.config.use_original);
    }

    #[test]
    fn test_fallback_does_not_auto_recover_from_processed_count_placeholder() {
        let mut monitor = DualThresholdMonitor::new(DualThresholdConfig::default());
        monitor.state = MonitorState::Fallback;
        monitor.stats.total_processed = 100_000;

        monitor.check_state_transitions();

        assert_eq!(monitor.state, MonitorState::Fallback);
    }
}
