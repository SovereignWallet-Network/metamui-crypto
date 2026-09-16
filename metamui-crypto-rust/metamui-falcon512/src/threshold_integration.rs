//! Integration of Threshold Optimization and Dual-Threshold Monitoring
//! 
//! This module integrates the advanced threshold systems into the main
//! Falcon-512 verification pipeline.

use crate::error::{Result, Falcon512Error};
use crate::dual_threshold_monitor::{
    DualThresholdConfig,
    initialize_global_monitor,
    with_global_monitor,
};
use crate::threshold_optimization::{
    ThresholdOptimizer,
    OptimizationMode,
};
use crate::PublicKey;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Global flag to enable threshold optimization
static THRESHOLD_OPTIMIZATION_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global flag to enable dual-threshold monitoring  
static DUAL_THRESHOLD_MONITORING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Counter for signatures processed
static SIGNATURES_PROCESSED: AtomicUsize = AtomicUsize::new(0);

/// Initialize threshold optimization system
pub fn initialize_threshold_optimization(_mode: OptimizationMode) -> Result<()> {
    // Initialize dual-threshold monitor with default config
    let config = DualThresholdConfig::default();
    initialize_global_monitor(config)?;
    
    // Enable optimization
    THRESHOLD_OPTIMIZATION_ENABLED.store(true, Ordering::SeqCst);
    DUAL_THRESHOLD_MONITORING_ENABLED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// Check if threshold optimization is enabled
pub fn is_optimization_enabled() -> bool {
    THRESHOLD_OPTIMIZATION_ENABLED.load(Ordering::SeqCst)
}

/// Check if dual-threshold monitoring is enabled
pub fn is_monitoring_enabled() -> bool {
    DUAL_THRESHOLD_MONITORING_ENABLED.load(Ordering::SeqCst)
}

/// Enhanced signature verification with threshold optimization
pub fn verify_with_threshold_optimization(
    _message: &[u8],
    _signature: &[u8],
    _public_key: &PublicKey,
    _s0: &[i16],
    _s1: &[i16],
) -> Result<bool> {
    Err(Falcon512Error::NotImplemented)
}

/// Standard threshold verification (fallback)
fn verify_standard_threshold(s0: &[i16], s1: &[i16]) -> Result<bool> {
    // Use the existing norm verification from falcon_complete
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
        + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    Ok(norm_sq <= 34034726) // floor(beta^2) is accepted (#352)
}

/// Configuration for threshold integration
#[derive(Clone, Debug)]
pub struct ThresholdIntegrationConfig {
    /// Enable optimization
    pub enable_optimization: bool,
    /// Enable monitoring
    pub enable_monitoring: bool,
    /// Optimization mode
    pub optimization_mode: OptimizationMode,
    /// Auto-transition to optimized-only in September 2025
    pub auto_transition_date: Option<String>,
    /// Verbose logging
    pub verbose: bool,
}

impl Default for ThresholdIntegrationConfig {
    fn default() -> Self {
        Self {
            enable_optimization: true,
            enable_monitoring: true,
            optimization_mode: OptimizationMode::Adaptive,
            auto_transition_date: None,
            verbose: false,
        }
    }
}

/// Integration manager for threshold systems
pub struct ThresholdIntegrationManager {
    /// Configuration
    config: ThresholdIntegrationConfig,
    /// Optimizer instance
    optimizer: ThresholdOptimizer,
}

impl ThresholdIntegrationManager {
    /// Create new integration manager
    pub fn new(config: ThresholdIntegrationConfig) -> Result<Self> {
        if config.auto_transition_date.is_some() {
            return Err(Falcon512Error::NotImplemented);
        }

        Ok(Self {
            optimizer: ThresholdOptimizer::new(config.optimization_mode.clone()),
            config,
        })
    }
    
    /// Process signature and update optimization
    pub fn process_signature(
        &mut self,
        s0: &[i16],
        s1: &[i16],
        accepted: bool,
    ) {
        // Update optimizer
        self.optimizer.process_signature(s0, s1, accepted);
    }
    
    /// Get current status
    pub fn get_status(&self) -> ThresholdStatus {
        ThresholdStatus {
            optimization_enabled: self.config.enable_optimization,
            monitoring_enabled: self.config.enable_monitoring,
            signatures_processed: self.optimizer.stats.total_signatures,
            acceptance_rate: self.optimizer.stats.acceptance_rate,
            current_threshold: self.optimizer.params.get_effective_threshold(),
            monitor_state: self.get_monitor_state(),
        }
    }
    
    /// Get monitor state
    fn get_monitor_state(&self) -> String {
        with_global_monitor(|monitor| format!("{:?}", monitor.state))
            .unwrap_or_else(|| "Not Initialized".to_string())
    }
}

/// Status information for threshold systems
#[derive(Clone, Debug)]
pub struct ThresholdStatus {
    pub optimization_enabled: bool,
    pub monitoring_enabled: bool,
    pub signatures_processed: usize,
    pub acceptance_rate: f64,
    pub current_threshold: f64,
    pub monitor_state: String,
}

/// Global integration manager instance
static GLOBAL_MANAGER: std::sync::Mutex<Option<ThresholdIntegrationManager>> = std::sync::Mutex::new(None);

/// Initialize global integration manager
pub fn initialize_global_manager(config: ThresholdIntegrationConfig) -> Result<()> {
    let mut guard = GLOBAL_MANAGER.lock().map_err(|_| Falcon512Error::AlreadyInitialized)?;
    if guard.is_some() {
        return Err(Falcon512Error::AlreadyInitialized);
    }
    *guard = Some(ThresholdIntegrationManager::new(config)?);
    Ok(())
}

/// Access the global manager via a closure
pub fn with_global_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThresholdIntegrationManager) -> R,
{
    GLOBAL_MANAGER.lock().ok()
        .and_then(|mut guard| guard.as_mut().map(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::N;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_threshold_integration() {
        // Initialize system
        initialize_threshold_optimization(OptimizationMode::Balanced)
            .expect("Initialization should succeed");
        
        assert!(is_optimization_enabled());
        assert!(is_monitoring_enabled());
    }

    #[test]
    fn test_verification_wrapper_fails_closed_until_real_signature_pipeline_exists() {
        let public_key = PublicKey {
            h: crate::poly::Poly::new(vec![0i16; N]),
        };
        let signature = vec![0u8; 64];
        let s0 = vec![0i16; N];
        let s1 = vec![0i16; N];

        assert!(matches!(
            verify_with_threshold_optimization(b"message", &signature, &public_key, &s0, &s1),
            Err(Falcon512Error::NotImplemented)
        ));
    }
    
    #[test]
    fn test_integration_manager() {
        let config = ThresholdIntegrationConfig::default();
        let mut manager = ThresholdIntegrationManager::new(config)
            .expect("manager initialization should succeed");
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Process some signatures
        for _ in 0..100 {
            let mut s0 = vec![0i16; N];
            let mut s1 = vec![0i16; N];
            
            for i in 0..N {
                s0[i] = rng.gen_range(-100..=100);
                s1[i] = rng.gen_range(-100..=100);
            }
            
            let accepted = rng.gen_bool(0.95);
            manager.process_signature(&s0, &s1, accepted);
        }
        
        let status = manager.get_status();
        assert_eq!(status.signatures_processed, 100);
        assert!(status.acceptance_rate > 0.0);
    }

    #[test]
    fn test_auto_transition_schedule_fails_closed_until_real_time_gate_exists() {
        let mut config = ThresholdIntegrationConfig::default();
        config.auto_transition_date = Some("2025-09-01".to_string());

        assert!(matches!(
            ThresholdIntegrationManager::new(config),
            Err(Falcon512Error::NotImplemented)
        ));
    }
}
