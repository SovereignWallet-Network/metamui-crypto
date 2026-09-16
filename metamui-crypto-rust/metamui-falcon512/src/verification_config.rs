//! Configuration for Falcon signature verification
//! 
//! This module provides configuration options for the verification process,
//! including whether to use refinement algorithms and their parameters.

/// Configuration for signature verification
#[derive(Clone, Debug)]
pub struct VerificationConfig {
    /// Enable Babai nearest plane refinement
    pub use_babai: bool,
    
    /// Enable iterative gradient refinement
    pub use_iterative: bool,
    
    /// Maximum iterations for Babai algorithm
    pub babai_max_iterations: usize,
    
    /// Configuration for iterative refinement
    pub iterative_config: crate::iterative_refinement::RefinementConfig,
    
    /// Enable verbose logging
    pub verbose: bool,
    
    /// Use relaxed error threshold (temporary)
    pub use_relaxed_threshold: bool,
    
    /// Target error threshold as percentage of maximum
    pub target_error_percent: f64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            use_babai: false,  // Disabled by default for performance
            use_iterative: false,  // Disabled by default for performance
            babai_max_iterations: 10,
            iterative_config: crate::iterative_refinement::RefinementConfig::default(),
            verbose: cfg!(feature = "std"),
            use_relaxed_threshold: false,  // Security fix: strict threshold to prevent wrong message verification
            target_error_percent: 1.0,  // 1% of maximum error
        }
    }
}

impl VerificationConfig {
    /// Create a configuration with all refinements enabled
    pub fn with_refinements() -> Self {
        Self {
            use_babai: true,
            use_iterative: true,
            ..Default::default()
        }
    }
    
    /// Create a configuration for maximum performance (no refinements)
    pub fn fast() -> Self {
        Self {
            use_babai: false,
            use_iterative: false,
            verbose: false,
            ..Default::default()
        }
    }
    
    /// Create a configuration for maximum accuracy
    pub fn accurate() -> Self {
        Self {
            use_babai: true,
            use_iterative: true,
            babai_max_iterations: 20,
            iterative_config: crate::iterative_refinement::RefinementConfig {
                max_iterations: 50,
                target_error_percent: 0.5,
                learning_rate: 0.05,
                use_momentum: true,
                momentum_factor: 0.95,
            },
            verbose: true,
            use_relaxed_threshold: false,  // Use strict threshold
            target_error_percent: 0.5,
        }
    }
}

/// Global verification configuration
///
/// This can be set once at application startup to configure
/// verification behavior globally.
static GLOBAL_CONFIG: std::sync::Mutex<Option<VerificationConfig>> = std::sync::Mutex::new(None);

/// Set the global verification configuration
///
/// This function is thread-safe. It should typically be called
/// once during application initialization before any verification.
pub fn set_global_config(config: VerificationConfig) {
    if let Ok(mut guard) = GLOBAL_CONFIG.lock() {
        *guard = Some(config);
    }
}

/// Get the global verification configuration
///
/// Returns the global config if set, otherwise returns default.
pub fn get_global_config() -> VerificationConfig {
    GLOBAL_CONFIG.lock().ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}

/// Builder pattern for verification configuration
pub struct VerificationConfigBuilder {
    config: VerificationConfig,
}

impl VerificationConfigBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: VerificationConfig::default(),
        }
    }
    
    /// Enable or disable Babai refinement
    pub fn with_babai(mut self, enable: bool) -> Self {
        self.config.use_babai = enable;
        self
    }
    
    /// Enable or disable iterative refinement
    pub fn with_iterative(mut self, enable: bool) -> Self {
        self.config.use_iterative = enable;
        self
    }
    
    /// Set maximum iterations for Babai
    pub fn babai_iterations(mut self, iterations: usize) -> Self {
        self.config.babai_max_iterations = iterations;
        self
    }
    
    /// Set iterative refinement iterations
    pub fn iterative_iterations(mut self, iterations: usize) -> Self {
        self.config.iterative_config.max_iterations = iterations;
        self
    }
    
    /// Set learning rate for iterative refinement
    pub fn learning_rate(mut self, rate: f64) -> Self {
        self.config.iterative_config.learning_rate = rate;
        self
    }
    
    /// Enable or disable verbose logging
    pub fn verbose(mut self, enable: bool) -> Self {
        self.config.verbose = enable;
        self
    }
    
    /// Use relaxed threshold
    pub fn relaxed_threshold(mut self, enable: bool) -> Self {
        self.config.use_relaxed_threshold = enable;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> VerificationConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_builder() {
        let config = VerificationConfigBuilder::new()
            .with_babai(true)
            .with_iterative(true)
            .babai_iterations(15)
            .learning_rate(0.1)
            .verbose(false)
            .build();
        
        assert!(config.use_babai);
        assert!(config.use_iterative);
        assert_eq!(config.babai_max_iterations, 15);
        assert_eq!(config.iterative_config.learning_rate, 0.1);
        assert!(!config.verbose);
    }
    
    #[test]
    fn test_preset_configs() {
        let fast = VerificationConfig::fast();
        assert!(!fast.use_babai);
        assert!(!fast.use_iterative);
        
        let accurate = VerificationConfig::accurate();
        assert!(accurate.use_babai);
        assert!(accurate.use_iterative);
        assert_eq!(accurate.babai_max_iterations, 20);
    }
}