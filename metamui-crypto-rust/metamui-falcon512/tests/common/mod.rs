/// Common test utilities and configurations for Falcon-512 tests

use metamui_falcon512::keygen_production::KeygenConfig;

/// Quick test configuration - minimal attempts for fast testing
pub fn quick_config() -> KeygenConfig {
    KeygenConfig {
        max_attempts: 5,
        simple_attempts: 2,
        invertible_attempts: 3,
        aggressive_optimization: false,
        enable_validation: false,
    }
}

/// Integration test configuration - balanced for reasonable coverage
pub fn integration_config() -> KeygenConfig {
    KeygenConfig {
        max_attempts: 20,
        simple_attempts: 5,
        invertible_attempts: 10,
        aggressive_optimization: false,
        enable_validation: true,
    }
}

/// Stress test configuration - full attempts for comprehensive testing
pub fn stress_config() -> KeygenConfig {
    KeygenConfig {
        max_attempts: 200,
        simple_attempts: 10,
        invertible_attempts: 20,
        aggressive_optimization: true,
        enable_validation: true,
    }
}

/// Helper to print test progress
pub fn print_progress(current: usize, total: usize, label: &str) {
    if current % (total / 10).max(1) == 0 || current == total {
        println!("{}: {}/{} ({:.0}%)", label, current, total, 
                 100.0 * current as f64 / total as f64);
    }
}