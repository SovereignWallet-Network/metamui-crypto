//! Precision monitoring for numerical analysis
//! 
//! This module tracks equation errors and signature metrics to help
//! understand and improve the numerical precision of Falcon-512.

use crate::constants::{N, Q};

/// Signature metrics for monitoring
#[derive(Clone, Debug)]
pub struct SignatureMetrics {
    /// Error in the signature equation
    pub equation_error: i64,
    /// Squared norm of the signature
    pub norm_squared: i64,
    /// Which sampler was used
    pub sampler_used: String,
    /// Whether verification succeeded
    pub verification_result: bool,
    /// Timestamp (if std feature enabled)
    #[cfg(feature = "std")]
    pub timestamp: std::time::SystemTime,
}

/// Global metrics collector (only in std mode for simplicity)
#[cfg(feature = "std")]
pub mod collector {
    use super::*;
    use std::sync::Mutex;
    use std::collections::VecDeque;
    
    lazy_static::lazy_static! {
        static ref METRICS: Mutex<MetricsCollector> = Mutex::new(MetricsCollector::new());
    }
    
    /// Metrics collector with rolling window
    pub struct MetricsCollector {
        /// Recent signature metrics (last 1000)
        recent_metrics: VecDeque<SignatureMetrics>,
        /// Statistics
        total_signatures: u64,
        failed_original_threshold: u64,
        failed_temporary_threshold: u64,
        max_error_seen: i64,
        min_error_seen: i64,
        sum_errors: i128,
    }
    
    impl MetricsCollector {
        fn new() -> Self {
            Self {
                recent_metrics: VecDeque::with_capacity(1000),
                total_signatures: 0,
                failed_original_threshold: 0,
                failed_temporary_threshold: 0,
                max_error_seen: 0,
                min_error_seen: i64::MAX,
                sum_errors: 0,
            }
        }
        
        /// Add a new metric
        pub fn add_metric(metric: SignatureMetrics) {
            let mut collector = METRICS.lock().unwrap();
            
            // Update statistics
            collector.total_signatures += 1;
            collector.sum_errors += metric.equation_error as i128;
            collector.max_error_seen = collector.max_error_seen.max(metric.equation_error);
            collector.min_error_seen = collector.min_error_seen.min(metric.equation_error);
            
            // Check thresholds
            let original_threshold = (N as i64 * Q as i64) / 4;  // 1,572,992
            let temporary_threshold = (N as i64 * Q as i64) / 2; // 3,145,984
            
            if metric.equation_error > original_threshold {
                collector.failed_original_threshold += 1;
            }
            if metric.equation_error > temporary_threshold {
                collector.failed_temporary_threshold += 1;
            }
            
            // Keep rolling window
            if collector.recent_metrics.len() >= 1000 {
                collector.recent_metrics.pop_front();
            }
            collector.recent_metrics.push_back(metric);
        }
        
        /// Get current statistics
        pub fn get_stats() -> MetricsStats {
            let collector = METRICS.lock().unwrap();
            
            let avg_error = if collector.total_signatures > 0 {
                (collector.sum_errors / collector.total_signatures as i128) as i64
            } else {
                0
            };
            
            let original_failure_rate = if collector.total_signatures > 0 {
                (collector.failed_original_threshold as f64 / collector.total_signatures as f64) * 100.0
            } else {
                0.0
            };
            
            let temporary_failure_rate = if collector.total_signatures > 0 {
                (collector.failed_temporary_threshold as f64 / collector.total_signatures as f64) * 100.0
            } else {
                0.0
            };
            
            // Calculate error distribution
            let mut error_buckets = vec![0u32; 10];
            for metric in &collector.recent_metrics {
                let bucket = match metric.equation_error {
                    e if e < 100_000 => 0,
                    e if e < 500_000 => 1,
                    e if e < 1_000_000 => 2,
                    e if e < 1_500_000 => 3,
                    e if e < 1_572_992 => 4,  // Original threshold
                    e if e < 2_000_000 => 5,
                    e if e < 2_500_000 => 6,
                    e if e < 3_000_000 => 7,
                    e if e < 3_145_984 => 8,  // Temporary threshold
                    _ => 9,
                };
                error_buckets[bucket] += 1;
            }
            
            MetricsStats {
                total_signatures: collector.total_signatures,
                average_error: avg_error,
                max_error: collector.max_error_seen,
                min_error: collector.min_error_seen,
                original_failure_rate,
                temporary_failure_rate,
                error_distribution: error_buckets,
            }
        }
        
        /// Clear all metrics
        pub fn clear() {
            let mut collector = METRICS.lock().unwrap();
            *collector = MetricsCollector::new();
        }
    }
    
    /// Statistics from collected metrics
    #[derive(Debug, Clone)]
    pub struct MetricsStats {
        pub total_signatures: u64,
        pub average_error: i64,
        pub max_error: i64,
        pub min_error: i64,
        pub original_failure_rate: f64,
        pub temporary_failure_rate: f64,
        pub error_distribution: Vec<u32>,
    }
    
    /// Public API for adding metrics
    pub fn record_signature(
        equation_error: i64,
        norm_squared: i64,
        sampler_used: &str,
        verification_result: bool,
    ) {
        let metric = SignatureMetrics {
            equation_error,
            norm_squared,
            sampler_used: sampler_used.to_string(),
            verification_result,
            timestamp: std::time::SystemTime::now(),
        };
        MetricsCollector::add_metric(metric);
    }
    
    /// Public API for getting stats
    pub fn get_statistics() -> MetricsStats {
        MetricsCollector::get_stats()
    }
    
    /// Public API for printing report
    pub fn print_report() {
        let stats = get_statistics();
        
        eprintln!("\n=== Falcon-512 Precision Monitoring Report ===");
        eprintln!("Total signatures: {}", stats.total_signatures);
        eprintln!("Average equation error: {}", stats.average_error);
        eprintln!("Max error seen: {}", stats.max_error);
        eprintln!("Min error seen: {}", stats.min_error);
        eprintln!();
        eprintln!("Failure rates:");
        eprintln!("  Original threshold (25%): {:.2}%", stats.original_failure_rate);
        eprintln!("  Temporary threshold (50%): {:.2}%", stats.temporary_failure_rate);
        eprintln!();
        eprintln!("Error distribution (last 1000 signatures):");
        eprintln!("  < 100K:     {} signatures", stats.error_distribution[0]);
        eprintln!("  100K-500K:  {} signatures", stats.error_distribution[1]);
        eprintln!("  500K-1M:    {} signatures", stats.error_distribution[2]);
        eprintln!("  1M-1.5M:    {} signatures", stats.error_distribution[3]);
        eprintln!("  1.5M-1.57M: {} signatures", stats.error_distribution[4]);
        eprintln!("  1.57M-2M:   {} signatures (would fail original)", stats.error_distribution[5]);
        eprintln!("  2M-2.5M:    {} signatures (would fail original)", stats.error_distribution[6]);
        eprintln!("  2.5M-3M:    {} signatures (would fail original)", stats.error_distribution[7]);
        eprintln!("  3M-3.15M:   {} signatures (would fail original)", stats.error_distribution[8]);
        eprintln!("  > 3.15M:    {} signatures (fails even temporary)", stats.error_distribution[9]);
        eprintln!("===============================================\n");
    }
}

/// Calculate equation error for monitoring
pub fn calculate_equation_error(
    s0: &[i16],
    s1: &[i16], 
    h: &[i16],
    c: &[i16]
) -> i64 {
    // Compute s1*h using NTT
    let s1h = crate::ntt_falcon::multiply_ntt(s1, h);
    let mut error = 0i64;
    
    for i in 0..N {
        // Compute s0 + s1*h mod q
        let lhs = ((s0[i] as i32 + s1h[i] as i32) % Q as i32 + Q as i32) % Q as i32;
        let rhs = (c[i] as i32 + Q as i32) % Q as i32;
        
        // Compute minimum distance considering modular wrap-around
        let diff = (lhs - rhs).abs();
        let wrap_diff = (Q as i32 - diff).min(diff);
        error += wrap_diff as i64;
    }
    
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(feature = "std")]
    fn test_metrics_collection() {
        use super::collector;
        
        // Clear any existing metrics
        collector::MetricsCollector::clear();
        
        // Add some test metrics
        collector::record_signature(1_000_000, 5000, "reference", true);  // Passes both
        collector::record_signature(1_600_000, 5100, "tree", true);       // Fails original, passes temp
        collector::record_signature(3_200_000, 5200, "hybrid", false);    // Fails both
        
        let stats = collector::get_statistics();
        assert_eq!(stats.total_signatures, 3);
        // 2 of 3 fail original threshold (66.67%)
        assert!(stats.original_failure_rate > 66.0 && stats.original_failure_rate < 67.0,
               "Original failure rate was {}", stats.original_failure_rate);
        // 1 of 3 fails temporary threshold (33.33%)
        assert!(stats.temporary_failure_rate > 33.0 && stats.temporary_failure_rate < 34.0,
               "Temporary failure rate was {}", stats.temporary_failure_rate);
        
        // Print report for visual inspection
        collector::print_report();
    }
    
    #[test]
    fn test_equation_error_calculation() {
        // Create simple test case where s0 + s1*h = c is satisfied
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        let mut h = vec![0i16; N];
        let mut c = vec![0i16; N];
        
        // Simple case: s0[0] = 1, s1[0] = 2, h[0] = 3
        // c[0] should be 1 + 2*3 = 7 mod Q
        s0[0] = 1;
        s1[0] = 2;
        h[0] = 3;
        c[0] = 7;
        
        let error = calculate_equation_error(&s0, &s1, &h, &c);
        // For this simple case the error should be very small
        assert!(error < Q as i64, "Error {} should be less than Q={}", error, Q);
    }
}