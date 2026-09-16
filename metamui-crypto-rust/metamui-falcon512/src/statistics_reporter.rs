//! Statistical reporting for Falcon-512 metrics
//! 
//! This module generates reports from collected precision monitoring data.

use crate::constants::{N, Q};
#[cfg(feature = "std")]
use crate::error::{Falcon512Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Statistical report of signature verification metrics
#[derive(Clone, Debug)]
pub struct StatisticalReport {
    /// Total signatures analyzed
    pub total_signatures: u64,
    
    /// Signatures that failed original threshold
    pub failed_original: u64,
    
    /// Signatures that failed relaxed threshold
    pub failed_relaxed: u64,
    
    /// Average equation error
    pub avg_error: f64,
    
    /// Maximum error seen
    pub max_error: i64,
    
    /// Minimum error seen
    pub min_error: i64,
    
    /// Standard deviation of errors
    pub std_deviation: f64,
    
    /// Error percentiles
    pub percentiles: ErrorPercentiles,
    
    /// Error distribution histogram
    pub distribution: Vec<(String, u64)>,
    
    /// Success rate with original threshold
    pub success_rate_original: f64,
    
    /// Success rate with relaxed threshold
    pub success_rate_relaxed: f64,
}

/// Error percentiles for analysis
#[derive(Clone, Debug)]
pub struct ErrorPercentiles {
    pub p50: i64,  // Median
    pub p75: i64,
    pub p90: i64,
    pub p95: i64,
    pub p99: i64,
}

impl StatisticalReport {
    /// Generate a text report
    pub fn to_text(&self) -> String {
        let mut report = String::new();
        
        report.push_str("=== Falcon-512 Statistical Report ===\n\n");
        
        report.push_str(&format!("Total Signatures Analyzed: {}\n", self.total_signatures));
        report.push_str(&format!("Failed Original Threshold: {} ({:.2}%)\n", 
                                self.failed_original, 
                                (self.failed_original as f64 / self.total_signatures as f64) * 100.0));
        report.push_str(&format!("Failed Relaxed Threshold: {} ({:.2}%)\n", 
                                self.failed_relaxed,
                                (self.failed_relaxed as f64 / self.total_signatures as f64) * 100.0));
        
        report.push_str("\n--- Error Statistics ---\n");
        report.push_str(&format!("Average Error: {:.0}\n", self.avg_error));
        report.push_str(&format!("Min Error: {}\n", self.min_error));
        report.push_str(&format!("Max Error: {}\n", self.max_error));
        report.push_str(&format!("Std Deviation: {:.2}\n", self.std_deviation));
        
        report.push_str("\n--- Error Percentiles ---\n");
        report.push_str(&format!("50th (Median): {}\n", self.percentiles.p50));
        report.push_str(&format!("75th: {}\n", self.percentiles.p75));
        report.push_str(&format!("90th: {}\n", self.percentiles.p90));
        report.push_str(&format!("95th: {}\n", self.percentiles.p95));
        report.push_str(&format!("99th: {}\n", self.percentiles.p99));
        
        report.push_str("\n--- Success Rates ---\n");
        report.push_str(&format!("Original Threshold (25%): {:.2}%\n", self.success_rate_original * 100.0));
        report.push_str(&format!("Relaxed Threshold (50%): {:.2}%\n", self.success_rate_relaxed * 100.0));
        
        report.push_str("\n--- Error Distribution ---\n");
        for (range, count) in &self.distribution {
            let percentage = (*count as f64 / self.total_signatures as f64) * 100.0;
            report.push_str(&format!("{}: {} ({:.2}%)\n", range, count, percentage));
        }
        
        report.push_str("\n--- Threshold Analysis ---\n");
        let original_threshold = (N as i64 * Q as i64) / 4;
        let relaxed_threshold = (N as i64 * Q as i64) / 2;
        report.push_str(&format!("Original Threshold: {} (25% of max)\n", original_threshold));
        report.push_str(&format!("Relaxed Threshold: {} (50% of max)\n", relaxed_threshold));
        report.push_str(&format!("Recommended Threshold (95th percentile): {}\n", self.percentiles.p95));
        
        if self.percentiles.p95 < original_threshold {
            report.push_str("✓ Original threshold would work for 95% of signatures\n");
        } else if self.percentiles.p95 < relaxed_threshold {
            report.push_str("⚠ Relaxed threshold needed for 95% success rate\n");
        } else {
            report.push_str("✗ Even relaxed threshold insufficient for 95% success\n");
        }
        
        report
    }
    
    /// Generate a CSV report
    pub fn to_csv(&self) -> String {
        let mut csv = String::new();
        
        csv.push_str("Metric,Value\n");
        csv.push_str(&format!("Total Signatures,{}\n", self.total_signatures));
        csv.push_str(&format!("Failed Original,{}\n", self.failed_original));
        csv.push_str(&format!("Failed Relaxed,{}\n", self.failed_relaxed));
        csv.push_str(&format!("Average Error,{:.0}\n", self.avg_error));
        csv.push_str(&format!("Min Error,{}\n", self.min_error));
        csv.push_str(&format!("Max Error,{}\n", self.max_error));
        csv.push_str(&format!("Std Deviation,{:.2}\n", self.std_deviation));
        csv.push_str(&format!("P50,{}\n", self.percentiles.p50));
        csv.push_str(&format!("P75,{}\n", self.percentiles.p75));
        csv.push_str(&format!("P90,{}\n", self.percentiles.p90));
        csv.push_str(&format!("P95,{}\n", self.percentiles.p95));
        csv.push_str(&format!("P99,{}\n", self.percentiles.p99));
        csv.push_str(&format!("Success Rate Original,{:.4}\n", self.success_rate_original));
        csv.push_str(&format!("Success Rate Relaxed,{:.4}\n", self.success_rate_relaxed));
        
        csv
    }
}

/// Generate a statistical report from collected metrics
#[cfg(feature = "std")]
pub fn generate_report() -> Result<StatisticalReport> {
    Err(Falcon512Error::NotImplemented)
}

/// Calculate standard deviation (simplified)
#[cfg(feature = "std")]
fn calculate_std_deviation(stats: &crate::precision_monitor::collector::MetricsStats) -> f64 {
    // Simplified calculation - would need variance tracking for accurate result
    // Estimate as 25% of range
    let range = (stats.max_error - stats.min_error) as f64;
    range * 0.25
}

/// Generate and print a report to stderr
#[cfg(feature = "std")]
pub fn print_report() -> Result<()> {
    let report = generate_report()?;
    eprintln!("{}", report.to_text());
    Ok(())
}

/// Generate and save reports to files
#[cfg(feature = "std")]
pub fn save_reports(_base_path: &str) -> Result<()> {
    Err(Falcon512Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_report_generation() {
        let report = StatisticalReport {
            total_signatures: 1000,
            failed_original: 50,
            failed_relaxed: 10,
            avg_error: 1000000.0,
            max_error: 3000000,
            min_error: 100000,
            std_deviation: 500000.0,
            percentiles: ErrorPercentiles {
                p50: 900000,
                p75: 1200000,
                p90: 1800000,
                p95: 2400000,
                p99: 2900000,
            },
            distribution: vec![
                ("0-500000".to_string(), 100),
                ("500000-1000000".to_string(), 400),
                ("1000000-2000000".to_string(), 400),
                ("2000000+".to_string(), 100),
            ],
            success_rate_original: 0.95,
            success_rate_relaxed: 0.99,
        };
        
        let text = report.to_text();
        assert!(text.contains("Total Signatures Analyzed: 1000"));
        assert!(text.contains("Original Threshold"));
        
        let csv = report.to_csv();
        assert!(csv.contains("Total Signatures,1000"));
        assert!(csv.contains("P95,2400000"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_generate_report_fails_closed_without_real_metrics_distribution() {
        assert!(matches!(
            generate_report(),
            Err(Falcon512Error::NotImplemented)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_print_report_fails_closed_without_real_metrics_distribution() {
        assert!(matches!(
            print_report(),
            Err(Falcon512Error::NotImplemented)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_save_reports_fails_closed_without_real_metrics_distribution() {
        assert!(matches!(
            save_reports("unused"),
            Err(Falcon512Error::NotImplemented)
        ));
    }
}
