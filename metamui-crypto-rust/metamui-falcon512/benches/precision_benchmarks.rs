//! Performance benchmarks for numerical precision improvements

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_falcon512::*;
use metamui_falcon512::fft_hybrid::{FFTMode, HybridFFT};
use metamui_falcon512::falcon_reference::extended_precision::*;
use metamui_falcon512::falcon_reference::basis_hybrid::HybridBasis;
use metamui_falcon512::poly::PolyF64;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

/// Benchmark FFT round-trip performance
fn bench_fft_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("FFT Modes");
    let mut rng = StdRng::seed_from_u64(42);
    
    // Create test polynomial
    let mut coeffs = vec![0.0; N];
    for i in 0..N {
        coeffs[i] = (rng.next_u32() % 1000) as f64 - 500.0;
    }
    let poly = PolyF64::new(coeffs);
    
    for mode in &[FFTMode::Native, FFTMode::Emulated, FFTMode::Hybrid] {
        group.bench_with_input(
            BenchmarkId::new("round_trip", format!("{:?}", mode)),
            mode,
            |b, &mode| {
                let fft = HybridFFT::new(mode);
                b.iter(|| {
                    let forward = fft.forward(&poly);
                    let inverse = fft.inverse(&forward);
                    black_box(inverse);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark Kahan summation vs regular summation
fn bench_summation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Summation");
    
    // Create test data with precision-sensitive values
    let mut values = Vec::new();
    for i in 0..1000 {
        if i % 2 == 0 {
            values.push(1e10);
        } else {
            values.push(1.0);
        }
    }
    // Add negative values to cancel out
    for i in 0..500 {
        values.push(-1e10);
    }
    
    group.bench_function("regular_sum", |b| {
        b.iter(|| {
            let sum: f64 = values.iter().sum();
            black_box(sum);
        });
    });
    
    group.bench_function("kahan_sum", |b| {
        b.iter(|| {
            let sum = kahan_sum(&values);
            black_box(sum);
        });
    });
    
    group.finish();
}

/// Benchmark extended precision accumulators
fn bench_accumulators(c: &mut Criterion) {
    let mut group = c.benchmark_group("Accumulators");
    let mut rng = StdRng::seed_from_u64(123);
    
    // Generate test values
    let mut values = Vec::new();
    for _ in 0..1000 {
        values.push((rng.next_u32() as f64) / 1000.0);
    }
    
    group.bench_function("accumulator_80", |b| {
        b.iter(|| {
            let mut acc = Accumulator80::zero();
            for &v in &values {
                acc.add(v);
            }
            black_box(acc.get_compensated());
        });
    });
    
    group.bench_function("accumulator_128", |b| {
        b.iter(|| {
            let mut acc = Accumulator128::zero();
            for &v in &values {
                acc.add(v);
            }
            black_box(acc.get());
        });
    });
    
    group.finish();
}

/// Benchmark basis operations with different FFT modes
fn bench_basis_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Basis Operations");
    let mut rng = StdRng::seed_from_u64(999);
    
    // Generate test keys
    if let Ok((f, g, big_f, big_g)) = metamui_falcon512::ntru_working::ntru_keygen_working(&mut rng) {
        for mode in &[FFTMode::Native, FFTMode::Hybrid] {
            group.bench_with_input(
                BenchmarkId::new("basis_creation", format!("{:?}", mode)),
                mode,
                |b, &mode| {
                    b.iter(|| {
                        let basis = HybridBasis::new(&f, &g, &big_f, &big_g, mode);
                        black_box(basis);
                    });
                },
            );
            
            // Create basis once for gram matrix benchmark
            if let Ok(basis) = HybridBasis::new(&f, &g, &big_f, &big_g, *mode) {
                group.bench_with_input(
                    BenchmarkId::new("gram_matrix", format!("{:?}", mode)),
                    mode,
                    |b, &mode| {
                        b.iter(|| {
                            let gram = basis.compute_gram_matrix(mode);
                            black_box(gram);
                        });
                    },
                );
            }
        }
    }
    
    group.finish();
}

/// Benchmark extended dot product
fn bench_dot_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dot Product");
    let mut rng = StdRng::seed_from_u64(456);
    
    // Create test vectors
    let mut a = vec![0.0; 512];
    let mut b = vec![0.0; 512];
    for i in 0..512 {
        a[i] = (rng.next_u32() as f64) / 1000000.0;
        b[i] = (rng.next_u32() as f64) / 1000000.0;
    }
    
    group.bench_function("regular_dot", |b| {
        b.iter(|| {
            let dot: f64 = a.iter().zip(b.iter())
                .map(|(x, y)| x * y)
                .sum();
            black_box(dot);
        });
    });
    
    group.bench_function("extended_dot", |b| {
        b.iter(|| {
            let dot = extended_dot_product(&a, &b);
            black_box(dot);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_fft_modes,
    bench_summation,
    bench_accumulators,
    bench_basis_operations,
    bench_dot_product
);
criterion_main!(benches);