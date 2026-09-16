// MetaMUI Falcon - SIMD Dispatch Performance Benchmarks
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarks for each SIMD tier: Portable, NEON, AVX2, AVX-512, Metal GPU

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_falcon512::dispatch;
use rand::SeedableRng;
use rand::rngs::StdRng;

// ================================================================
// Helper: generate random f64 polynomial data
// ================================================================

fn random_poly(n: usize, seed: u64) -> Vec<f64> {
    let mut rng = StdRng::seed_from_u64(seed);
    use rand::Rng;
    (0..n).map(|_| rng.gen_range(-100.0..100.0)).collect()
}

// ================================================================
// FFT Domain Operations (polynomial-level, SIMD dispatched)
// ================================================================

fn bench_poly_add_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_add_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let a = random_poly(n, 100 + logn as u64);
        let b = random_poly(n, 200 + logn as u64);
        let mut out = vec![0.0f64; n];

        let label = format!("n={}", n);
        group.bench_function(&label, |bench| {
            bench.iter(|| {
                dispatch::poly_add_fft(black_box(&mut out), &a, &b, logn as usize);
            });
        });
    }
    group.finish();
}

fn bench_poly_sub_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_sub_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let a = random_poly(n, 300 + logn as u64);
        let b = random_poly(n, 400 + logn as u64);
        let mut out = vec![0.0f64; n];

        let label = format!("n={}", n);
        group.bench_function(&label, |bench| {
            bench.iter(|| {
                dispatch::poly_sub_fft(black_box(&mut out), &a, &b, logn as usize);
            });
        });
    }
    group.finish();
}

fn bench_poly_mul_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_mul_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let a = random_poly(n, 500 + logn as u64);
        let b = random_poly(n, 600 + logn as u64);
        let mut out = vec![0.0f64; n];

        let label = format!("n={}", n);
        group.bench_function(&label, |bench| {
            bench.iter(|| {
                dispatch::poly_mul_fft(black_box(&mut out), &a, &b, logn as usize);
            });
        });
    }
    group.finish();
}

fn bench_poly_muladd_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_muladd_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let a = random_poly(n, 700 + logn as u64);
        let b = random_poly(n, 800 + logn as u64);
        let acc = random_poly(n, 900 + logn as u64);
        let mut out = vec![0.0f64; n];

        let label = format!("n={}", n);
        group.bench_function(&label, |bench| {
            bench.iter(|| {
                dispatch::poly_muladd_fft(black_box(&mut out), &a, &b, &acc, logn as usize);
            });
        });
    }
    group.finish();
}

fn bench_poly_mulsub_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_mulsub_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let a = random_poly(n, 1000 + logn as u64);
        let b = random_poly(n, 1100 + logn as u64);
        let acc = random_poly(n, 1200 + logn as u64);
        let mut out = vec![0.0f64; n];

        let label = format!("n={}", n);
        group.bench_function(&label, |bench| {
            bench.iter(|| {
                dispatch::poly_mulsub_fft(black_box(&mut out), &a, &b, &acc, logn as usize);
            });
        });
    }
    group.finish();
}

fn bench_poly_split_merge_fft(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/poly_split_merge_fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let hn = n >> 1;
        let f = random_poly(n, 1300 + logn as u64);
        let mut f0 = vec![0.0f64; hn];
        let mut f1 = vec![0.0f64; hn];
        let mut merged = vec![0.0f64; n];

        group.bench_function(format!("split_n={}", n), |bench| {
            bench.iter(|| {
                dispatch::poly_split_fft(black_box(&mut f0), &mut f1, &f, logn as usize);
            });
        });

        // Pre-split for merge benchmark
        dispatch::poly_split_fft(&mut f0, &mut f1, &f, logn as usize);

        group.bench_function(format!("merge_n={}", n), |bench| {
            bench.iter(|| {
                dispatch::poly_merge_fft(black_box(&mut merged), &f0, &f1, logn as usize);
            });
        });
    }
    group.finish();
}

// ================================================================
// FFT Forward / Inverse (full O(n log n) butterfly)
// ================================================================

fn bench_fft_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/fft");

    for logn in [9u32, 10] {
        let n = 1usize << logn;
        let original = random_poly(n, 1400 + logn as u64);

        group.bench_function(format!("forward_n={}", n), |bench| {
            bench.iter(|| {
                let mut f = original.clone();
                dispatch::fft_forward(black_box(&mut f), logn as usize);
            });
        });

        // Pre-transform for inverse benchmark
        let mut fft_data = original.clone();
        dispatch::fft_forward(&mut fft_data, logn as usize);

        group.bench_function(format!("inverse_n={}", n), |bench| {
            bench.iter(|| {
                let mut f = fft_data.clone();
                dispatch::fft_inverse(black_box(&mut f), logn as usize);
            });
        });

        group.bench_function(format!("roundtrip_n={}", n), |bench| {
            bench.iter(|| {
                let mut f = original.clone();
                dispatch::fft_forward(&mut f, logn as usize);
                dispatch::fft_inverse(black_box(&mut f), logn as usize);
            });
        });
    }
    group.finish();
}

// ================================================================
// NTT polynomial multiplication (negacyclic convolution)
// ================================================================

fn bench_ntt_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt/multiply");

    for n in [512usize, 1024] {
        let mut rng = StdRng::seed_from_u64(1500 + n as u64);
        use rand::Rng;
        let a: Vec<i16> = (0..n).map(|_| rng.gen_range(-100..100)).collect();
        let b: Vec<i16> = (0..n).map(|_| rng.gen_range(-100..100)).collect();

        group.bench_function(format!("n={}", n), |bench| {
            bench.iter(|| {
                let result = metamui_falcon512::ntt_falcon::multiply_ntt(
                    black_box(&a), black_box(&b),
                );
                black_box(result);
            });
        });
    }
    group.finish();
}

// ================================================================
// Full sign + verify pipeline
// ================================================================

fn bench_sign_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");
    group.sample_size(20); // Signing is slow; fewer samples

    let mut rng = StdRng::seed_from_u64(42);
    let keypair = metamui_falcon512::generate_keypair(&mut rng)
        .expect("keygen should succeed");

    let message = b"Benchmark message for Falcon-512 SIMD dispatch pipeline";

    group.bench_function("sign", |bench| {
        let mut rng = StdRng::seed_from_u64(100);
        bench.iter(|| {
            let sig = metamui_falcon512::sign(
                black_box(message), &keypair.private_key, &mut rng,
            ).expect("sign should succeed");
            black_box(sig);
        });
    });

    let signature = metamui_falcon512::sign(message, &keypair.private_key, &mut rng)
        .expect("sign should succeed");

    group.bench_function("verify", |bench| {
        bench.iter(|| {
            let valid = metamui_falcon512::verify(
                black_box(message), black_box(&signature), &keypair.public_key,
            ).expect("verify should succeed");
            black_box(valid);
        });
    });

    group.finish();
}

// ================================================================
// Dispatch detection overhead
// ================================================================

fn bench_dispatch_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch/overhead");

    group.bench_function("detect_best", |bench| {
        bench.iter(|| {
            black_box(dispatch::detect_best());
        });
    });

    group.bench_function("detect_best_for_batch", |bench| {
        bench.iter(|| {
            black_box(dispatch::detect_best_for_batch(black_box(200)));
        });
    });

    group.bench_function("is_metal_available", |bench| {
        bench.iter(|| {
            black_box(dispatch::is_metal_available());
        });
    });

    group.finish();
}

// ================================================================
// Batch verification (CPU path)
// ================================================================

fn bench_batch_verify_cpu(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch/verify_cpu");
    group.sample_size(10);

    let mut rng = StdRng::seed_from_u64(42);
    let keypair = metamui_falcon512::generate_keypair(&mut rng)
        .expect("keygen should succeed");

    // Pre-generate signatures
    for batch_size in [1, 10, 50] {
        let messages: Vec<Vec<u8>> = (0..batch_size).map(|i| {
            format!("Batch verify benchmark message #{}", i).into_bytes()
        }).collect();

        let signatures: Vec<Vec<u8>> = messages.iter().map(|msg| {
            metamui_falcon512::sign(msg, &keypair.private_key, &mut rng)
                .expect("sign should succeed")
        }).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &(messages, signatures),
            |bench, (msgs, sigs)| {
                bench.iter(|| {
                    let valid: Vec<bool> = msgs.iter().zip(sigs.iter()).map(|(msg, sig)| {
                        metamui_falcon512::verify(msg, sig, &keypair.public_key)
                            .unwrap_or(false)
                    }).collect();
                    black_box(valid);
                });
            },
        );
    }
    group.finish();
}

// ================================================================
// Criterion configuration
// ================================================================

criterion_group!(
    simd_benches,
    bench_poly_add_fft,
    bench_poly_sub_fft,
    bench_poly_mul_fft,
    bench_poly_muladd_fft,
    bench_poly_mulsub_fft,
    bench_poly_split_merge_fft,
    bench_fft_roundtrip,
    bench_ntt_multiply,
    bench_sign_verify,
    bench_dispatch_overhead,
    bench_batch_verify_cpu,
);

criterion_main!(simd_benches);
