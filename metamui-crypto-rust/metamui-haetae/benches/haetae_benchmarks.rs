//! HAETAE Benchmark Suite
//!
//! Comprehensive benchmarks for HAETAE post-quantum signature scheme using
//! the canonical implementation with correct modulus (Q = 64513).
//!
//! This benchmark suite measures:
//! - Key generation performance
//! - Signing performance (various message sizes)
//! - Verification performance
//! - Key and signature sizes
//!
//! Run with:
//!   HAETAE-2: cargo bench --bench haetae_benchmarks --features haetae2
//!   HAETAE-3: cargo bench --bench haetae_benchmarks --no-default-features --features haetae3,std
//!   HAETAE-5: cargo bench --bench haetae_benchmarks --no-default-features --features haetae5,std

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_haetae::api::KeyPair;
use metamui_haetae::params::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES};

/// Security level name for benchmark labels
fn security_level_name() -> &'static str {
    #[cfg(feature = "haetae2")]
    return "HAETAE-2";

    #[cfg(feature = "haetae3")]
    return "HAETAE-3";

    #[cfg(feature = "haetae5")]
    return "HAETAE-5";

    #[cfg(not(any(feature = "haetae2", feature = "haetae3", feature = "haetae5")))]
    compile_error!("At least one security level must be enabled");
}

/// Benchmark key generation
fn bench_keygen(c: &mut Criterion) {
    let level = security_level_name();

    c.bench_function(&format!("{} keygen", level), |b| {
        b.iter(|| {
            let keypair = KeyPair::generate().expect("Keygen failed");
            black_box(keypair)
        })
    });
}

/// Benchmark signing with various message sizes
fn bench_sign(c: &mut Criterion) {
    let level = security_level_name();
    let keypair = KeyPair::generate().expect("Keygen failed");

    let message_sizes = vec![
        ("32B", 32),
        ("64B", 64),
        ("128B", 128),
        ("256B", 256),
        ("512B", 512),
        ("1KB", 1024),
        ("4KB", 4096),
        ("16KB", 16384),
    ];

    let mut group = c.benchmark_group(format!("{} sign", level));

    for (size_name, size) in message_sizes {
        let message = vec![0u8; size];

        group.bench_with_input(
            BenchmarkId::from_parameter(size_name),
            &message,
            |b, msg| {
                b.iter(|| {
                    let signature = keypair.sign(black_box(msg)).expect("Signing failed");
                    black_box(signature)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark verification with various message sizes
fn bench_verify(c: &mut Criterion) {
    let level = security_level_name();
    let keypair = KeyPair::generate().expect("Keygen failed");

    let message_sizes = vec![
        ("32B", 32),
        ("64B", 64),
        ("128B", 128),
        ("256B", 256),
        ("512B", 512),
        ("1KB", 1024),
        ("4KB", 4096),
        ("16KB", 16384),
    ];

    let mut group = c.benchmark_group(format!("{} verify", level));

    for (size_name, size) in message_sizes {
        let message = vec![0u8; size];
        let signature = keypair.sign(&message).expect("Signing failed");

        group.bench_with_input(
            BenchmarkId::from_parameter(size_name),
            &(&message, &signature),
            |b, (msg, sig)| {
                b.iter(|| {
                    let result = keypair.verifying_key().verify(black_box(msg), black_box(sig));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark full sign-verify cycle
fn bench_sign_verify_cycle(c: &mut Criterion) {
    let level = security_level_name();
    let message = b"Benchmark message for HAETAE sign-verify cycle";

    c.bench_function(&format!("{} sign+verify cycle", level), |b| {
        b.iter(|| {
            let keypair = KeyPair::generate().expect("Keygen failed");
            let signature = keypair.sign(black_box(message)).expect("Signing failed");
            let result = keypair.verifying_key().verify(black_box(message), black_box(&signature));
            black_box(result)
        })
    });
}

/// Report key and signature sizes
fn report_sizes(c: &mut Criterion) {
    let level = security_level_name();

    // Print sizes at runtime
    println!("\n=== {} Parameter Sizes ===", level);
    println!("Public Key:  {} bytes", CRYPTO_PUBLICKEYBYTES);
    println!("Secret Key:  {} bytes", CRYPTO_SECRETKEYBYTES);
    println!("Signature:   {} bytes", CRYPTO_BYTES);
    println!("Modulus Q:   64513 (correct HAETAE specification)");

    #[cfg(feature = "haetae2")]
    {
        println!("Security:    NIST Level 2 (128-bit)");
        println!("Parameters:  K=2, L=4");
    }

    #[cfg(feature = "haetae3")]
    {
        println!("Security:    NIST Level 3 (192-bit)");
        println!("Parameters:  K=3, L=6");
    }

    #[cfg(feature = "haetae5")]
    {
        println!("Security:    NIST Level 5 (256-bit)");
        println!("Parameters:  K=4, L=7");
    }

    println!("===============================\n");

    // Create a dummy benchmark so Criterion doesn't complain
    c.bench_function(&format!("{} sizes", level), |b| {
        b.iter(|| {
            black_box(CRYPTO_BYTES)
        })
    });
}

criterion_group!(
    benches,
    report_sizes,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_sign_verify_cycle,
);

criterion_main!(benches);
