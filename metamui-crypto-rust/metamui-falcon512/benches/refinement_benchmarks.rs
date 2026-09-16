use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_falcon512::{generate_keypair, sign, verify, verify_with_config};
use metamui_falcon512::verification_config::VerificationConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn benchmark_verification_configs(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(12345);
    let keypair = generate_keypair(&mut rng).expect("Key generation failed");
    
    let message = b"Benchmark message for performance testing of Falcon-512 verification with different configurations";
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing failed");
    
    let mut group = c.benchmark_group("verification_configs");
    
    // Benchmark default verification (no refinement)
    group.bench_function("default", |b| {
        b.iter(|| {
            verify(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key)
            )
        })
    });
    
    // Benchmark fast config (explicitly disabled refinement)
    let fast_config = VerificationConfig::fast();
    group.bench_function("fast", |b| {
        b.iter(|| {
            verify_with_config(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key),
                black_box(&fast_config)
            )
        })
    });
    
    // Benchmark with Babai only
    let babai_config = VerificationConfig {
        use_babai: true,
        use_iterative: false,
        ..Default::default()
    };
    group.bench_function("babai_only", |b| {
        b.iter(|| {
            verify_with_config(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key),
                black_box(&babai_config)
            )
        })
    });
    
    // Benchmark with iterative only
    let iterative_config = VerificationConfig {
        use_babai: false,
        use_iterative: true,
        ..Default::default()
    };
    group.bench_function("iterative_only", |b| {
        b.iter(|| {
            verify_with_config(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key),
                black_box(&iterative_config)
            )
        })
    });
    
    // Benchmark with both refinements
    let both_config = VerificationConfig::with_refinements();
    group.bench_function("both_refinements", |b| {
        b.iter(|| {
            verify_with_config(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key),
                black_box(&both_config)
            )
        })
    });
    
    // Benchmark accurate config (maximum refinement)
    let accurate_config = VerificationConfig::accurate();
    group.bench_function("accurate", |b| {
        b.iter(|| {
            verify_with_config(
                black_box(message),
                black_box(&signature),
                black_box(&keypair.public_key),
                black_box(&accurate_config)
            )
        })
    });
    
    group.finish();
}

fn benchmark_refinement_iterations(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(67890);
    let keypair = generate_keypair(&mut rng).expect("Key generation failed");
    
    let message = b"Testing different iteration counts for refinement algorithms";
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing failed");
    
    let mut group = c.benchmark_group("refinement_iterations");
    
    // Benchmark different Babai iteration counts
    for iterations in [1, 5, 10, 20, 50].iter() {
        let config = VerificationConfig {
            use_babai: true,
            use_iterative: false,
            babai_max_iterations: *iterations,
            ..Default::default()
        };
        
        group.bench_with_input(
            BenchmarkId::new("babai", iterations),
            iterations,
            |b, _| {
                b.iter(|| {
                    verify_with_config(
                        black_box(message),
                        black_box(&signature),
                        black_box(&keypair.public_key),
                        black_box(&config)
                    )
                })
            }
        );
    }
    
    // Benchmark different iterative refinement iteration counts
    for iterations in [10, 20, 50, 100].iter() {
        let mut config = VerificationConfig {
            use_babai: false,
            use_iterative: true,
            ..Default::default()
        };
        config.iterative_config.max_iterations = *iterations;
        
        group.bench_with_input(
            BenchmarkId::new("iterative", iterations),
            iterations,
            |b, _| {
                b.iter(|| {
                    verify_with_config(
                        black_box(message),
                        black_box(&signature),
                        black_box(&keypair.public_key),
                        black_box(&config)
                    )
                })
            }
        );
    }
    
    group.finish();
}

fn benchmark_message_sizes(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(54321);
    let keypair = generate_keypair(&mut rng).expect("Key generation failed");
    
    let mut group = c.benchmark_group("message_sizes");
    
    // Test different message sizes
    let sizes = vec![16, 64, 256, 1024, 4096];
    
    for size in sizes {
        let message = vec![0x42u8; size];
        let signature = sign(&message, &keypair.private_key, &mut rng).expect("Signing failed");
        
        // Benchmark without refinement
        group.bench_with_input(
            BenchmarkId::new("no_refinement", size),
            &size,
            |b, _| {
                b.iter(|| {
                    verify(
                        black_box(&message),
                        black_box(&signature),
                        black_box(&keypair.public_key)
                    )
                })
            }
        );
        
        // Benchmark with refinement
        let config = VerificationConfig::with_refinements();
        group.bench_with_input(
            BenchmarkId::new("with_refinement", size),
            &size,
            |b, _| {
                b.iter(|| {
                    verify_with_config(
                        black_box(&message),
                        black_box(&signature),
                        black_box(&keypair.public_key),
                        black_box(&config)
                    )
                })
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_verification_configs,
    benchmark_refinement_iterations,
    benchmark_message_sizes
);
criterion_main!(benches);