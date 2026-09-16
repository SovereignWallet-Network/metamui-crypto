use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_keygen");
    
    group.bench_function("generate_keypair", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        b.iter(|| {
            let _keypair = generate_keypair(&mut rng).unwrap();
        });
    });
    
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_sign");
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).unwrap();
    
    // Test different message sizes
    let message_sizes = [32, 64, 128, 256, 512, 1024];
    
    for size in &message_sizes {
        let message = vec![0u8; *size];
        group.bench_with_input(
            BenchmarkId::new("message_size", size),
            &message,
            |b, msg| {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                b.iter(|| {
                    let _sig = sign(black_box(msg), &keypair.private_key, &mut rng).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_verify");
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).unwrap();
    
    // Test different message sizes
    let message_sizes = [32, 64, 128, 256, 512, 1024];
    
    for size in &message_sizes {
        let message = vec![0u8; *size];
        let signature = sign(&message, &keypair.private_key, &mut rng).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("message_size", size),
            &(message, signature),
            |b, (msg, sig)| {
                b.iter(|| {
                    let _valid = verify(black_box(msg), black_box(sig), &keypair.public_key);
                });
            },
        );
    }
    
    group.finish();
}

fn bench_ntt(c: &mut Criterion) {
    use metamui_falcon512::ntt_negacyclic::NegacyclicNTT;
    use metamui_falcon512::poly::Poly;
    use metamui_falcon512::constants::N;
    
    let mut group = c.benchmark_group("falcon512_ntt");
    
    group.bench_function("forward_ntt", |b| {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = 1;
        }
        b.iter(|| {
            NegacyclicNTT::forward(black_box(&poly));
        });
    });
    
    group.bench_function("inverse_ntt", |b| {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = 1;
        }
        let ntt = NegacyclicNTT::forward(&poly);
        b.iter(|| {
            NegacyclicNTT::inverse(black_box(&ntt));
        });
    });
    
    group.finish();
}

#[cfg(any(
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "sse2")),
    all(target_arch = "aarch64", target_feature = "neon")
))]
fn bench_simd_ntt(c: &mut Criterion) {
    use metamui_falcon512::simd_ntt::SimdNegacyclicNTT;
    use metamui_falcon512::poly::Poly;
    use metamui_falcon512::constants::N;
    
    let mut group = c.benchmark_group("falcon512_simd_ntt");
    
    group.bench_function("simd_forward_ntt", |b| {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = 1;
        }
        b.iter(|| {
            SimdNegacyclicNTT::forward(black_box(&poly));
        });
    });
    
    group.bench_function("simd_inverse_ntt", |b| {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = 1;
        }
        let ntt = SimdNegacyclicNTT::forward(&poly);
        b.iter(|| {
            SimdNegacyclicNTT::inverse(black_box(&ntt));
        });
    });
    
    group.finish();
}

fn bench_modular_arithmetic(c: &mut Criterion) {
    use metamui_falcon512::mod_arith::ModArith;
    
    let mut group = c.benchmark_group("falcon512_mod_arith");
    
    group.bench_function("barrett_reduce", |b| {
        let values: Vec<u32> = (0..1000).map(|i| i * 12289).collect();
        b.iter(|| {
            for &val in &values {
                let _ = ModArith::barrett_reduce(black_box(val));
            }
        });
    });
    
    group.bench_function("mul_mod_barrett", |b| {
        let pairs: Vec<(u16, u16)> = (0..1000).map(|i| ((i % 12289) as u16, ((i * 7) % 12289) as u16)).collect();
        b.iter(|| {
            for &(a, b) in &pairs {
                let _ = ModArith::mul_mod_barrett(black_box(a), black_box(b));
            }
        });
    });
    
    group.bench_function("mont_mul", |b| {
        let pairs: Vec<(u16, u16)> = (0..1000).map(|i| ((i % 12289) as u16, ((i * 7) % 12289) as u16)).collect();
        b.iter(|| {
            for &(a, b) in &pairs {
                let _ = ModArith::mont_mul(black_box(a), black_box(b));
            }
        });
    });
    
    group.finish();
}

// Configure benchmarks
criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_ntt,
    bench_modular_arithmetic
);

#[cfg(any(
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "sse2")),
    all(target_arch = "aarch64", target_feature = "neon")
))]
criterion_group!(
    simd_benches,
    bench_simd_ntt
);

#[cfg(not(any(
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "sse2")),
    all(target_arch = "aarch64", target_feature = "neon")
)))]
criterion_main!(benches);

#[cfg(any(
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "sse2")),
    all(target_arch = "aarch64", target_feature = "neon")
))]
criterion_main!(benches, simd_benches);