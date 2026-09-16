//! Benchmarks for Falcon-512 implementation

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn benchmark_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_keygen");
    
    group.bench_function("generate_keypair", |b| {
        let mut rng = StdRng::seed_from_u64(42);
        b.iter(|| {
            let keypair = generate_keypair(&mut rng).expect("Key generation should work");
            black_box(keypair);
        });
    });
    
    group.finish();
}

fn benchmark_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_sign");
    
    let mut rng = StdRng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).expect("Key generation should work");
    
    for size in [0, 32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &message,
            |b, msg| {
                let mut rng = StdRng::seed_from_u64(42);
                b.iter(|| {
                    let sig = sign(msg, &keypair.private_key, &mut rng)
                        .expect("Signing should work");
                    black_box(sig);
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_verify");
    
    let mut rng = StdRng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).expect("Key generation should work");
    
    for size in [0, 32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0u8; *size];
        let signature = sign(&message, &keypair.private_key, &mut rng)
            .expect("Signing should work");
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(message.clone(), signature.clone()),
            |b, (msg, sig)| {
                b.iter(|| {
                    let valid = verify(msg, sig, &keypair.public_key)
                        .expect("Verification should work");
                    black_box(valid);
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_ntt(c: &mut Criterion) {
    use metamui_falcon512::constants::N;
    
    let mut group = c.benchmark_group("falcon512_ntt");
    
    group.bench_function("ntt_forward", |b| {
        let poly = vec![1i16; N];
        b.iter(|| {
            // Note: NTT functions would need to be made public for this
            // For now, this is a placeholder
            black_box(&poly);
        });
    });
    
    group.finish();
}

fn benchmark_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon512_memory");
    
    group.bench_function("keypair_size", |b| {
        let mut rng = StdRng::seed_from_u64(42);
        b.iter(|| {
            let keypair = generate_keypair(&mut rng).expect("Key generation should work");
            let pk_size = keypair.public_key.h.coeffs.len() * 2; // 2 bytes per coefficient
            let sk_size = keypair.private_key.f.coeffs.len() * 2 * 4; // 4 polynomials
            black_box((pk_size, sk_size));
        });
    });
    
    group.bench_function("signature_size", |b| {
        let mut rng = StdRng::seed_from_u64(42);
        let keypair = generate_keypair(&mut rng).expect("Key generation should work");
        let message = b"Test message";
        
        b.iter(|| {
            let sig = sign(message, &keypair.private_key, &mut rng)
                .expect("Signing should work");
            black_box(sig.len());
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_keygen,
    benchmark_sign,
    benchmark_verify,
    benchmark_ntt,
    benchmark_memory
);

criterion_main!(benches);