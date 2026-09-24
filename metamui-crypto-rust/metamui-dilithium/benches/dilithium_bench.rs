use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metamui_dilithium::{Dilithium2, Dilithium3, Dilithium5};

fn benchmark_dilithium2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium2");
    
    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium2::generate_keypair();
            black_box((pk, sk))
        });
    });
    
    // Signing
    let (_, sk) = Dilithium2::generate_keypair();
    let msg = b"Test message for benchmarking";
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = Dilithium2::sign(&sk, msg);
            black_box(sig)
        });
    });
    
    // Verification
    let (pk, sk) = Dilithium2::generate_keypair();
    let sig = Dilithium2::sign(&sk, msg);
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = Dilithium2::verify(&pk, msg, &sig);
            black_box(valid)
        });
    });
    
    group.finish();
}

fn benchmark_dilithium3(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium3");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium3::generate_keypair();
            black_box((pk, sk))
        });
    });
    
    let (_, sk) = Dilithium3::generate_keypair();
    let msg = b"Test message for benchmarking";
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = Dilithium3::sign(&sk, msg);
            black_box(sig)
        });
    });
    
    let (pk, sk) = Dilithium3::generate_keypair();
    let sig = Dilithium3::sign(&sk, msg);
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = Dilithium3::verify(&pk, msg, &sig);
            black_box(valid)
        });
    });
    
    group.finish();
}

fn benchmark_dilithium5(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium5");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (pk, sk) = Dilithium5::generate_keypair();
            black_box((pk, sk))
        });
    });
    
    let (_, sk) = Dilithium5::generate_keypair();
    let msg = b"Test message for benchmarking";
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = Dilithium5::sign(&sk, msg);
            black_box(sig)
        });
    });
    
    let (pk, sk) = Dilithium5::generate_keypair();
    let sig = Dilithium5::sign(&sk, msg);
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = Dilithium5::verify(&pk, msg, &sig);
            black_box(valid)
        });
    });
    
    group.finish();
}

// benchmark_ntt removed: the `ntt::ntt` / `ntt::intt` free functions
// were folded into internal polynomial helpers and are no longer part
// of the public API. The Dilithium2/3/5 keygen/sign/verify benches
// below still exercise the NTT path end-to-end.

fn benchmark_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Message Sizes");
    
    let (pk, sk) = Dilithium5::generate_keypair();
    let message_sizes = [32, 128, 512, 1024, 4096];
    
    for &size in &message_sizes {
        let msg = vec![0u8; size];
        
        group.bench_function(&format!("sign_{}_bytes", size), |b| {
            b.iter(|| {
                let sig = Dilithium5::sign(&sk, &msg);
                black_box(sig)
            });
        });
        
        let sig = Dilithium5::sign(&sk, &msg);
        group.bench_function(&format!("verify_{}_bytes", size), |b| {
            b.iter(|| {
                let valid = Dilithium5::verify(&pk, &msg, &sig);
                black_box(valid)
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_dilithium2,
    benchmark_dilithium3,
    benchmark_dilithium5,
    benchmark_message_sizes
);
criterion_main!(benches);