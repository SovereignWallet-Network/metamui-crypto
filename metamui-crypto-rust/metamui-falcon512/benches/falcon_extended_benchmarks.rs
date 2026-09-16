use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metamui_falcon512::constants::N;
use metamui_falcon512::error::Falcon512Error;
use metamui_falcon512::extended_key::ExtendedPrivateKey;
use metamui_falcon512::poly::Poly;
use metamui_falcon512::sign_extended::verify_extended;
use metamui_falcon512::{generate_keypair, sign, verify, PublicKey};
use rand::rngs::OsRng;

fn benchmark_basic_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");
    let mut rng = OsRng;

    group.bench_function("basic", |b| {
        b.iter(|| {
            let keypair = generate_keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });

    group.finish();
}

fn benchmark_basic_sign_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_verify");
    let mut rng = OsRng;
    let keypair = generate_keypair(&mut rng).unwrap();
    let message = b"Benchmark test message for Falcon-512 signing operations";
    let signature = sign(message, &keypair.private_key, &mut rng).unwrap();

    group.bench_function("basic_sign", |b| {
        b.iter(|| {
            let sig = sign(message, &keypair.private_key, &mut rng).unwrap();
            black_box(sig);
        });
    });

    group.bench_function("basic_verify", |b| {
        b.iter(|| {
            let valid = verify(message, &signature, &keypair.public_key).unwrap();
            black_box(valid);
        });
    });

    group.finish();
}

fn benchmark_extended_phase0_fail_closed(c: &mut Criterion) {
    let mut group = c.benchmark_group("extended_phase0");
    let public_key = PublicKey { h: Poly::zero(N) };
    let zero_poly = Poly::zero(N);

    group.bench_function("extended_private_key_from_basic_err", |b| {
        b.iter(|| {
            let result = ExtendedPrivateKey::from_basic(
                zero_poly.clone(),
                zero_poly.clone(),
                zero_poly.clone(),
                zero_poly.clone(),
            );
            black_box(matches!(result, Err(Falcon512Error::NotImplemented)));
        });
    });

    group.bench_function("extended_verify_err", |b| {
        b.iter(|| {
            let result = verify_extended(b"message", &[0x39], &public_key);
            black_box(matches!(result, Err(Falcon512Error::NotImplemented)));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_basic_key_generation,
    benchmark_basic_sign_verify,
    benchmark_extended_phase0_fail_closed
);

criterion_main!(benches);
