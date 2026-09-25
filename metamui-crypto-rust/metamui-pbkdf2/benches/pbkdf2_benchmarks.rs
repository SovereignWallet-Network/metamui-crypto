use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metamui_pbkdf2::PBKDF2;

fn benchmark_pbkdf2_sha256(c: &mut Criterion) {
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;
    let key_length = 32;
    
    c.bench_function("pbkdf2_sha256_4096", |b| {
        b.iter(|| {
            PBKDF2::pbkdf2_hmac_sha256(
                black_box(password),
                black_box(salt),
                black_box(iterations),
                black_box(key_length),
            )
        })
    });
}

fn benchmark_pbkdf2_sha512(c: &mut Criterion) {
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;
    let key_length = 64;
    
    c.bench_function("pbkdf2_sha512_4096", |b| {
        b.iter(|| {
            PBKDF2::pbkdf2_hmac_sha512(
                black_box(password),
                black_box(salt),
                black_box(iterations),
                black_box(key_length),
            )
        })
    });
}

fn benchmark_bip39_seed(c: &mut Criterion) {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    
    c.bench_function("bip39_mnemonic_to_seed", |b| {
        b.iter(|| {
            PBKDF2::bip39_mnemonic_to_seed(
                black_box(mnemonic),
                black_box(passphrase),
            )
        })
    });
}

fn benchmark_pbkdf2_iterations(c: &mut Criterion) {
    let password = b"password";
    let salt = b"salt";
    let key_length = 32;
    
    let mut group = c.benchmark_group("pbkdf2_sha256_iterations");
    
    for iterations in &[1000, 10000, 100000] {
        group.bench_with_input(
            format!("iterations_{}", iterations),
            iterations,
            |b, &iterations| {
                b.iter(|| {
                    PBKDF2::pbkdf2_hmac_sha256(
                        black_box(password),
                        black_box(salt),
                        black_box(iterations),
                        black_box(key_length),
                    )
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_pbkdf2_sha256,
    benchmark_pbkdf2_sha512,
    benchmark_bip39_seed,
    benchmark_pbkdf2_iterations
);
criterion_main!(benches);