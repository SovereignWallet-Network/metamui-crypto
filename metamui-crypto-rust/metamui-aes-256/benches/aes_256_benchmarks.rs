// Legacy AES-256 benchmarks. Rewritten to track the current public API
// (module paths under `metamui_aes_256::modes::*`, no `generate_nonce`
// convenience constructors). Enable via `cargo bench --features legacy-benches`.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use metamui_aes_256::Aes256Key;
use metamui_aes_256::modes::{
    cbc::Aes256Cbc,
    ctr::Aes256CtrCipher,
    ecb::Aes256Ecb,
    gcm::Aes256Gcm,
};
use rand::RngCore;

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("AES-256 key generation", |b| {
        b.iter(|| {
            let key = Aes256Key::generate().unwrap();
            black_box(key);
        });
    });
}

fn bench_gcm_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM");

    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let key = Aes256Key::generate().unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce: [u8; 12] = rand_bytes();
        let plaintext = vec![0u8; *size];

        group.bench_function(format!("encrypt {} bytes", size), |b| {
            b.iter(|| {
                let (ct, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
                black_box((ct, tag));
            });
        });

        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();

        group.bench_function(format!("decrypt {} bytes", size), |b| {
            b.iter(|| {
                let pt = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
                black_box(pt);
            });
        });
    }

    group.finish();
}

fn bench_cbc_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-CBC");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let key = Aes256Key::generate().unwrap();
        let cipher = Aes256Cbc::new(&key).unwrap();
        let iv: [u8; 16] = rand_bytes();
        let plaintext = vec![0u8; *size];

        group.bench_function(format!("encrypt {} bytes", size), |b| {
            b.iter(|| {
                let ct = cipher.encrypt(&iv, &plaintext).unwrap();
                black_box(ct);
            });
        });

        let ciphertext = cipher.encrypt(&iv, &plaintext).unwrap();

        group.bench_function(format!("decrypt {} bytes", size), |b| {
            b.iter(|| {
                let pt = cipher.decrypt(&iv, &ciphertext).unwrap();
                black_box(pt);
            });
        });
    }

    group.finish();
}

fn bench_ctr_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-CTR");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let key = Aes256Key::generate().unwrap();
        let cipher = Aes256CtrCipher::new(&key).unwrap();
        let nonce: [u8; 16] = rand_bytes();
        let data = vec![0u8; *size];

        group.bench_function(format!("process {} bytes", size), |b| {
            b.iter(|| {
                let result = cipher.process(&nonce, &data).unwrap();
                black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_ecb_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-ECB");

    for blocks in [1, 4, 16, 64, 256].iter() {
        let size = blocks * 16;
        group.throughput(Throughput::Bytes(size as u64));

        let key = Aes256Key::generate().unwrap();
        let cipher = Aes256Ecb::new(&key).unwrap();
        let plaintext = vec![0u8; size];

        group.bench_function(format!("encrypt {} blocks", blocks), |b| {
            b.iter(|| {
                let ct = cipher.encrypt(&plaintext).unwrap();
                black_box(ct);
            });
        });

        let ciphertext = cipher.encrypt(&plaintext).unwrap();

        group.bench_function(format!("decrypt {} blocks", blocks), |b| {
            b.iter(|| {
                let pt = cipher.decrypt(&ciphertext).unwrap();
                black_box(pt);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_gcm_mode,
    bench_cbc_mode,
    bench_ctr_mode,
    bench_ecb_mode
);
criterion_main!(benches);
