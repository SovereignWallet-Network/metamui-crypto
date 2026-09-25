use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use metamui_camellia::{
    modes::{cbc, ctr, gcm},
    BlockCipher, Camellia, Camellia128, Camellia192, Camellia256,
};

fn bench_key_schedule(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_schedule");

    group.bench_function("camellia128", |b| {
        let key = [0u8; 16];
        b.iter(|| Camellia128::new(black_box(&key)));
    });

    group.bench_function("camellia192", |b| {
        let key = [0u8; 24];
        b.iter(|| Camellia192::new(black_box(&key)));
    });

    group.bench_function("camellia256", |b| {
        let key = [0u8; 32];
        b.iter(|| Camellia256::new(black_box(&key)));
    });

    group.finish();
}

fn bench_block_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_operations");
    group.throughput(Throughput::Bytes(16));

    let key = [0u8; 32];
    let cipher = Camellia256::new(&key);

    group.bench_function("encrypt_block", |b| {
        let mut block = [0u8; 16];
        b.iter(|| {
            cipher.encrypt_block(black_box(&mut block));
        });
    });

    group.bench_function("decrypt_block", |b| {
        let mut block = [0u8; 16];
        b.iter(|| {
            cipher.decrypt_block(black_box(&mut block));
        });
    });

    group.finish();
}

fn bench_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("modes");
    
    let key = [0u8; 32];
    let cipher = Camellia::new(&key).unwrap();
    let iv = [0u8; 16];
    let nonce = [0u8; 16];

    // Test different message sizes
    for size in [64, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        group.bench_function(format!("cbc_encrypt_{}", size), |b| {
            b.iter(|| {
                cbc::encrypt_cbc(&cipher, &iv, black_box(&data)).unwrap();
            });
        });

        group.bench_function(format!("ctr_process_{}", size), |b| {
            b.iter(|| {
                ctr::process_ctr(&cipher, &nonce, black_box(&data)).unwrap();
            });
        });

        group.bench_function(format!("gcm_encrypt_{}", size), |b| {
            let aad = b"additional data";
            b.iter(|| {
                gcm::encrypt_gcm(&cipher, &nonce[..12], black_box(&data), aad).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_size_comparison");
    group.throughput(Throughput::Bytes(1024));

    let data = vec![0u8; 1024];
    let nonce = [0u8; 16];

    // Compare different key sizes
    let key128 = [0u8; 16];
    let key192 = [0u8; 24];
    let key256 = [0u8; 32];

    let cipher128 = Camellia::new(&key128).unwrap();
    let cipher192 = Camellia::new(&key192).unwrap();
    let cipher256 = Camellia::new(&key256).unwrap();

    group.bench_function("camellia128_ctr", |b| {
        b.iter(|| {
            ctr::process_ctr(&cipher128, &nonce, black_box(&data)).unwrap();
        });
    });

    group.bench_function("camellia192_ctr", |b| {
        b.iter(|| {
            ctr::process_ctr(&cipher192, &nonce, black_box(&data)).unwrap();
        });
    });

    group.bench_function("camellia256_ctr", |b| {
        b.iter(|| {
            ctr::process_ctr(&cipher256, &nonce, black_box(&data)).unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_schedule,
    bench_block_ops,
    bench_modes,
    bench_comparison
);
criterion_main!(benches);