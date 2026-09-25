use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use metamui_blake3::{MetaMUIBlake3, Blake3Key};

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hashing");
    
    // Test different input sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];
    
    for size in sizes {
        let data = vec![0u8; size];
        
        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            let hasher = MetaMUIBlake3::new();
            b.iter(|| {
                black_box(hasher.hash(black_box(data)));
            });
        });
        
        group.bench_with_input(BenchmarkId::new("incremental", size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = MetaMUIBlake3::new();
                hasher.update(black_box(data));
                black_box(hasher.finalize());
            });
        });
    }
    
    group.finish();
}

fn bench_keyed_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_keyed");
    
    let key = Blake3Key::new([42u8; 32]);
    let data = vec![0u8; 1024];
    
    group.bench_function("keyed_hash", |b| {
        b.iter(|| {
            black_box(MetaMUIBlake3::hash_keyed(black_box(&key), black_box(&data)));
        });
    });
    
    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_kdf");
    
    let input_key_material = b"some input key material for derivation";
    let context = "test context";
    
    let output_sizes = [16, 32, 64, 128];
    
    for size in output_sizes {
        group.bench_with_input(BenchmarkId::new("derive_key", size), &size, |b, &size| {
            b.iter(|| {
                black_box(MetaMUIBlake3::derive_key(
                    black_box(context),
                    black_box(input_key_material),
                    black_box(size),
                ));
            });
        });
    }
    
    group.finish();
}

fn bench_xof(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_xof");
    
    let hasher = MetaMUIBlake3::new();
    let output_sizes = [32, 64, 128, 256, 512, 1024];
    
    for size in output_sizes {
        group.bench_with_input(BenchmarkId::new("variable_output", size), &size, |b, &size| {
            b.iter(|| {
                black_box(hasher.finalize_variable(black_box(size)));
            });
        });
    }
    
    group.finish();
}

#[cfg(feature = "multithreading")]
fn bench_parallel_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_parallel");
    
    let chunk_counts = [4, 8, 16, 32];
    let chunk_size = 1024;
    
    for count in chunk_counts {
        let chunks: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; chunk_size]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        
        group.bench_with_input(BenchmarkId::new("parallel", count), &chunk_refs, |b, chunks| {
            b.iter(|| {
                black_box(MetaMUIBlake3::hash_chunks_parallel(black_box(chunks)));
            });
        });
        
        group.bench_with_input(BenchmarkId::new("sequential", count), &chunk_refs, |b, chunks| {
            b.iter(|| {
                let hasher = MetaMUIBlake3::new();
                let results: Vec<_> = chunks.iter()
                    .map(|chunk| hasher.hash(chunk))
                    .collect();
                black_box(results);
            });
        });
    }
    
    group.finish();
}

// Temporarily disabled due to missing dependencies (sha2, blake2)
/*
fn bench_comparison_with_other_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_comparison");

    let data = vec![0u8; 1024];

    // BLAKE3
    group.bench_function("blake3", |b| {
        let hasher = MetaMUIBlake3::new();
        b.iter(|| {
            black_box(hasher.hash(black_box(&data)));
        });
    });

    // SHA-256 for comparison
    group.bench_function("sha256", |b| {
        // use sha2::{Sha256, Digest}; // TODO: Add sha2 to dev-dependencies if needed
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            black_box(hasher.finalize());
        });
    });

    // Blake2b for comparison
    group.bench_function("blake2b", |b| {
        use blake2::{Blake2b512, Digest};
        b.iter(|| {
            let mut hasher = Blake2b512::new();
            hasher.update(black_box(&data));
            black_box(hasher.finalize());
        });
    });

    group.finish();
}
*/

criterion_group!(
    benches,
    bench_hashing,
    bench_keyed_hashing,
    bench_key_derivation,
    bench_xof,
    // bench_comparison_with_other_hashes  // Temporarily disabled due to missing dependencies
);

#[cfg(feature = "multithreading")]
criterion_group!(
    parallel_benches,
    bench_parallel_hashing
);

#[cfg(not(feature = "multithreading"))]
criterion_main!(benches);

#[cfg(feature = "multithreading")]
criterion_main!(benches, parallel_benches);