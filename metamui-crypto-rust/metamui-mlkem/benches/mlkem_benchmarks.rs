//! ML-KEM benchmarks (legacy) — track the current instance-style API.
//!
//! Only ML-KEM-768 is exposed at the crate root today (with `MLKem512` /
//! `MLKem1024` reserved as marker structs but without an engine). Enable
//! this bench via `cargo bench --features legacy-benches`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "mlkem768")]
use metamui_mlkem::MLKem768;
use rand::thread_rng;

#[cfg(feature = "mlkem768")]
fn bench_mlkem768(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768");
    let mut rng = thread_rng();
    let kem = MLKem768::new();

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = kem.generate_keypair(&mut rng).unwrap();
        });
    });

    let kp = kem.generate_keypair(&mut rng).unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let _ = kem.encapsulate(black_box(&kp.public_key), &mut rng).unwrap();
        });
    });

    let (ct, _ss) = kem.encapsulate(&kp.public_key, &mut rng).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let _ = kem.decapsulate(black_box(&kp.private_key), black_box(&ct)).unwrap();
        });
    });

    group.finish();
}

#[cfg(not(feature = "mlkem768"))]
fn bench_mlkem768(_c: &mut Criterion) {}

criterion_group!(benches, bench_mlkem768);
criterion_main!(benches);
