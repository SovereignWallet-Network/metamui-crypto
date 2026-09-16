use criterion::{black_box, criterion_group, criterion_main, Criterion};
use metamui_security_utils::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

fn bench_constant_time_eq(c: &mut Criterion) {
    let a = 0x12345678u32;
    let b = 0x12345678u32;
    let c_val = 0x87654321u32;

    c.bench_function("ct_eq_equal", |bench| {
        bench.iter(|| {
            black_box(a).ct_eq(&black_box(b))
        });
    });

    c.bench_function("ct_eq_not_equal", |bench| {
        bench.iter(|| {
            black_box(a).ct_eq(&black_box(c_val))
        });
    });
}

fn bench_conditional_select(c: &mut Criterion) {
    let a = 0x12345678u32;
    let b = 0x87654321u32;
    let choice_true = Choice::one();
    let choice_false = Choice::zero();

    c.bench_function("conditional_select_true", |bench| {
        bench.iter(|| {
            u32::conditional_select(&black_box(a), &black_box(b), black_box(choice_true))
        });
    });

    c.bench_function("conditional_select_false", |bench| {
        bench.iter(|| {
            u32::conditional_select(&black_box(a), &black_box(b), black_box(choice_false))
        });
    });
}

fn bench_zeroize(c: &mut Criterion) {
    c.bench_function("zeroize_u32", |bench| {
        bench.iter(|| {
            let mut value = black_box(0x12345678u32);
            value.zeroize();
            black_box(value);
        });
    });

    c.bench_function("zeroize_array_32", |bench| {
        bench.iter(|| {
            let mut array = black_box([0x42u8; 32]);
            array.zeroize();
            black_box(array);
        });
    });

    c.bench_function("zeroize_array_256", |bench| {
        bench.iter(|| {
            let mut array = black_box([0x42u8; 256]);
            array.zeroize();
            black_box(array);
        });
    });
}

criterion_group!(benches, bench_constant_time_eq, bench_conditional_select, bench_zeroize);
criterion_main!(benches);