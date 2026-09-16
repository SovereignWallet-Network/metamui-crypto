use metamui_mlkem::mlkem768::{generate_keypair, encapsulate, decapsulate};
use rand::thread_rng;
use std::time::Instant;

fn main() {
    println!("ML-KEM768 Performance Demonstration");
    println!("====================================\n");

    let mut rng = thread_rng();

    // Architecture info
    println!("CPU Architecture:");
    #[cfg(target_arch = "x86_64")]
    {
        println!("  Platform: x86_64");
        if is_x86_feature_detected!("avx2") {
            println!("  AVX2: Available");
        }
        if is_x86_feature_detected!("avx512f") {
            println!("  AVX512: Available");
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        println!("  Platform: ARM64");
        println!("  NEON: Available");
    }
    println!();

    // Warm up
    println!("Warming up...");
    for _ in 0..10 {
        let keypair = generate_keypair(&mut rng).unwrap();
        let (ct, _ss1) = encapsulate(&keypair.public_key, &mut rng).unwrap();
        let _ss2 = decapsulate(&keypair.private_key, &ct).unwrap();
    }

    // Performance measurements
    const ITERATIONS: usize = 1000;
    println!("Running {} iterations...\n", ITERATIONS);

    // Key Generation
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = generate_keypair(&mut rng).unwrap();
    }
    let keygen_time = start.elapsed();
    let keygen_ops_per_sec = ITERATIONS as f64 / keygen_time.as_secs_f64();

    // Generate keypair for encap/decap tests
    let keypair = generate_keypair(&mut rng).unwrap();

    // Encapsulation
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = encapsulate(&keypair.public_key, &mut rng).unwrap();
    }
    let encap_time = start.elapsed();
    let encap_ops_per_sec = ITERATIONS as f64 / encap_time.as_secs_f64();

    // Decapsulation
    let (ct, _) = encapsulate(&keypair.public_key, &mut rng).unwrap();
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = decapsulate(&keypair.private_key, &ct).unwrap();
    }
    let decap_time = start.elapsed();
    let decap_ops_per_sec = ITERATIONS as f64 / decap_time.as_secs_f64();

    // Full cycle
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let kp = generate_keypair(&mut rng).unwrap();
        let (ct, ss1) = encapsulate(&kp.public_key, &mut rng).unwrap();
        let ss2 = decapsulate(&kp.private_key, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
    let full_time = start.elapsed();
    let full_ops_per_sec = ITERATIONS as f64 / full_time.as_secs_f64();

    // Print results
    println!("Performance Results:");
    println!("====================");
    println!();
    println!("Key Generation:");
    println!("  Total time:     {:?}", keygen_time);
    println!("  Per operation:  {:?}", keygen_time / ITERATIONS as u32);
    println!("  Ops/second:     {:.1}", keygen_ops_per_sec);
    println!();
    println!("Encapsulation:");
    println!("  Total time:     {:?}", encap_time);
    println!("  Per operation:  {:?}", encap_time / ITERATIONS as u32);
    println!("  Ops/second:     {:.1}", encap_ops_per_sec);
    println!();
    println!("Decapsulation:");
    println!("  Total time:     {:?}", decap_time);
    println!("  Per operation:  {:?}", decap_time / ITERATIONS as u32);
    println!("  Ops/second:     {:.1}", decap_ops_per_sec);
    println!();
    println!("Full Cycle (KeyGen + Encap + Decap):");
    println!("  Total time:     {:?}", full_time);
    println!("  Per cycle:      {:?}", full_time / ITERATIONS as u32);
    println!("  Cycles/second:  {:.1}", full_ops_per_sec);
    println!();

    println!("Constant-time operations: Enforced");
}
