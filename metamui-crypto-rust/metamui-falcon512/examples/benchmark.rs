use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn main() {
    println!("Falcon-512 Performance Benchmark");
    println!("=================================\n");
    
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Benchmark key generation
    println!("Key Generation:");
    let start = Instant::now();
    let keypair = generate_keypair(&mut rng).expect("Failed to generate keypair");
    let keygen_time = start.elapsed();
    println!("  Time: {:?}", keygen_time);
    
    // Benchmark signing
    let message = b"Hello, Falcon-512! This is a test message for benchmarking.";
    println!("\nSigning (message size: {} bytes):", message.len());
    
    let mut sign_times = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        let _signature = sign(message, &keypair.private_key, &mut rng).expect("Failed to sign");
        sign_times.push(start.elapsed());
    }
    
    let avg_sign_time = sign_times.iter().sum::<std::time::Duration>() / sign_times.len() as u32;
    println!("  Average time (10 runs): {:?}", avg_sign_time);
    
    // Generate a signature for verification benchmark
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Failed to sign");
    println!("  Signature size: {} bytes", signature.len());
    
    // Benchmark verification
    println!("\nVerification:");
    let mut verify_times = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        let _valid = verify(message, &signature, &keypair.public_key);
        verify_times.push(start.elapsed());
    }
    
    let avg_verify_time = verify_times.iter().sum::<std::time::Duration>() / verify_times.len() as u32;
    println!("  Average time (10 runs): {:?}", avg_verify_time);
    
    // Summary
    println!("\n=================================");
    println!("Summary:");
    println!("  Key generation: {:?}", keygen_time);
    println!("  Signing: {:?}/op", avg_sign_time);
    println!("  Verification: {:?}/op", avg_verify_time);
    
    if keygen_time.as_secs() < 1 {
        println!("\n✅ Performance is acceptable for testing!");
    } else {
        println!("\n⚠ Performance needs optimization");
    }
}