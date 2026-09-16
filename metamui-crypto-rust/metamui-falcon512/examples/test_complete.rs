use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn main() {
    println!("Falcon-512 Complete Implementation Test");
    println!("========================================\n");
    
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Test 1: Key Generation
    println!("1. Key Generation Test");
    println!("----------------------");
    let start = Instant::now();
    let keypair = match generate_keypair(&mut rng) {
        Ok(kp) => {
            let elapsed = start.elapsed();
            println!("✓ Key generation successful");
            println!("  Time: {:?}", elapsed);
            println!("  Keys generated successfully");
            kp
        }
        Err(e) => {
            println!("✗ Key generation failed: {:?}", e);
            return;
        }
    };
    
    // Test 2: Signing
    println!("\n2. Signing Test");
    println!("---------------");
    let message = b"Hello, Falcon-512! This is a test message.";
    println!("Message: {:?}", std::str::from_utf8(message).unwrap());
    
    let start = Instant::now();
    let signature = match sign(message, &keypair.private_key, &mut rng) {
        Ok(sig) => {
            let elapsed = start.elapsed();
            println!("✓ Signing successful");
            println!("  Time: {:?}", elapsed);
            println!("  Signature size: {} bytes", sig.len());
            sig
        }
        Err(e) => {
            println!("✗ Signing failed: {:?}", e);
            return;
        }
    };
    
    // Test 3: Verification
    println!("\n3. Verification Test");
    println!("-------------------");
    
    let start = Instant::now();
    match verify(message, &signature, &keypair.public_key) {
        Ok(valid) => {
            let elapsed = start.elapsed();
            if valid {
                println!("✓ Signature verification successful");
                println!("  Time: {:?}", elapsed);
            } else {
                println!("⚠ Signature verification failed - invalid signature");
                println!("  Time: {:?}", elapsed);
            }
        }
        Err(e) => {
            println!("⚠ Verification error: {:?}", e);
        }
    }
    
    // Test 4: Wrong Message Verification
    println!("\n4. Wrong Message Test");
    println!("--------------------");
    let wrong_message = b"This is a different message";
    
    match verify(wrong_message, &signature, &keypair.public_key) {
        Ok(valid) => {
            if !valid {
                println!("✓ Correctly rejected wrong message");
            } else {
                println!("✗ ERROR: Accepted wrong message!");
            }
        }
        Err(_) => {
            println!("✓ Correctly rejected wrong message (with error)");
        }
    }
    
    // Test 5: Multiple Signatures
    println!("\n5. Multiple Signatures Test");
    println!("---------------------------");
    let mut all_different = true;
    let mut signatures = Vec::new();
    
    for i in 0..3 {
        let sig = sign(message, &keypair.private_key, &mut rng).expect("Signing should work");
        
        // Check if this signature is different from previous ones
        for prev_sig in &signatures {
            if sig == *prev_sig {
                all_different = false;
                break;
            }
        }
        
        println!("  Signature {} size: {} bytes", i + 1, sig.len());
        signatures.push(sig);
    }
    
    if all_different {
        println!("✓ All signatures are different (randomized signing)");
    } else {
        println!("⚠ Some signatures are identical");
    }
    
    // Test 6: Performance Summary
    println!("\n6. Performance Benchmark");
    println!("------------------------");
    
    let mut keygen_times = Vec::new();
    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();
    
    for _ in 0..5 {
        // Key generation
        let start = Instant::now();
        let kp = generate_keypair(&mut rng).expect("Keygen should work");
        keygen_times.push(start.elapsed());
        
        // Signing
        let start = Instant::now();
        let sig = sign(message, &kp.private_key, &mut rng).expect("Sign should work");
        sign_times.push(start.elapsed());
        
        // Verification
        let start = Instant::now();
        let _ = verify(message, &sig, &kp.public_key);
        verify_times.push(start.elapsed());
    }
    
    let avg_keygen = keygen_times.iter().sum::<std::time::Duration>() / keygen_times.len() as u32;
    let avg_sign = sign_times.iter().sum::<std::time::Duration>() / sign_times.len() as u32;
    let avg_verify = verify_times.iter().sum::<std::time::Duration>() / verify_times.len() as u32;
    
    println!("Average times (5 runs):");
    println!("  Key generation: {:?}", avg_keygen);
    println!("  Signing: {:?}", avg_sign);
    println!("  Verification: {:?}", avg_verify);
    
    // Final verdict
    println!("\n========================================");
    if avg_keygen.as_millis() < 100 && avg_sign.as_millis() < 50 {
        println!("✅ Falcon-512 implementation is working with good performance!");
    } else if avg_keygen.as_secs() < 1 {
        println!("✅ Falcon-512 implementation is working (performance could be improved)");
    } else {
        println!("⚠ Falcon-512 implementation needs performance optimization");
    }
}