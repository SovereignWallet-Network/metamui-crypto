/// Simple test to verify the implementation works

use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_simple_sign_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    
    // Generate a keypair
    let keypair = generate_keypair(&mut rng).unwrap();
    println!("✓ Generated keypair");
    
    // Test messages
    let messages = [
        b"".as_slice(),                    // Empty message (like test 0)
        b"abc",                            // 3-byte message (like test 1)  
        b"The quick brown fox jumps over", // Longer message
    ];
    
    for (i, message) in messages.iter().enumerate() {
        println!("\nTesting message {}: {:?}", i, 
                 std::str::from_utf8(message).unwrap_or("<binary>"));
        
        // Sign the message
        let signature = sign(message, &keypair.private_key, &mut rng).unwrap();
        println!("  Signature size: {} bytes", signature.len());
        
        // Verify the signature
        let is_valid = verify(message, &signature, &keypair.public_key).unwrap();
        println!("  Verification: {}", if is_valid { "✓ PASS" } else { "✗ FAIL" });
        
        assert!(is_valid, "Signature should verify");
        
        // Try with wrong message
        let wrong_message = b"wrong message";
        let wrong_valid = verify(wrong_message, &signature, &keypair.public_key).unwrap();
        println!("  Wrong message: {}", if !wrong_valid { "✓ Correctly rejected" } else { "✗ Should have failed" });
        
        assert!(!wrong_valid, "Wrong message should not verify");
    }
    
    println!("\n✓ All tests passed!");
}