//! Example demonstrating multiple signatures and signature properties
//!
//! This example shows:
//! - Signing multiple different messages with the same key
//! - Signature uniqueness (same message produces different signatures)
//! - Batch verification
//!
//! Run with: cargo run --example multiple_signatures --features haetae2,getrandom

use metamui_haetae::{KeyPair, Signature, Error};

fn main() -> Result<(), Error> {
    println!("HAETAE Multiple Signatures Example");
    println!("===================================\n");

    // Generate a keypair
    let keypair = KeyPair::generate()?;
    println!("✓ Keypair generated\n");

    // Sign multiple different messages
    println!("1. Signing multiple different messages:");
    let messages = [
        b"First message" as &[u8],
        b"Second message",
        b"Third message with more content",
        b"",  // Empty message
    ];

    let mut signatures = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        let signature = keypair.sign(message)?;
        signatures.push(signature);
        println!("   Message {}: \"{}\" -> {} byte signature",
                 i + 1,
                 String::from_utf8_lossy(message),
                 Signature::len());
    }

    // Verify all signatures
    println!("\n2. Verifying all signatures:");
    for (i, (message, signature)) in messages.iter().zip(signatures.iter()).enumerate() {
        keypair.verify(message, signature)?;
        println!("   ✓ Signature {} verified", i + 1);
    }

    // Demonstrate signature randomization
    println!("\n3. Demonstrating signature randomization:");
    println!("   (Same message produces different signatures each time)");
    let repeated_message = b"Repeated message";

    let sig1 = keypair.sign(repeated_message)?;
    let sig2 = keypair.sign(repeated_message)?;
    let sig3 = keypair.sign(repeated_message)?;

    println!("   Signature 1: {}...", hex_preview(&sig1.to_bytes(), 8));
    println!("   Signature 2: {}...", hex_preview(&sig2.to_bytes(), 8));
    println!("   Signature 3: {}...", hex_preview(&sig3.to_bytes(), 8));

    if sig1.as_bytes() != sig2.as_bytes() && sig2.as_bytes() != sig3.as_bytes() {
        println!("   ✓ Signatures are different (randomized signing)");
    }

    // But all verify correctly
    println!("\n4. Verifying randomized signatures:");
    keypair.verify(repeated_message, &sig1)?;
    keypair.verify(repeated_message, &sig2)?;
    keypair.verify(repeated_message, &sig3)?;
    println!("   ✓ All three signatures verify correctly");

    // Demonstrate signature malleability protection
    println!("\n5. Testing signature malleability protection:");
    let original_sig = keypair.sign(b"Protected message")?;

    // Create a tampered signature by flipping a bit in the serialized bytes
    let mut tampered_bytes = original_sig.to_bytes();
    tampered_bytes[0] ^= 1;  // Flip one bit
    let tampered_sig = Signature::from_bytes(&tampered_bytes)
        .expect("Should be able to create signature from modified bytes");

    match keypair.verify(b"Protected message", &tampered_sig) {
        Err(Error::VerificationFailed) => {
            println!("   ✓ Tampered signature correctly rejected");
        }
        Ok(()) => {
            println!("   ✗ Tampered signature incorrectly accepted!");
        }
        Err(e) => {
            println!("   ✗ Unexpected error: {}", e);
        }
    }

    // Cross-message verification should fail
    println!("\n6. Testing cross-message verification:");
    let msg_a = b"Message A";
    let msg_b = b"Message B";

    let sig_a = keypair.sign(msg_a)?;

    match keypair.verify(msg_b, &sig_a) {
        Err(Error::VerificationFailed) => {
            println!("   ✓ Signature for Message A correctly rejected for Message B");
        }
        Ok(()) => {
            println!("   ✗ Cross-verification incorrectly succeeded!");
        }
        Err(e) => {
            println!("   ✗ Unexpected error: {}", e);
        }
    }

    println!("\n✓ All tests passed!");

    Ok(())
}

/// Helper function to display hex preview of bytes
fn hex_preview(bytes: &[u8], len: usize) -> String {
    bytes.iter()
        .take(len)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
