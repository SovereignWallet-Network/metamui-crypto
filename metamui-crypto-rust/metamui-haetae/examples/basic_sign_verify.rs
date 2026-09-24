//! Basic example of signing and verifying with HAETAE
//!
//! This example demonstrates the simplest use case: generating a keypair,
//! signing a message, and verifying the signature.
//!
//! Run with: cargo run --example basic_sign_verify --features haetae2,getrandom

use metamui_haetae::{KeyPair, Error};

fn main() -> Result<(), Error> {
    println!("HAETAE Basic Sign/Verify Example");
    println!("=================================\n");

    // Generate a new keypair
    println!("Generating keypair...");
    let keypair = KeyPair::generate()?;
    println!("✓ Keypair generated successfully\n");

    // Message to sign
    let message = b"Hello, post-quantum world!";
    println!("Message: {}", String::from_utf8_lossy(message));

    // Sign the message
    println!("\nSigning message...");
    let signature = keypair.sign(message)?;
    println!("✓ Signature generated ({} bytes)", signature.as_bytes().len());

    // Verify the signature
    println!("\nVerifying signature...");
    match keypair.verify(message, &signature) {
        Ok(()) => println!("✓ Signature verified successfully!"),
        Err(e) => println!("✗ Verification failed: {}", e),
    }

    // Try to verify with wrong message (should fail)
    println!("\nTrying to verify with wrong message...");
    let wrong_message = b"Wrong message";
    match keypair.verify(wrong_message, &signature) {
        Ok(()) => println!("✗ Should have failed!"),
        Err(Error::VerificationFailed) => println!("✓ Correctly rejected wrong message"),
        Err(e) => println!("✗ Unexpected error: {}", e),
    }

    Ok(())
}
