//! Example demonstrating key serialization and deserialization
//!
//! This example shows how to serialize keys to bytes for storage or transmission,
//! and how to reconstruct them for later use.
//!
//! Run with: cargo run --example key_serialization --features haetae2,getrandom

use metamui_haetae::{KeyPair, SigningKey, VerifyingKey, Error};

fn main() -> Result<(), Error> {
    println!("HAETAE Key Serialization Example");
    println!("=================================\n");

    // Generate a keypair
    println!("1. Generating keypair...");
    let keypair = KeyPair::generate()?;
    println!("   ✓ Generated\n");

    // Serialize the keys
    println!("2. Serializing keys to bytes...");
    let public_key_bytes = keypair.verifying_key().to_bytes();
    let secret_key_bytes = keypair.signing_key().to_bytes();
    println!("   ✓ Public key: {} bytes", public_key_bytes.len());
    println!("   ✓ Secret key: {} bytes", secret_key_bytes.len());

    // In a real application, you might save these to a file or database
    println!("\n3. Simulating storage/transmission...");
    println!("   (In practice, you would save to file or send over network)");

    // Reconstruct the keys from bytes
    println!("\n4. Reconstructing keys from bytes...");
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes);
    let signing_key = SigningKey::from_bytes(secret_key_bytes);
    println!("   ✓ Keys reconstructed\n");

    // Use the reconstructed keys to sign and verify
    println!("5. Testing reconstructed keys...");
    let message = b"Test message with serialized keys";

    let signature = signing_key.sign(message)?;
    println!("   ✓ Signed with reconstructed signing key");

    verifying_key.verify(message, &signature)?;
    println!("   ✓ Verified with reconstructed verifying key");

    // Demonstrate separating signing and verification
    println!("\n6. Demonstrating key separation:");
    println!("   Signer has: SigningKey");
    println!("   Verifier has: VerifyingKey (public, can be shared)");

    let another_message = b"Another message";
    let another_signature = signing_key.sign(another_message)?;
    println!("   ✓ Signer creates signature");

    // The verifying key can be shared publicly
    let shared_public_key_bytes = verifying_key.to_bytes();
    let recipient_verifying_key = VerifyingKey::from_bytes(shared_public_key_bytes);

    recipient_verifying_key.verify(another_message, &another_signature)?;
    println!("   ✓ Recipient verifies with public key");

    println!("\n✓ All operations successful!");

    Ok(())
}
