use metamui_mlkem::mlkem768::{decapsulate, encapsulate, generate_keypair};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_basic_kem_flow() {
    // Use deterministic RNG for reproducible results
    let mut rng = ChaCha20Rng::seed_from_u64(12345);

    // Generate keypair
    let keypair = generate_keypair(&mut rng).expect("Failed to generate keypair");

    // Encapsulate
    let (ciphertext, shared_secret_enc) =
        encapsulate(&keypair.public_key, &mut rng).expect("Failed to encapsulate");

    // Decapsulate
    let shared_secret_dec =
        decapsulate(&keypair.private_key, &ciphertext).expect("Failed to decapsulate");

    // Check if they match
    assert_eq!(
        shared_secret_enc.as_bytes(),
        shared_secret_dec.as_bytes(),
        "Shared secrets should match"
    );
}
