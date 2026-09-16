//! Generate test vectors for ML-KEM

#[cfg(feature = "mlkem768")]
use metamui_mlkem::{generate_keypair, encapsulate, decapsulate};
use rand_core::OsRng;

fn main() {
    println!("ML-KEM Test Vector Generator");
    println!("============================\n");

    // Generate ML-KEM-768 test vectors
    println!("ML-KEM-768 Test Vectors:");
    println!("------------------------");
    #[cfg(feature = "mlkem768")]
    {
        let mut rng = OsRng;
        let keypair = generate_keypair(&mut rng).unwrap();
        let (ct, ss1) = encapsulate(&keypair.public_key, &mut rng).unwrap();
        let ss2 = decapsulate(&keypair.private_key, &ct).unwrap();

        println!("Public Key (first 32 bytes): {:02x?}", &keypair.public_key.as_bytes()[..32]);
        println!("Private Key (first 32 bytes): {:02x?}", &keypair.private_key.as_bytes()[..32]);
        println!("Ciphertext (first 32 bytes): {:02x?}", &ct.as_bytes()[..32]);
        println!("Shared Secret: {:02x?}", ss1.as_bytes());
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        println!("Encapsulation/Decapsulation successful\n");
    }
}