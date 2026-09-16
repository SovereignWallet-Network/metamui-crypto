fn main() {
    let input = b"Hello, SHA3!";
    
    println!("Input: {:?}", std::str::from_utf8(input).unwrap());
    println!();
    
    // Test convenience functions
    let hash256 = metamui_sha3::sha3_256(input);
    let hash384 = metamui_sha3::sha3_384(input);
    let hash512 = metamui_sha3::sha3_512(input);
    
    println!("SHA3-256: {:02x?}", hash256);
    println!("SHA3-384: {:02x?}", hash384);
    println!("SHA3-512: {:02x?}", hash512);
    println!();
    
    // Test incremental hashing
    let mut hasher = metamui_sha3::Sha3_256::new();
    hasher.update(b"Hello, ").unwrap();
    hasher.update(b"SHA3!").unwrap();
    let incremental_hash = hasher.finalize();
    
    println!("Incremental SHA3-256: {:02x?}", incremental_hash);
    println!("Matches convenience function: {}", hash256 == incremental_hash);
    
    // Test known vectors
    println!();
    println!("Known test vectors:");
    println!("SHA3-256(empty): {:02x?}", metamui_sha3::sha3_256(b""));
    println!("SHA3-256(abc): {:02x?}", metamui_sha3::sha3_256(b"abc"));
}
