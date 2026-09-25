use metamui_argon2::{argon2_hash, Argon2Type};
use hex;

#[test]
fn test_argon2i_version_19() {
    // Test vector from PHC winner Argon2 reference implementation
    // https://github.com/P-H-C/phc-winner-argon2
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 65536; // 64 MiB
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2i,
        0x13, // version 1.3
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from reference implementation
    let expected = hex::decode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0").unwrap();
    assert_eq!(hash, expected, "Argon2i hash mismatch");
}

#[test]
fn test_argon2d_version_19() {
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 65536; // 64 MiB
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2d,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf").unwrap();
    assert_eq!(hash, expected, "Argon2d hash mismatch");
}

#[test]
fn test_argon2id_version_19() {
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 65536; // 64 MiB
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2id,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from reference implementation
    let expected = hex::decode("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7").unwrap();
    assert_eq!(hash, expected, "Argon2id hash mismatch");
}

#[test]
fn test_argon2i_minimal() {
    // Minimal test case
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 1;
    let m_cost = 64; // 64 KiB minimum
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2i,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("9bec782fb84dd994630417dc331dbd068e49749c48139d9daad33a23fc068c36").unwrap();
    assert_eq!(hash, expected, "Argon2i minimal hash mismatch");
}

#[test]
fn test_argon2d_minimal() {
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 1;
    let m_cost = 64; // 64 KiB minimum
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2d,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("063f9e47e2f270b195d3e16245f2f73a0c47244f1703fbc04348a0585bde7c4f").unwrap();
    assert_eq!(hash, expected, "Argon2d minimal hash mismatch");
}

#[test]
fn test_argon2id_minimal() {
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 1;
    let m_cost = 64; // 64 KiB minimum
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2id,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("729c7a54441bc13559bdca71348c4e554599e719c08a952601ed5c83618c1bbd").unwrap();
    assert_eq!(hash, expected, "Argon2id minimal hash mismatch");
}

#[test]
fn test_argon2i_parallel() {
    // Test with parallelism > 1
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 256; // 256 KiB
    let parallelism = 4;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2i,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("d4542bfab778f1a00cd608fc7befbc79c19291075d3800984abd81e2111e22a8").unwrap();
    assert_eq!(hash, expected, "Argon2i parallel hash mismatch");
}

#[test]
fn test_argon2_empty_password() {
    // Test with empty password
    let password = b"";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 64;
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2i,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Expected hash from RustCrypto argon2 v0.5 reference
    let expected = hex::decode("0bac21175a1922adaa0bcf9bbae93a9ad97e4592a3cb85db3726a56181e48184").unwrap();
    assert_eq!(hash, expected, "Argon2i empty password hash mismatch");
}

#[test]
fn test_argon2_long_password() {
    // Test with long password (> 64 bytes)
    let password = b"this is a very long password that exceeds the blake2b block size of 64 bytes to test proper handling";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 64;
    let parallelism = 1;
    let hash_len = 32;
    
    let result = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        hash_len,
        Argon2Type::Argon2i,
        0x13,
    );
    
    assert!(result.is_ok());
    let hash = result.unwrap();
    
    // Should produce consistent hash
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_argon2_different_hash_lengths() {
    let password = b"password";
    let salt = b"somesalt";
    let t_cost = 2;
    let m_cost = 64;
    let parallelism = 1;
    
    // Test 16 byte hash
    let result_16 = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        16,
        Argon2Type::Argon2i,
        0x13,
    );
    assert!(result_16.is_ok());
    assert_eq!(result_16.unwrap().len(), 16);
    
    // Test 64 byte hash
    let result_64 = argon2_hash(
        password,
        salt,
        t_cost,
        m_cost,
        parallelism,
        64,
        Argon2Type::Argon2i,
        0x13,
    );
    assert!(result_64.is_ok());
    assert_eq!(result_64.unwrap().len(), 64);
}

#[test]
fn test_argon2_invalid_parameters() {
    let password = b"password";
    let salt = b"somesalt";
    
    // Test with t_cost = 0 (should fail)
    let result = argon2_hash(
        password,
        salt,
        0,
        64,
        1,
        32,
        Argon2Type::Argon2i,
        0x13,
    );
    assert!(result.is_err());
    
    // Test with m_cost < 8 * parallelism (should fail)
    let result = argon2_hash(
        password,
        salt,
        1,
        4,
        2,
        32,
        Argon2Type::Argon2i,
        0x13,
    );
    assert!(result.is_err());
    
    // Test with parallelism = 0 (should fail)
    let result = argon2_hash(
        password,
        salt,
        1,
        64,
        0,
        32,
        Argon2Type::Argon2i,
        0x13,
    );
    assert!(result.is_err());
}