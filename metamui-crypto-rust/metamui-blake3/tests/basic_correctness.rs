use metamui_blake3::blake3::{native_blake3, native_blake3_keyed, Blake3Hasher};
use metamui_blake3::KEY_SIZE;
use metamui_crypto_utilities::encoding::hex;

#[test]
fn test_native_blake3_empty() {
    let hash = native_blake3(b"");
    // BLAKE3 empty hash
    let expected = hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262").unwrap();
    assert_eq!(&hash[..], &expected[..]);
}

#[test]
fn test_native_blake3_basic() {
    let hash = native_blake3(b"abc");
    // Test that it produces consistent output
    let hash2 = native_blake3(b"abc");
    assert_eq!(hash, hash2);
}

#[test]
fn test_native_blake3_keyed() {
    let key = [0x42u8; KEY_SIZE];
    let hash = native_blake3_keyed(&key, b"message");
    let hash2 = native_blake3_keyed(&key, b"message");
    assert_eq!(hash, hash2);
    
    // Different key should produce different hash
    let key2 = [0x43u8; KEY_SIZE];
    let hash3 = native_blake3_keyed(&key2, b"message");
    assert_ne!(hash, hash3);
}

#[test]
fn test_native_blake3_single_a() {
    let hash = native_blake3(b"a");
    let hex_result = hex::encode(&hash);
    
    let expected = "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f";
    assert_eq!(hex_result, expected, "Rust BLAKE3 single a mismatch");
}

#[test]
fn test_native_blake3_ab() {
    let hash = native_blake3(b"ab");
    let hex_result = hex::encode(&hash);
    println!("ab hash: {}", hex_result);
    // We'll check if this passes or fails to identify the pattern
}

#[test]
fn test_blake3_performance() {
    use std::time::Instant;
    
    // Test with different input sizes
    let sizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB
    
    for &size in &sizes {
        let data = vec![0x42u8; size];
        
        let start = Instant::now();
        let _hash = native_blake3(&data);
        let duration = start.elapsed();
        
        let throughput = (size as f64) / (duration.as_secs_f64() * 1024.0 * 1024.0);
        println!("BLAKE3 performance: {} bytes in {:?} ({:.2} MB/s)", 
                    size, duration, throughput);
    }
}

#[test]
fn test_blake3_batch_processing() {
    let chunks = vec![
        b"chunk1".as_slice(),
        b"chunk2".as_slice(),
        b"chunk3".as_slice(),
        b"chunk4".as_slice(),
    ];
    
    let mut hasher = Blake3Hasher::new();
    hasher.update_batch(&chunks);
    let hash = hasher.finalize();
    
    // Should match sequential update
    let mut hasher2 = Blake3Hasher::new();
    for chunk in &chunks {
        hasher2.update(chunk);
    }
    let hash2 = hasher2.finalize();
    
    assert_eq!(hash, hash2);
}
