use metamui_argon2::blake2b::blake2b_long;
use hex;

#[test]
fn test_blake2b_reference_vectors() {
    // blake2b_long implements Argon2's H' function (RFC 9106 Section 3.2):
    // H'^T(A) = Blake2b-T(LE32(T) || A)
    // So it always prepends LE32(output_length) to the input.

    // Test vector 1: H'(64, "") = Blake2b-64(LE32(64) || "")
    let input = b"";
    let mut output = vec![0u8; 64];

    let result = blake2b_long(&mut output, input);
    assert!(result.is_ok());

    let expected = hex::decode("7fedd5af05184f3700cb1986bf39663bc06501e6455da2b643d47bc1c01302bea32e4e9ec6b29f4d151c6348788b59d4e02e69e4199a886d5b36fc3e5200ab04").unwrap();
    assert_eq!(output, expected, "H'(64, '') test failed");

    // Test vector 2: H'(64, "abc") = Blake2b-64(LE32(64) || "abc")
    let input = b"abc";
    let mut output = vec![0u8; 64];

    let result = blake2b_long(&mut output, input);
    assert!(result.is_ok());

    let expected = hex::decode("f32577a3172f56657d531faaa43077bb8c9726ada7bb04dd337ec5a65454abff241ad6b87a72440e5127c6f9caa70327f2a699096e52d163eb52d9cd99620593").unwrap();
    assert_eq!(output, expected, "H'(64, 'abc') test failed");
}

#[test]
fn test_blake2b_long_output() {
    // Test Blake2b-long with output > 64 bytes
    let input = b"test";
    let mut output = vec![0u8; 128];
    
    let result = blake2b_long(&mut output, input);
    assert!(result.is_ok());
    
    println!("Blake2b-long('test', 128): {}", hex::encode(&output));
    
    // Should not be all zeros
    assert_ne!(output, vec![0u8; 128]);
    
    // Test consistency
    let mut output2 = vec![0u8; 128];
    let result2 = blake2b_long(&mut output2, input);
    assert!(result2.is_ok());
    assert_eq!(output, output2, "Blake2b-long should be deterministic");
}