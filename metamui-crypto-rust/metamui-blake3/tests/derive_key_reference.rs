
#[cfg(test)]
mod tests {
    use metamui_blake3::MetaMUIBlake3;
    use hex;

    #[test]
    fn test_derive_key_reference() {
        let context = "metamui-context";
        let material = b"abc";
        // Generated with: b3sum --derive-key "metamui-context" <(echo -n "abc")
        let expected = "b0fffc23ca0d96c135cf63f90127e5d0cc98c5b8a5ab9ff1c6e4aabaea72fec1";

        // Test public API (which uses native implementation by default)
        let result = MetaMUIBlake3::derive_key(context, material, 32);
        assert_eq!(hex::encode(result), expected, "MetaMUIBlake3::derive_key failed");
    }

    #[test]
    fn test_basic_hash_reference() {
        use metamui_blake3::blake3::native_blake3;
        let hash = native_blake3(b"abc");
        // Verified with official b3sum: echo -n "abc" | b3sum
        // Output: 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
        let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
        assert_eq!(hex::encode(hash), expected, "Basic hash failed");
    }
}

