use metamui_slhdsa::*;
#[test]
fn debug_single_keygen() {
    let sk_seed = hex::decode("173D04C938C1C36BF289C3C022D04B14").unwrap();
    let sk_prf = hex::decode("63AE23C41AA546DA589774AC20B745C4").unwrap();
    let pk_seed = hex::decode("0D794777914C99766827F0F09CA972BE").unwrap();

    let (pk, _sk) = slh_keygen_from_seeds::<SlhDsa128s>(&sk_seed, &sk_prf, &pk_seed).unwrap();

    println!("Computed PK: {}", hex::encode(&pk));
    println!("Expected PK: 0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C");

    // Split PK
    println!("pk_seed: {}", hex::encode(&pk[..16]));
    println!("pk_root computed: {}", hex::encode(&pk[16..]));
    println!("pk_root expected: 0162C10219D422ADBA1359E6AA65299C");
}
#[test]
fn test_address_byte_layout() {
    use metamui_slhdsa::address::Address;
    
    let mut addr = Address::new();
    addr.set_layer(6)
        .set_tree(0x0123456789ABCDEF)
        .set_type_wots()
        .set_keypair(10)
        .set_chain_addr(15)
        .set_hash_addr(20);
    
    let bytes = addr.to_bytes();
    
    println!("Address bytes: {}", hex::encode(&bytes));
    println!("\nByte layout:");
    println!("  Byte 3 (layer):      0x{:02x} (expected: 0x06)", bytes[3]);
    println!("  Bytes 8-15 (tree):   {} (expected: 0123456789ABCDEF)", hex::encode(&bytes[8..16]));
    println!("  Byte 19 (type):      0x{:02x} (expected: 0x00)", bytes[19]);
    println!("  Bytes 20-23 (kp):    {} (expected: 0000000A)", hex::encode(&bytes[20..24]));
    println!("  Byte 27 (chain):     0x{:02x} (expected: 0x0F)", bytes[27]);
    println!("  Byte 31 (hash):      0x{:02x} (expected: 0x14)", bytes[31]);
    
    assert_eq!(bytes[3], 6);
    assert_eq!(&bytes[8..16], &hex::decode("0123456789ABCDEF").unwrap()[..]);
    assert_eq!(bytes[19], 0);
    assert_eq!(&bytes[20..24], &hex::decode("0000000A").unwrap()[..]);
    assert_eq!(bytes[27], 15);
    assert_eq!(bytes[31], 20);
}
#[test]
fn test_hash_f() {
    use metamui_slhdsa::{hash::Hash, address::Address, params::SlhDsa128s};
    
    // Test SHAKE256 hash function F
    let pk_seed = vec![0u8; 16];
    let mut addr = Address::new();
    addr.set_layer(0).set_tree(0).set_type_wots();
    
    let m1 = vec![0u8; 16];
    let mut out = vec![0u8; 16];
    
    Hash::<SlhDsa128s>::f(&mut out, &pk_seed, &addr, &m1);
    
    println!("Hash F output: {}", hex::encode(&out));
    
    // This should be deterministic
    let mut out2 = vec![0u8; 16];
    Hash::<SlhDsa128s>::f(&mut out2, &pk_seed, &addr, &m1);
    assert_eq!(out, out2, "Hash should be deterministic");
}

#[test]
fn verify_address_matches_reference() {
    use metamui_slhdsa::address::Address;
    
    // Create test address matching reference behavior
    let mut addr = Address::new();
    addr.set_layer(1)
        .set_tree(0x0123456789ABCDEF)
        .set_type_wots()
        .set_keypair(5)
        .set_chain_addr(10)
        .set_hash_addr(15);
    
    let bytes = addr.to_bytes();
    
    println!("\n=== Address Verification ===");
    println!("Full address: {}", hex::encode(&bytes));
    println!("\nReference layout (from shake_offsets.h):");
    println!("  Byte 3:      layer      = {} (expected: 1)", bytes[3]);
    println!("  Bytes 8-15:  tree       = {} (expected: 0123456789ABCDEF)", hex::encode(&bytes[8..16]));
    println!("  Byte 19:     type       = {} (expected: 0)", bytes[19]);
    println!("  Bytes 20-23: keypair    = {} (expected: 00000005)", hex::encode(&bytes[20..24]));
    println!("  Byte 27:     chain_addr = {} (expected: 10)", bytes[27]);
    println!("  Byte 31:     hash_addr  = {} (expected: 15)", bytes[31]);
    
    // Verify
    assert_eq!(bytes[3], 1, "layer at byte 3");
    assert_eq!(&bytes[8..16], &hex::decode("0123456789ABCDEF").unwrap()[..], "tree at bytes 8-15");
    assert_eq!(bytes[19], 0, "type at byte 19");
    assert_eq!(bytes[20..24], hex::decode("00000005").unwrap()[..], "keypair at bytes 20-23");
    assert_eq!(bytes[27], 10, "chain_addr at byte 27");
    assert_eq!(bytes[31], 15, "hash_addr at byte 31");
    
    println!("\n✓ All address fields match reference layout!");
}
#[test]
fn test_hypertree_layer() {
    use metamui_slhdsa::params::*;
    
    println!("SlhDsa128s: D={}, top layer should be {}", SlhDsa128s::D, SlhDsa128s::D - 1);
    println!("SlhDsa256s: D={}, top layer should be {}", SlhDsa256s::D, SlhDsa256s::D - 1);
}
#[test]
fn debug_keygen_detailed_comparison() {
    use metamui_slhdsa::{*, address::Address, wots, xmss, params::SlhDsa128s};

    // Test 11 from NIST vectors (actual values from test output)
    let sk_seed = hex::decode("C151951F3811029239B74ADD24C506AF").unwrap();
    let sk_prf = hex::decode("DD30363E156E6FE936EC6ED0231FEB5C").unwrap();
    let pk_seed = hex::decode("529FFE86200D1F32C2B60D0CD909F190").unwrap();

    let expected_pk = hex::decode("529FFE86200D1F32C2B60D0CD909F1900761F9B727AFA724B47223016BB5B2BA").unwrap();
    let expected_pk_root = &expected_pk[16..];

    println!("\n=== Detailed KeyGen Debug ===");
    println!("Inputs:");
    println!("  sk_seed: {}", hex::encode(&sk_seed));
    println!("  sk_prf:  {}", hex::encode(&sk_prf));
    println!("  pk_seed: {}", hex::encode(&pk_seed));
    println!("\nExpected:");
    println!("  pk:      {}", hex::encode(&expected_pk));
    println!("  pk_root: {}", hex::encode(expected_pk_root));

    type P = SlhDsa128s;

    // Manually compute the root
    let mut addr = Address::new();
    addr.set_layer(P::D as u32 - 1); // D=8, so layer=7
    addr.set_tree(0);

    println!("\n=== Top-level Address ===");
    println!("  Layer: {}", P::D - 1);
    println!("  Tree: 0");
    let addr_bytes = addr.to_bytes();
    println!("  Address bytes: {}", hex::encode(&addr_bytes[..20]));

    // Generate XMSS root at layer 7
    let computed_root = xmss::xmss_root::<P>(&sk_seed, &pk_seed, &addr);
    println!("\n=== Computed Root ===");
    println!("  Root: {}", hex::encode(&computed_root));

    // Now let's manually generate the first WOTS+ public key to see if that's correct
    let mut wots_addr = addr;
    wots_addr.set_type_wots();
    wots_addr.set_keypair(0);

    println!("\n=== First WOTS+ Key (keypair=0) ===");
    let wots_addr_bytes = wots_addr.to_bytes();
    println!("  Address bytes: {}", hex::encode(&wots_addr_bytes[..20]));

    let first_wots_pk = wots::wots_gen_pk::<P>(&sk_seed, &pk_seed, &wots_addr);
    println!("  First WOTS PK: {}", hex::encode(&first_wots_pk));

    // Compare
    if computed_root == expected_pk_root {
        println!("\n✓ Root matches!");
    } else {
        println!("\n✗ Root mismatch!");
        println!("  Expected: {}", hex::encode(expected_pk_root));
        println!("  Got:      {}", hex::encode(&computed_root));
    }
}
