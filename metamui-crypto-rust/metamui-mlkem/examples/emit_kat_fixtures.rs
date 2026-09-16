//! Emit ML-KEM KAT fixtures using the in-tree Rust reference.
//!
//! Output: JSON to stdout. Schema:
//!
//! ```json
//! {
//!   "spec": "FIPS 203",
//!   "source": "metamui-crypto-rust/metamui-mlkem v3.0.0 (working reference)",
//!   "variants": {
//!     "ML-KEM-512":  { "records": [ {...}, ... ] },
//!     "ML-KEM-768":  { "records": [ {...}, ... ] },
//!     "ML-KEM-1024": { "records": [ {...}, ... ] }
//!   }
//! }
//! ```
//!
//! Each record contains: label, seed (32 B), m (32 B), publicKey,
//! privateKey, ciphertext, sharedSecret (all hex strings).
//!
//! Build + run (all three variants):
//!     cargo run -p metamui-mlkem --release --example emit_kat_fixtures \
//!       --features "mlkem512 mlkem768 mlkem1024" \
//!       > test-vectors/ml-kem/rust-fixtures.json
//!
//! Cross-language byte-equality contract: any other ML-KEM implementation
//! that wires the same (d=seed, z=SHA3-256(seed || "z_derivation"))
//! derivation per crate::kem::mlkem_keygen_from_seed must produce the
//! same publicKey / privateKey, and the same ciphertext / sharedSecret
//! given the same (seed, m) inputs. See Phase 2 audit Gap A closure.

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("bad hex byte at {}: {}", i, e));
    }
    out
}

#[derive(Clone, Copy)]
struct Case {
    label: &'static str,
    seed_hex: &'static str,
    m_hex: &'static str,
}

// Shared deterministic test cases — same (seed, m) inputs across all three
// variants so cross-language drivers can pivot on variant ID alone.
const COMMON_CASES: &[Case] = &[
    Case {
        label: "all-0x00",
        seed_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        m_hex:    "0000000000000000000000000000000000000000000000000000000000000000",
    },
    Case {
        label: "all-0x42",
        seed_hex: "4242424242424242424242424242424242424242424242424242424242424242",
        m_hex:    "7777777777777777777777777777777777777777777777777777777777777777",
    },
    Case {
        label: "all-0x55-and-m-0x77",
        seed_hex: "5555555555555555555555555555555555555555555555555555555555555555",
        m_hex:    "7777777777777777777777777777777777777777777777777777777777777777",
    },
    Case {
        label: "all-0x55-and-m-0x78",
        seed_hex: "5555555555555555555555555555555555555555555555555555555555555555",
        m_hex:    "7878787878787878787878787878787878787878787878787878787878787878",
    },
    Case {
        label: "all-0x66",
        seed_hex: "6666666666666666666666666666666666666666666666666666666666666666",
        m_hex:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
];

// Per-variant "nist-kat" seed — preserves the prior test-vectors/ml-kem/
// nist-kat.json seeds (0001…, 1011…, 2021…) so downstream consumers
// already keyed on those exact seeds continue to work.
#[cfg(feature = "mlkem512")]
const NIST_KAT_512: Case = Case {
    label: "nist-kat",
    seed_hex: "0001020304050607080910111213141516171819202122232425262728293031",
    m_hex:    "0101010101010101010101010101010101010101010101010101010101010101",
};
#[cfg(feature = "mlkem768")]
const NIST_KAT_768: Case = Case {
    label: "nist-kat",
    seed_hex: "1011121314151617181920212223242526272829303132333435363738394041",
    m_hex:    "0101010101010101010101010101010101010101010101010101010101010101",
};
#[cfg(feature = "mlkem1024")]
const NIST_KAT_1024: Case = Case {
    label: "nist-kat",
    seed_hex: "2021222324252627282930313233343536373839404142434445464748495051",
    m_hex:    "0101010101010101010101010101010101010101010101010101010101010101",
};

fn emit_record(label: &str, seed: &[u8; 32], m: &[u8; 32], pk: &[u8], sk: &[u8], ct: &[u8], ss: &[u8], last: bool) {
    println!("        {{");
    println!("          \"label\":        \"{}\",", label);
    println!("          \"seed\":         \"{}\",", hex(seed));
    println!("          \"m\":            \"{}\",", hex(m));
    println!("          \"publicKey\":    \"{}\",", hex(pk));
    println!("          \"privateKey\":   \"{}\",", hex(sk));
    println!("          \"ciphertext\":   \"{}\",", hex(ct));
    println!("          \"sharedSecret\": \"{}\"", hex(ss));
    print!("        }}");
    if !last { print!(","); }
    println!();
}

#[cfg(feature = "mlkem512")]
fn emit_variant_512(last_variant: bool) {
    use metamui_mlkem::mlkem512::{generate_keypair_from_seed, encapsulate_deterministic, decapsulate};

    println!("    \"ML-KEM-512\": {{");
    println!("      \"records\": [");

    let cases: Vec<Case> = COMMON_CASES.iter().copied().chain(std::iter::once(NIST_KAT_512)).collect();
    let last = cases.len() - 1;
    for (i, case) in cases.iter().enumerate() {
        let seed = hex32(case.seed_hex);
        let m = hex32(case.m_hex);
        let (pk, sk) = generate_keypair_from_seed(&seed)
            .unwrap_or_else(|e| panic!("ML-KEM-512 keygen failed for {}: {:?}", case.label, e));
        let (ct, ss_enc) = encapsulate_deterministic(&pk, &m)
            .unwrap_or_else(|e| panic!("ML-KEM-512 encap failed for {}: {:?}", case.label, e));
        let ss_dec = decapsulate(&sk, &ct)
            .unwrap_or_else(|e| panic!("ML-KEM-512 decap failed for {}: {:?}", case.label, e));
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref(),
            "ML-KEM-512 roundtrip failed for {}", case.label);

        emit_record(case.label, &seed, &m, pk.as_ref(), sk.as_ref(),
                    ct.as_ref(), ss_enc.as_ref(), i == last);
    }

    println!("      ]");
    if last_variant {
        println!("    }}");
    } else {
        println!("    }},");
    }
}

#[cfg(feature = "mlkem768")]
fn emit_variant_768(last_variant: bool) {
    use metamui_mlkem::mlkem768::{generate_keypair_from_seed, encapsulate_deterministic, decapsulate};

    println!("    \"ML-KEM-768\": {{");
    println!("      \"records\": [");

    let cases: Vec<Case> = COMMON_CASES.iter().copied().chain(std::iter::once(NIST_KAT_768)).collect();
    let last = cases.len() - 1;
    for (i, case) in cases.iter().enumerate() {
        let seed = hex32(case.seed_hex);
        let m = hex32(case.m_hex);
        let kp = generate_keypair_from_seed(&seed)
            .unwrap_or_else(|e| panic!("ML-KEM-768 keygen failed for {}: {:?}", case.label, e));
        let (ct, ss_enc) = encapsulate_deterministic(&kp.public_key, &m)
            .unwrap_or_else(|e| panic!("ML-KEM-768 encap failed for {}: {:?}", case.label, e));
        let ss_dec = decapsulate(&kp.private_key, &ct)
            .unwrap_or_else(|e| panic!("ML-KEM-768 decap failed for {}: {:?}", case.label, e));
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes(),
            "ML-KEM-768 roundtrip failed for {}", case.label);

        emit_record(case.label, &seed, &m, kp.public_key.as_bytes(),
                    kp.private_key.as_bytes(), ct.as_bytes(), ss_enc.as_bytes(),
                    i == last);
    }

    println!("      ]");
    if last_variant {
        println!("    }}");
    } else {
        println!("    }},");
    }
}

#[cfg(feature = "mlkem1024")]
fn emit_variant_1024(last_variant: bool) {
    use metamui_mlkem::mlkem1024::{generate_keypair_from_seed, encapsulate_deterministic, decapsulate};

    println!("    \"ML-KEM-1024\": {{");
    println!("      \"records\": [");

    let cases: Vec<Case> = COMMON_CASES.iter().copied().chain(std::iter::once(NIST_KAT_1024)).collect();
    let last = cases.len() - 1;
    for (i, case) in cases.iter().enumerate() {
        let seed = hex32(case.seed_hex);
        let m = hex32(case.m_hex);
        let (pk, sk) = generate_keypair_from_seed(&seed)
            .unwrap_or_else(|e| panic!("ML-KEM-1024 keygen failed for {}: {:?}", case.label, e));
        let (ct, ss_enc) = encapsulate_deterministic(&pk, &m)
            .unwrap_or_else(|e| panic!("ML-KEM-1024 encap failed for {}: {:?}", case.label, e));
        let ss_dec = decapsulate(&sk, &ct)
            .unwrap_or_else(|e| panic!("ML-KEM-1024 decap failed for {}: {:?}", case.label, e));
        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref(),
            "ML-KEM-1024 roundtrip failed for {}", case.label);

        emit_record(case.label, &seed, &m, pk.as_ref(), sk.as_ref(),
                    ct.as_ref(), ss_enc.as_ref(), i == last);
    }

    println!("      ]");
    if last_variant {
        println!("    }}");
    } else {
        println!("    }},");
    }
}

fn main() {
    let _ = (
        cfg!(feature = "mlkem512"),
        cfg!(feature = "mlkem768"),
        cfg!(feature = "mlkem1024"),
    );

    #[cfg(not(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024")))]
    {
        eprintln!("emit_kat_fixtures: build with at least one of \
                   --features mlkem512 / mlkem768 / mlkem1024");
        std::process::exit(1);
    }

    println!("{{");
    println!("  \"spec\": \"FIPS 203\",");
    println!("  \"source\": \"metamui-crypto-rust/metamui-mlkem v3.0.0 (working reference)\",");
    println!("  \"variants\": {{");

    // Determine which variant is the last one enabled (for trailing-comma
    // handling), in declaration order 512 → 768 → 1024.
    let _has_512 = cfg!(feature = "mlkem512");
    let _has_768 = cfg!(feature = "mlkem768");
    let _has_1024 = cfg!(feature = "mlkem1024");

    #[cfg(feature = "mlkem512")]
    {
        #[cfg(any(feature = "mlkem768", feature = "mlkem1024"))]
        emit_variant_512(false);
        #[cfg(not(any(feature = "mlkem768", feature = "mlkem1024")))]
        emit_variant_512(true);
    }

    #[cfg(feature = "mlkem768")]
    {
        #[cfg(feature = "mlkem1024")]
        emit_variant_768(false);
        #[cfg(not(feature = "mlkem1024"))]
        emit_variant_768(true);
    }

    #[cfg(feature = "mlkem1024")]
    emit_variant_1024(true);

    println!("  }}");
    println!("}}");
}
