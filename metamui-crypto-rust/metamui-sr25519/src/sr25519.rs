use crate::Sr25519Error;
extern crate alloc;
use alloc::string::ToString;
use super::native::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use metamui_sha2::sha512::Sha512Hasher;

/// Divide a 256-bit little-endian scalar by 8 in place.
///
/// Matches `schnorrkel::scalars::divide_scalar_bytes_by_cofactor`
/// verbatim. Required by `expand_mini_secret_key` to compensate for
/// Ed25519's cofactor-8 clamping when the resulting scalar is used
/// against the Ristretto (prime-order) basepoint.
fn divide_scalar_bytes_by_cofactor(scalar: &mut [u8; 32]) {
    let mut low: u8 = 0;
    for b in scalar.iter_mut().rev() {
        let r = *b & 0b0000_0111; // save low 3 bits as remainder
        *b >>= 3;                 // divide this byte by 8
        *b += low;                // fold in carry from the byte above
        low = r << 5;             // carry for the next (lower) byte
    }
}

// Debug flag for VRF operations - set to false to disable debug output



/// SR25519 implementation using Ed25519 primitives
/// Based on the Python implementation which is known to work
pub struct Sr25519;

impl Sr25519 {
    /// Expand a 32-byte mini-secret key into (scalar_bytes, nonce_bytes)
    /// **matching `schnorrkel::MiniSecretKey::expand(ExpansionMode::Ed25519)`
    /// byte-for-byte**. Required for Polkadot/Substrate wire-compat.
    ///
    /// Algorithm (RFC 9496-adjacent; see schnorrkel/src/keys.rs:183):
    ///   1. `h = SHA-512(mini_secret)` — 64 bytes
    ///   2. `key = h[0..32]`, `nonce = h[32..64]`
    ///   3. Ed25519-style bit clamping on `key`:
    ///        `key[0]  &= 248`        (clear bits 0..2)
    ///        `key[31] &=  63`        (clear bits 6 **and** 7)
    ///        `key[31] |=  64`        (set bit 6)
    ///   4. **Divide `key` by the cofactor (8)** in place.
    ///      This is the critical step: the Ristretto basepoint has
    ///      prime order ℓ, so we must store the clamped Ed25519
    ///      scalar divided by 8. Previous versions of this crate
    ///      omitted steps (3b) and (4), which made every derived
    ///      public key diverge from schnorrkel.
    pub fn expand_mini_secret_key(mini_secret: &[u8]) -> Result<([u8; 32], [u8; 32]), Sr25519Error> {
        if mini_secret.len() != 32 {
            return Err(Sr25519Error::InvalidKey("Mini-secret key must be 32 bytes".to_string()));
        }

        // 1. SHA-512(mini_secret)
        let mut hasher = Sha512Hasher::new();
        hasher.update(mini_secret);
        let hash = hasher.finalize();

        // 2. Split
        let mut scalar_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        nonce_bytes.copy_from_slice(&hash[32..64]);

        // 3. Ed25519 clamp
        scalar_bytes[0]  &= 248; // clear low 3 bits
        scalar_bytes[31] &=  63; // clear high 2 bits (NOT &= 127 — that leaves bit 6's top alone)
        scalar_bytes[31] |=  64; // set bit 6

        // 4. Divide by the cofactor (= 8).
        divide_scalar_bytes_by_cofactor(&mut scalar_bytes);

        Ok((scalar_bytes, nonce_bytes))
    }

    /// Derive the Ristretto255 public key from a 32-byte mini-secret,
    /// matching `schnorrkel::MiniSecretKey::expand_to_public(Ed25519)`.
    ///
    /// Computes `pk = expanded_key · RISTRETTO_BASEPOINT` where the
    /// expanded key is already cofactor-divided by
    /// [`expand_mini_secret_key`]. Emits the 32-byte canonical RFC 9496
    /// encoding (NOT the Ed25519 compressed point encoding — those
    /// were the bytes this function previously returned, which made
    /// it look like Ed25519 RFC 8032 output and broke every compliance
    /// test).
    pub fn get_public_key(mini_secret: &[u8]) -> Result<[u8; 32], Sr25519Error> {
        let (scalar_bytes, _) = Self::expand_mini_secret_key(mini_secret)?;
        let pk_point = RistrettoPoint::base_point().mul(&scalar_bytes);
        Ok(pk_point.compress())
    }
    
    // ─────────────────────────────────────────────────────────────
    // Phase 5 cleanup: 6 dead Phase-1-era transcript helpers and
    // their `verify_with_transcript` plumbing have been removed.
    // The retired surface was:
    //   create_transcript / create_legacy_transcript /
    //   try_legacy_transcript_formats / verify_with_transcript /
    //   create_enhanced_transcript
    // None had any caller after Phase 3 wired sign/verify onto
    // Merlin+Ristretto. The compliance KAT in
    // `tests/kat_schnorrkel.rs` is the only authoritative parity
    // assertion now.
    // ─────────────────────────────────────────────────────────────


    /// Sign a message under `context` using the schnorrkel wire
    /// protocol.
    ///
    /// This replaces the previous SHA-512-based signing code. It now:
    ///
    ///   1. Builds a Merlin transcript identical to
    ///      `schnorrkel::SigningContext::new(ctx).bytes(msg)`:
    ///
    ///      ```text
    ///      Transcript::new(b"SigningContext")
    ///        .append_message(b"",           context)
    ///        .append_message(b"sign-bytes", message)
    ///        .append_message(b"proto-name", b"Schnorr-sig")
    ///        .append_message(b"sign:pk",    pk_compressed)
    ///      ```
    ///
    ///   2. Derives a deterministic 64-byte witness via a transcript
    ///      clone rekeyed with the 32-byte nonce seed from
    ///      `expand_mini_secret_key`, wide-reduced mod ℓ. Schnorrkel
    ///      additionally mixes in `OsRng`, but the verifier only
    ///      checks that `R, s` satisfy the Schnorr equation — not how
    ///      `r` was derived — so the deterministic form is
    ///      interoperable.
    ///
    ///   3. Computes `R = r · Ristretto_B` (real Ristretto255 base
    ///      point, not Edwards) and commits `sign:R` into the
    ///      transcript.
    ///
    ///   4. Derives `c = challenge_scalar(b"sign:c")` via **wide**
    ///      reduction of 64 challenge bytes — the previous
    ///      implementation used narrow reduction on 32 bytes, which
    ///      introduces measurable modular bias.
    ///
    ///   5. Emits `R || s` with `sig[63] |= 0x80` per schnorrkel's
    ///      Ed25519-vs-Schnorrkel wire discriminator.
    #[allow(non_snake_case)]
    pub fn sign(message: &[u8], mini_secret: &[u8], context: &[u8]) -> Result<[u8; 64], Sr25519Error> {
        if mini_secret.len() != 32 {
            return Err(Sr25519Error::InvalidKey(
                "Mini-secret key must be 32 bytes".to_string(),
            ));
        }

        // 1. Expand the mini-secret → (scalar_bytes, nonce_seed).
        //    scalar_bytes is already cofactor-divided and ready for
        //    Ristretto scalar mul.
        let (scalar_bytes, nonce_seed) = Self::expand_mini_secret_key(mini_secret)?;
        let a = Scalar::from_bytes_mod_order(scalar_bytes);

        // 2. Derive the Ristretto public key (for the `sign:pk` commit).
        let pk_bytes = RistrettoPoint::base_point().mul(&scalar_bytes).compress();

        // 3. Build the schnorrkel signing transcript.
        use crate::merlin::MerlinTranscript;
        let mut t = MerlinTranscript::for_signing_context(context, message);
        t.append_message(b"proto-name", b"Schnorr-sig");
        t.append_message(b"sign:pk", &pk_bytes);

        // 4. Deterministic witness scalar. Clone the transcript,
        //    feed in the nonce seed under b"signing", squeeze 64
        //    bytes of PRF, wide-reduce. This drops schnorrkel's
        //    OsRng mix-in — signatures become deterministic but
        //    remain verifiable by any schnorrkel-compatible verifier
        //    (the verify equation is blind to r's derivation).
        let mut witness_t = t.clone();
        witness_t.append_message(b"signing", &nonce_seed);
        let wide_r = witness_t.challenge_scalar_wide(b"signing");
        let r = Scalar::from_bytes_mod_order_wide(&wide_r);

        // 5. R = r · B (Ristretto basepoint).
        let R_bytes = RistrettoPoint::base_point().mul(&r.to_bytes()).compress();
        t.append_message(b"sign:R", &R_bytes);

        // 6. Challenge scalar `c` — wide reduction, NOT the previous
        //    buggy narrow reduction of 32 bytes.
        let wide_c = t.challenge_scalar_wide(b"sign:c");
        let c = Scalar::from_bytes_mod_order_wide(&wide_c);

        // 7. s = r + c · a   (NB: schnorrkel uses the same ordering,
        //    even though Schnorr literature sometimes writes s = k − c·a).
        let s = r.add(&c.mul(&a));
        let s_bytes = s.to_bytes();

        // 8. Assemble signature with the schnorrkel wire-format flag.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&R_bytes);
        signature[32..].copy_from_slice(&s_bytes);
        signature[63] |= 0x80;
        Ok(signature)
    }

    /// Verify an SR25519 signature
    pub fn verify(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        context: &[u8],
    ) -> Result<bool, Sr25519Error> {
        if public_key.len() != 32 {
            return Ok(false);
        }
        if signature.len() != 64 {
            return Ok(false);
        }

        // Schnorrkel wire-format flag bit.
        //
        // `Signature::from_bytes` in schnorrkel rejects any sig whose
        // byte[63] high bit is not set — preventing Ed25519-shaped
        // signatures from being silently accepted as sr25519. Apply
        // the same gate here for interop.
        if signature[63] & 0x80 == 0 {
            return Ok(false);
        }

        // Parse: R || s, with the flag bit stripped for scalar parse.
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        s_bytes.copy_from_slice(&signature[32..]);
        s_bytes[31] &= 0x7f; // clear the schnorrkel flag bit

        // Decode the Ristretto R and A points. Ristretto enforces
        // prime-order subgroup membership implicitly via the RFC 9496
        // validity check.
        let big_r = match RistrettoPoint::decompress(&r_bytes) {
            Some(p) => p,
            None => return Ok(false),
        };
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(public_key);
        let big_a = match RistrettoPoint::decompress(&pk_arr) {
            Some(p) => p,
            None => return Ok(false),
        };

        // Scalar parse — schnorrkel requires canonical form; our
        // `from_bytes_mod_order` implicitly reduces, which accepts
        // non-canonical s. Add an explicit canonical check: re-encode
        // and compare.
        let s = Scalar::from_bytes_mod_order(s_bytes);
        if s.to_bytes() != s_bytes {
            return Ok(false);
        }

        // Rebuild the transcript EXACTLY as the signer did.
        use crate::merlin::MerlinTranscript;
        let mut t = MerlinTranscript::for_signing_context(context, message);
        t.append_message(b"proto-name", b"Schnorr-sig");
        t.append_message(b"sign:pk", public_key);
        t.append_message(b"sign:R", &r_bytes);

        // c = challenge_scalar(b"sign:c") — wide reduction of 64 bytes.
        let wide_c = t.challenge_scalar_wide(b"sign:c");
        let c = Scalar::from_bytes_mod_order_wide(&wide_c);

        // Schnorr equation: s · B == R + c · A
        // (equivalent to schnorrkel's `vartime_double_scalar_mul_basepoint`).
        let lhs = RistrettoPoint::base_point().mul(&s.to_bytes());
        let rhs = big_r.add(&big_a.mul(&c.to_bytes()));

        Ok(lhs.compress() == rhs.compress())
    }
    
    // ─────────────────────────────────────────────────────────────
    // Phase 5 cleanup: `verify_with_legacy_compatibility` and
    // `verify_legacy` were removed alongside the legacy transcript
    // helpers. They tried to verify signatures produced by an older
    // (incompatible-with-schnorrkel) sign path that no longer exists
    // in this crate; the canonical entry point is
    // `Sr25519::verify`. Callers needing migration support should
    // re-sign their data with the current `Sr25519::sign`.
    // ─────────────────────────────────────────────────────────────
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    // EdwardsPoint is only used by `test_fundamental_operations`'s
    // primitive smoke checks — keep the import scoped to the test
    // module so production code doesn't depend on it.
    use super::super::native::curve::EdwardsPoint;

    #[test]
    fn test_mini_secret_expansion() {
        // Post-Phase-2 invariants on the expand_ed25519 output:
        //   1. Low 3 bits of byte[0] are cleared (Ed25519 clamp).
        //   2. After cofactor-division by 8, the pre-division top two
        //      bits of byte[31] shifted into byte[30..31]: byte[31]'s
        //      top bits must be 0 because we started from `&= 63`.
        //   3. Nonce must differ from scalar (guards against SHA-512
        //      aliasing).
        //
        // The prior version of this test asserted the clamp invariants
        // directly on byte[31] — but after cofactor division those
        // invariants no longer hold on byte[31] alone. The clamp is
        // now verified indirectly: our output matches
        // `schnorrkel::expand_ed25519` byte-for-byte, enforced by
        // `tests/kat_schnorrkel.rs::axis_a_public_key_derivation_matches_schnorrkel`.
        let mini_secret = [0x42u8; 32];
        let (scalar, nonce) = Sr25519::expand_mini_secret_key(&mini_secret).unwrap();
        // Post-cofactor-divide the explicit Ed25519 clamp bits are
        // NOT preserved on the output bytes — they shift around. The
        // clamp is instead verified end-to-end by the schnorrkel-
        // parity KAT in `tests/kat_schnorrkel.rs` (axis A).
        //
        // The only byte-level invariant that survives is the byte[31]
        // upper bound: before cofactor-divide, byte[31] had bits 7+6
        // cleared and bit 6 set, so the pre-divide value's MSByte is
        // at most 0x7f. After divide-by-8, byte[31] ≤ 0x0f, i.e. top
        // 4 bits are zero. Use that as the smoke assertion.
        assert_eq!(scalar[31] & 0b1111_0000, 0,
            "scalar[31] top nibble must be zero after cofactor-divide (got {:02x})",
            scalar[31]);
        assert_ne!(&scalar[..], &nonce[..]);

        // The `9d61…` mini_secret was historically asserted to produce
        // the Ed25519 RFC 8032 public key `d75a980182…`. That is an
        // Ed25519 bytes encoding — NOT a Ristretto255 sr25519 public
        // key. The real sr25519 pk for this seed is defined by the
        // schnorrkel KAT
        // `test-vectors/sr25519/sr25519-schnorrkel-kat.json` tc_id=7;
        // that assertion lives in `tests/kat_schnorrkel.rs`.
        //
        // Keep this call as a smoke test that `expand_mini_secret_key`
        // does not panic on the classic seed.
        let mini_secret = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ).unwrap();
        let _ = Sr25519::expand_mini_secret_key(&mini_secret).unwrap();
        let _ = Sr25519::get_public_key(&mini_secret).unwrap();
    }

    #[test]
    // -------------------------------------------------------------
    // Phase 2 side-effect: the tests from here down all exercise the
    // legacy SHA-512 sign/verify path. Since Phase 2 switched
    // `get_public_key` to emit RFC 9496 Ristretto255 bytes while
    // `sign`/`verify` still decompress keys as Ed25519 points, the
    // internal pipeline is temporarily inconsistent.
    // Phase 3 rewrites sign/verify on top of `RistrettoPoint` +
    // Merlin, at which point these tests either re-pass or are
    // replaced with the compliance KAT in `tests/kat_schnorrkel.rs`.
    // The compliance KAT is authoritative; these are secondary.
    // -------------------------------------------------------------
    fn test_sign_verify() {
        let mini_secret = [0x01u8; 32];
        let message = b"test message";
        let context = b"substrate";

        let signature = Sr25519::sign(message, &mini_secret, context).unwrap();
        let public_key = Sr25519::get_public_key(&mini_secret).unwrap();
        
        assert!(Sr25519::verify(message, &signature, &public_key, context).unwrap());
        
        // Wrong message should fail
        assert!(!Sr25519::verify(b"wrong", &signature, &public_key, context).unwrap());
    }

    #[test]
    #[ignore = "stale — asserted Ed25519 RFC 8032 pk as sr25519 pk; \
        real sr25519 parity is enforced by tests/kat_schnorrkel.rs (axis A)"]
    fn test_substrate_vectors() {
        // This test previously asserted that `get_public_key` on the
        // RFC 8032 seed `9d61…` produced `d75a980182…`. That is the
        // Ed25519 public key for the seed, NOT the Ristretto255
        // sr25519 public key. The correct expected value lives in
        // `test-vectors/sr25519/sr25519-schnorrkel-kat.json` tc_id=7
        // and is enforced by `tests/kat_schnorrkel.rs` Axis A.
        //
        // The body is preserved only so that re-enabling this test
        // after an intentional change remains visible in diff review.
        let mini_secret = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let expected_public = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();

        let public_key = Sr25519::get_public_key(&mini_secret).unwrap();
        assert_eq!(public_key.to_vec(), expected_public, "Public key mismatch");

        // Test signing
        let message = b"";
        let context = b"substrate";
        let signature = Sr25519::sign(message, &mini_secret, context).unwrap();
        
        // Verify signature
        assert!(Sr25519::verify(message, &signature, &public_key, context).unwrap());
    }

    #[test]
    fn test_polkadot_js_vectors() {
        // Test vector from polkadot-js
        let mini_secret = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let message = b"I am Alice";
        let context = b"substrate";
        
        let public_key = Sr25519::get_public_key(&mini_secret).unwrap();
        let signature = Sr25519::sign(message, &mini_secret, context).unwrap();
        
        // Should verify
        assert!(Sr25519::verify(message, &signature, &public_key, context).unwrap());
    }

    #[test]
    fn test_signature_verification_failure() {
        let mini_secret = [0x42u8; 32];
        let message = b"test message";
        let context = b"substrate";
        
        let public_key = Sr25519::get_public_key(&mini_secret).unwrap();
        let signature = Sr25519::sign(message, &mini_secret, context).unwrap();
        
        // Wrong message should fail
        assert!(!Sr25519::verify(b"wrong message", &signature, &public_key, context).unwrap());
        
        // Wrong context should fail
        assert!(!Sr25519::verify(message, &signature, &public_key, b"wrong").unwrap());
        
        // Wrong public key should fail
        let wrong_key = Sr25519::get_public_key(&[0x43u8; 32]).unwrap();
        assert!(!Sr25519::verify(message, &signature, &wrong_key, context).unwrap());
    }

    #[test]
    fn test_cross_language_compatibility() {
        // Test vectors that should match TypeScript and Python implementations
        let test_vectors = [
            (
                // Seed: "0000000000000000000000000000000000000000000000000000000000000001"
                hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                b"test message" as &[u8],
                b"substrate" as &[u8],
            ),
            (
                // Seed: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap(),
                b"Hello, SR25519!" as &[u8],
                b"substrate" as &[u8],
            ),
            (
                // Seed: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap(),
                b"" as &[u8], // Empty message
                b"substrate" as &[u8],
            ),
            (
                // Seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
                b"substrate signing test" as &[u8],
                b"substrate" as &[u8],
            ),
        ];

        for (i, (seed, message, context)) in test_vectors.iter().enumerate() {
            println!("\nTesting vector {}: seed={}, message={:?}", i, hex::encode(seed), std::str::from_utf8(message).unwrap_or("<binary>"));
            
            // Generate keypair and sign
            let public_key = Sr25519::get_public_key(seed).unwrap();
            let signature = Sr25519::sign(message, seed, context).unwrap();
            
            println!("  Public key: {}", hex::encode(&public_key));
            println!("  Signature:  {}", hex::encode(&signature));
            
            // Verify the signature
            assert!(Sr25519::verify(message, &signature, &public_key, context).unwrap(), 
                   "Vector {} should verify", i);
            
            // Test deterministic signatures (should be the same every time)
            let signature2 = Sr25519::sign(message, seed, context).unwrap();
            assert_eq!(signature, signature2, "Vector {} signatures should be deterministic", i);
            
            // Test that different message fails
            if !message.is_empty() {
                let mut wrong_message = message.to_vec();
                wrong_message[0] ^= 1; // Flip one bit
                assert!(!Sr25519::verify(&wrong_message, &signature, &public_key, context).unwrap(),
                       "Vector {} should fail with wrong message", i);
            }
        }
    }

    #[test]
    fn test_enhanced_key_expansion() {
        // Test that our key expansion matches expected behavior
        let test_seeds = [
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap(),
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
        ];

        for (i, seed) in test_seeds.iter().enumerate() {
            let (scalar, nonce) = Sr25519::expand_mini_secret_key(seed).unwrap();
            let public_key = Sr25519::get_public_key(seed).unwrap();
            
            println!("\nTest seed {}: {}", i, hex::encode(seed));
            println!("  Expanded scalar: {}", hex::encode(&scalar));
            println!("  Expanded nonce:  {}", hex::encode(&nonce));
            println!("  Public key:      {}", hex::encode(&public_key));
            
            // The Ed25519 clamp bits were applied BEFORE
            // `divide_scalar_bytes_by_cofactor`; after the divide the
            // byte-level clamp invariants don't survive on the
            // resulting bytes. See `test_mini_secret_expansion` for
            // the post-divide invariant we can assert, and
            // `tests/kat_schnorrkel.rs` axis A for byte-exact parity
            // with schnorrkel's `expand_ed25519`.
            assert_eq!(scalar[31] & 0b1111_0000, 0,
                "post-cofactor-divide scalar[31] must fit in low nibble");
            
            // Verify nonce is different from scalar
            assert_ne!(&scalar[..], &nonce[..], "Nonce should be different from scalar");
            
            // Test that the same seed produces the same results
            let (scalar2, nonce2) = Sr25519::expand_mini_secret_key(seed).unwrap();
            let public_key2 = Sr25519::get_public_key(seed).unwrap();
            
            assert_eq!(scalar, scalar2, "Scalar expansion should be deterministic");
            assert_eq!(nonce, nonce2, "Nonce expansion should be deterministic");
            assert_eq!(public_key, public_key2, "Public key derivation should be deterministic");
        }
    }

    #[test]
    fn test_context_sensitivity() {
        // Test that different contexts produce different signatures
        let seed = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        let message = b"test message";
        
        let contexts = [b"substrate" as &[u8], b"polkadot", b"kusama", b"westend"];
        let mut signatures = Vec::new();
        
        for context in &contexts {
            let signature = Sr25519::sign(message, &seed, context).unwrap();
            let public_key = Sr25519::get_public_key(&seed).unwrap();
            
            // Should verify with correct context
            assert!(Sr25519::verify(message, &signature, &public_key, context).unwrap());
            
            // Should NOT verify with different context
            for other_context in &contexts {
                if other_context != context {
                    assert!(!Sr25519::verify(message, &signature, &public_key, other_context).unwrap(),
                           "Signature with context {:?} should not verify with context {:?}", 
                           std::str::from_utf8(context), std::str::from_utf8(other_context));
                }
            }
            
            signatures.push(signature);
        }
        
        // All signatures should be different
        for i in 0..signatures.len() {
            for j in i+1..signatures.len() {
                assert_ne!(signatures[i], signatures[j], 
                          "Signatures with different contexts should be different");
            }
        }
    }

    #[test]
    fn test_edge_cases() {
        let seed = [0x42u8; 32];
        let public_key = Sr25519::get_public_key(&seed).unwrap();
        let context = b"substrate";
        
        // Test empty message
        let empty_sig = Sr25519::sign(b"", &seed, context).unwrap();
        assert!(Sr25519::verify(b"", &empty_sig, &public_key, context).unwrap());
        
        // Test very long message
        let long_message = vec![0x55u8; 10000];
        let long_sig = Sr25519::sign(&long_message, &seed, context).unwrap();
        assert!(Sr25519::verify(&long_message, &long_sig, &public_key, context).unwrap());
        
        // Test empty context
        let empty_ctx_sig = Sr25519::sign(b"test", &seed, b"").unwrap();
        assert!(Sr25519::verify(b"test", &empty_ctx_sig, &public_key, b"").unwrap());
        
        // Test very long context
        let long_context = vec![0xAAu8; 1000];
        let long_ctx_sig = Sr25519::sign(b"test", &seed, &long_context).unwrap();
        assert!(Sr25519::verify(b"test", &long_ctx_sig, &public_key, &long_context).unwrap());
    }


    #[test]
    fn test_scalar_serialization() {
        // Test scalar serialization/deserialization consistency
        use hex;
        
        println!("=== TESTING SCALAR SERIALIZATION ===");
        
        // Create a test scalar from hash
        let test_bytes = [0xb4, 0xea, 0x9e, 0xcd, 0x94, 0x57, 0x1f, 0xaf, 
                         0xce, 0x76, 0x6c, 0x6e, 0x57, 0xbe, 0x4e, 0xd3, 
                         0xec, 0x9b, 0x8f, 0x5f, 0xaa, 0x44, 0x8d, 0xf8, 
                         0xd1, 0x30, 0xd1, 0x74, 0xe5, 0x76, 0x85, 0x00];
        
        let scalar1 = Scalar::from_bytes_mod_order(test_bytes);
        let bytes1 = scalar1.to_bytes();
        println!("Original bytes: {}", hex::encode(&test_bytes));
        println!("Scalar bytes:   {}", hex::encode(&bytes1));
        
        let scalar2 = Scalar::from_bytes_mod_order(bytes1);
        let bytes2 = scalar2.to_bytes();
        println!("Round-trip:     {}", hex::encode(&bytes2));
        
        assert_eq!(bytes1, bytes2, "Scalar round-trip should be consistent");
        
        // Test with the actual challenge bytes that are failing
        let challenge_bytes = hex::decode("cb36cf007a453303abeea9e04235be83acdc1e87a73f931ddcc84f4ee20bc5b4").unwrap();
        let challenge_array: [u8; 32] = challenge_bytes.try_into().unwrap();
        
        let challenge_scalar = Scalar::from_bytes_mod_order(challenge_array);
        let challenge_serialized = challenge_scalar.to_bytes();
        
        println!("Challenge original: {}", hex::encode(&challenge_array));
        println!("Challenge parsed:   {}", hex::encode(&challenge_serialized));
        
        let challenge_parsed = Scalar::from_bytes_mod_order(challenge_serialized);
        let challenge_final = challenge_parsed.to_bytes();
        
        println!("Challenge final:    {}", hex::encode(&challenge_final));
        
        assert_eq!(challenge_serialized, challenge_final, "Challenge round-trip should be consistent");
    }

    // Phase 5 cleanup: `test_enhanced_transcript` exercised the
    // retired `create_transcript` / `create_enhanced_transcript`
    // helpers. The Merlin transcript surface is now tested directly
    // by `tests/merlin_parity_kat.rs` against reference `merlin =
    // "=3.0.0"`, which is a much stronger assertion than the old
    // "is the byte vector longer than the previous one" smoke test.

    #[test]
    fn test_optimization_benchmarks() {
        // Basic performance test to ensure optimizations don't break functionality
        let seed = [0x55u8; 32];
        let _message = b"performance test message";
        let context = b"substrate";
        
        let public_key = Sr25519::get_public_key(&seed).unwrap();
        
        // Test multiple sign/verify cycles
        for i in 0..10 {
            let test_message = format!("test message {}", i);
            let signature = Sr25519::sign(test_message.as_bytes(), &seed, context).unwrap();
            assert!(Sr25519::verify(test_message.as_bytes(), &signature, &public_key, context).unwrap(),
                   "Iteration {} should verify", i);
        }
        
        println!("Performance test completed successfully");
    }

    #[test]
    fn test_fundamental_operations() {
        println!("\n=== Testing Fundamental Operations ===");
        
        // Test 1: Basic scalar arithmetic
        let k = Scalar::from_bytes_mod_order([5u8; 32]);
        let c = Scalar::from_bytes_mod_order([3u8; 32]);
        let x = Scalar::from_bytes_mod_order([7u8; 32]);
        
        println!("Test scalars:");
        println!("  k: {}", hex::encode(&k.to_bytes()));
        println!("  c: {}", hex::encode(&c.to_bytes()));
        println!("  x: {}", hex::encode(&x.to_bytes()));
        
        // Test scalar multiplication: c * x
        let cx = c.mul(&x);
        println!("  c*x: {}", hex::encode(&cx.to_bytes()));
        
        // Test scalar addition: k + (c * x)
        let s = k.add(&cx);
        println!("  s = k + c*x: {}", hex::encode(&s.to_bytes()));
        
        // Test 2: Point-scalar operations
        let h_point = EdwardsPoint::base_point();
        println!("\nTest point operations:");
        println!("  H (base point): {}", hex::encode(&h_point.compress()));
        
        // Test point-scalar multiplication
        let kh = h_point.scalar_mul(&k.to_bytes());
        let sh = h_point.scalar_mul(&s.to_bytes());
        let xh = h_point.scalar_mul(&x.to_bytes());  // This is Gamma
        let cxh = xh.scalar_mul(&c.to_bytes());     // This is c*Gamma
        
        println!("  k*H: {}", hex::encode(&kh.compress()));
        println!("  s*H: {}", hex::encode(&sh.compress()));
        println!("  x*H (Gamma): {}", hex::encode(&xh.compress()));
        println!("  c*(x*H) = c*Gamma: {}", hex::encode(&cxh.compress()));
        
        // Test 3: Point subtraction
        let sh_minus_cxh = sh.sub(&cxh);
        println!("  s*H - c*Gamma: {}", hex::encode(&sh_minus_cxh.compress()));
        
        // Test 4: The fundamental equation: k*H should equal s*H - c*Gamma
        println!("\nFundamental equation test:");
        println!("  Expected (k*H): {}", hex::encode(&kh.compress()));
        println!("  Computed (s*H - c*Gamma): {}", hex::encode(&sh_minus_cxh.compress()));
        
        if kh.equals(&sh_minus_cxh) {
            println!("  ✅ Fundamental equation PASSED!");
        } else {
            println!("  ❌ Fundamental equation FAILED!");
            
            // Debug step by step
            println!("\nDebugging step by step:");
            
            // Verify: s = k + c*x by checking s - k = c*x
            let s_minus_k = s.sub(&k);
            println!("  s - k: {}", hex::encode(&s_minus_k.to_bytes()));
            println!("  c*x:   {}", hex::encode(&cx.to_bytes()));
            if s_minus_k == cx {
                println!("  ✅ Scalar equation s = k + c*x is correct");
            } else {
                println!("  ❌ Scalar equation s = k + c*x is WRONG!");
            }
            
            // Verify distributive property: (k + c*x)*H = k*H + (c*x)*H
            let cx_h = h_point.scalar_mul(&cx.to_bytes());
            let kh_plus_cxh = kh.add(&cx_h);
            println!("  k*H + (c*x)*H: {}", hex::encode(&kh_plus_cxh.compress()));
            println!("  (k + c*x)*H:   {}", hex::encode(&sh.compress()));
            if kh_plus_cxh.equals(&sh) {
                println!("  ✅ Distributive property k*H + (c*x)*H = (k + c*x)*H works");
            } else {
                println!("  ❌ Distributive property FAILED!");
            }
            
            // Check if c*(x*H) = (c*x)*H
            println!("  (c*x)*H: {}", hex::encode(&cx_h.compress()));
            println!("  c*(x*H): {}", hex::encode(&cxh.compress()));
            if cx_h.equals(&cxh) {
                println!("  ✅ Scalar multiplication associativity works");
            } else {
                println!("  ❌ Scalar multiplication associativity FAILED!");
            }
        }
    }

}
