/**
 * ML-KEM-768 Key Encapsulation Mechanism
 *
 * NIST FIPS 203 (Fujisaki-Okamoto transform). As of the Finding #28 in-tree
 * FIPS 203 port, this module is a thin facade over the byte-exact generic
 * engine in [`crate::kem`] (parameterized with `MLKEM768_PARAMS`). The former
 * self-contained 768 fork (its own indcpa/ntt/serialize/compress/sampling)
 * diverged from FIPS 203 final in exactly the same way the generic engine did
 * (t̂/ŝ packed in the wrong domain); routing through the single corrected
 * engine guarantees byte-equality with NIST ACVP vectors and keeps one source
 * of truth across all three parameter sets.
 */
use crate::kem as engine;
use crate::mlkem768::error::{MLKemError, MLKemResult};
use crate::mlkem768::types::{Ciphertext, KeyPair, PrivateKey, PublicKey, SharedSecret};
use crate::params::MLKEM768_PARAMS;
use rand_core::{CryptoRng, RngCore};

const PK: usize = 1184;
const SK: usize = 2400;
const CT: usize = 1088;

/// Map the crate-level engine error into the 768 module's error type. The
/// FIPS 203 §7 input-check failures keep their meaning (#323); anything else
/// is an engine fault.
fn map_err(e: crate::error::MLKemError) -> MLKemError {
    use crate::error::MLKemError as E;
    match e {
        E::InvalidPublicKey => MLKemError::InvalidPublicKey,
        E::InvalidSecretKey => MLKemError::InvalidPrivateKey,
        E::InvalidCiphertext | E::InvalidCiphertextSize => MLKemError::InvalidCiphertext,
        _ => MLKemError::ImplementationError("ML-KEM-768 engine error".into()),
    }
}

/// Generate an ML-KEM-768 keypair (ML-KEM.KeyGen, FIPS 203 Alg 19).
pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> MLKemResult<KeyPair> {
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    engine::mlkem_keygen(&MLKEM768_PARAMS, &mut pk, &mut sk, rng).map_err(map_err)?;
    Ok(KeyPair::new(PublicKey::from_bytes(pk), PrivateKey::from_bytes(sk)))
}

/// Generate an ML-KEM-768 keypair from explicit `(d, z)` (FIPS 203 §6.1
/// KeyGen_internal). Two independent 32-byte inputs as the spec defines —
/// used for NIST ACVP keyGen byte-equality.
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn generate_keypair_from_dz(d: &[u8; 32], z: &[u8; 32]) -> MLKemResult<KeyPair> {
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    engine::mlkem_keygen_from_dz(&MLKEM768_PARAMS, &mut pk, &mut sk, d, z).map_err(map_err)?;
    Ok(KeyPair::new(PublicKey::from_bytes(pk), PrivateKey::from_bytes(sk)))
}

/// Generate an ML-KEM-768 keypair deterministically from a single 32-byte
/// seed (single-seed convenience contract: `d := seed`,
/// `z := SHA3-256(seed ‖ "z_derivation")`).
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> MLKemResult<KeyPair> {
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    engine::mlkem_keygen_from_seed(&MLKEM768_PARAMS, &mut pk, &mut sk, seed).map_err(map_err)?;
    Ok(KeyPair::new(PublicKey::from_bytes(pk), PrivateKey::from_bytes(sk)))
}

/// Encapsulate a shared secret (ML-KEM.Encaps, FIPS 203 Alg 20).
pub fn encapsulate<R: RngCore + CryptoRng>(
    public_key: &PublicKey,
    rng: &mut R,
) -> MLKemResult<(Ciphertext, SharedSecret)> {
    let mut ct = [0u8; CT];
    let mut ss = [0u8; 32];
    engine::mlkem_encapsulate(&MLKEM768_PARAMS, public_key.as_bytes(), &mut ct, &mut ss, rng)
        .map_err(map_err)?;
    Ok((Ciphertext::from_bytes(ct), SharedSecret::from_bytes(ss)))
}

/// Deterministic encapsulation using `m` as the message (FIPS 203 §6.2
/// Encaps_internal). For KAT generation and byte-equality checks.
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn encapsulate_deterministic(
    public_key: &PublicKey,
    m: &[u8; 32],
) -> MLKemResult<(Ciphertext, SharedSecret)> {
    let mut ct = [0u8; CT];
    let mut ss = [0u8; 32];
    engine::mlkem_encapsulate_deterministic(
        &MLKEM768_PARAMS,
        public_key.as_bytes(),
        &mut ct,
        &mut ss,
        m,
    )
    .map_err(map_err)?;
    Ok((Ciphertext::from_bytes(ct), SharedSecret::from_bytes(ss)))
}

/// Decapsulate a shared secret (ML-KEM.Decaps, FIPS 203 Alg 21, with implicit
/// rejection).
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> MLKemResult<SharedSecret> {
    let mut ss = [0u8; 32];
    engine::mlkem_decapsulate(
        &MLKEM768_PARAMS,
        private_key.as_bytes(),
        ciphertext.as_bytes(),
        &mut ss,
    )
    .map_err(map_err)?;
    Ok(SharedSecret::from_bytes(ss))
}

/// Verify that a ciphertext is the correct size for ML-KEM-768.
#[allow(dead_code)]
pub fn verify_ciphertext(_public_key: &PublicKey, ciphertext: &Ciphertext) -> bool {
    ciphertext.as_bytes().len() == CT
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_kem_keygen() {
        let mut rng = thread_rng();
        let keypair = generate_keypair(&mut rng).unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), PK);
        assert_eq!(keypair.private_key.as_bytes().len(), SK);
    }

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let seed = [42u8; 32];
        let keypair = generate_keypair_from_seed(&seed).unwrap();
        let m = [1u8; 32];

        let (ciphertext, ss_enc) = encapsulate_deterministic(&keypair.public_key, &m).unwrap();
        assert_eq!(ciphertext.as_bytes().len(), CT);

        let ss_dec = decapsulate(&keypair.private_key, &ciphertext).unwrap();
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_multiple_encapsulations() {
        let mut rng = thread_rng();
        let keypair = generate_keypair(&mut rng).unwrap();

        let (ct1, ss1) = encapsulate(&keypair.public_key, &mut rng).unwrap();
        let (ct2, ss2) = encapsulate(&keypair.public_key, &mut rng).unwrap();
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        let ss1_dec = decapsulate(&keypair.private_key, &ct1).unwrap();
        let ss2_dec = decapsulate(&keypair.private_key, &ct2).unwrap();
        assert_eq!(ss1.as_bytes(), ss1_dec.as_bytes());
        assert_eq!(ss2.as_bytes(), ss2_dec.as_bytes());
    }

    #[test]
    fn test_invalid_ciphertext_implicit_reject() {
        let mut rng = thread_rng();
        let keypair = generate_keypair(&mut rng).unwrap();
        let (ciphertext, _) = encapsulate(&keypair.public_key, &mut rng).unwrap();

        let mut corrupted_bytes = *ciphertext.as_bytes();
        corrupted_bytes[0] ^= 0xFF;
        let corrupted_ct = Ciphertext::from_bytes(corrupted_bytes);

        // Implicit rejection: decap succeeds but yields a different (pseudorandom) ss.
        let invalid_ss = decapsulate(&keypair.private_key, &corrupted_ct).unwrap();
        let good_ss = decapsulate(&keypair.private_key, &ciphertext).unwrap();
        assert_ne!(good_ss.as_bytes(), invalid_ss.as_bytes());
    }

    #[test]
    fn test_deterministic_encapsulation() {
        let mut rng = thread_rng();
        let keypair = generate_keypair(&mut rng).unwrap();
        let m = [42u8; 32];

        let (ct1, ss1) = encapsulate_deterministic(&keypair.public_key, &m).unwrap();
        let (ct2, ss2) = encapsulate_deterministic(&keypair.public_key, &m).unwrap();
        assert_eq!(ct1.as_bytes(), ct2.as_bytes());
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
