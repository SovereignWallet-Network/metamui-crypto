//! SP 800-90A Rev. 1 conformance points the ACVP gate (kat_vectors.rs) cannot
//! reach: every ACVP hmacDRBG-1.0 record carries non-empty additional input,
//! and none makes tiny requests (review finding M-20).

use metamui_hmac_drbg::{HashAlgorithm, HmacDrbg, MAX_REQUEST_LENGTH};

const ALGS: [HashAlgorithm; 3] = [HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512];

fn seq(from: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| from.wrapping_add(i as u8)).collect()
}

/// Instantiate(00..1f, 20..2f, no perso); Generate(40, AI); Reseed(30..4f, AI);
/// Generate(40, AI) — returns both outputs.
fn script(alg: HashAlgorithm, ai: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
    let mut d = HmacDrbg::new(&seq(0, 32), Some(&seq(32, 16)), None, alg).unwrap();
    let mut a = vec![0u8; 40];
    d.generate(&mut a, ai).unwrap();
    d.reseed(&seq(48, 32), ai).unwrap();
    let mut b = vec![0u8; 40];
    d.generate(&mut b, ai).unwrap();
    (a, b)
}

/// SP 800-90A §4 defines Null as the empty string, and HMAC_DRBG_Update
/// (§10.1.2.2 step 3) / HMAC_DRBG_Generate (§10.1.2.5 step 2) branch on
/// `provided_data = Null`. `Some(&[])` used to run the second HMAC round of
/// the update (and the extra step-2 update), so it diverged from `None` and
/// from the Go binding, which tests `len(additionalInput) > 0`.
#[test]
fn empty_additional_input_is_null() {
    for alg in ALGS {
        assert_eq!(script(alg, Some(&[])), script(alg, None), "{alg:?}: Some(&[]) != None");
    }
}

/// Expected values from an independent Python (stdlib hmac) transcription of
/// §10.1.2, which reproduces all 90 SHA2-256/384/512 ACVP hmacDRBG-1.0
/// records before emitting these.
#[test]
fn empty_additional_input_kat() {
    let expected = [
        (
            HashAlgorithm::Sha256,
            "0ffb80875a3e9022a4941a3fa1b0d3611df14e1cf651a73ce9229b9f3ad56887680428845710288e",
            "26f85b0894d0404d79be1414566f09ce19e14c4d00798220d44d1720e425b880ae0cef64a9f98d80",
        ),
        (
            HashAlgorithm::Sha384,
            "290e3c0f81e1dd8e99e839fb98383fafc42d52d2cec7424d02ee75b628f981fe5e2375daa2b2315c",
            "30fe00c8e1b44022e7f54fee66de68e58b759153bfe8052d6a51fb79f9cc7318fef79db5060ea3d8",
        ),
        (
            HashAlgorithm::Sha512,
            "5a947e2ec811344b506f321e3f1fbde3fde96845301a7c1793e72b2071e1d984846eda8ee0e97301",
            "339d1c56b23363c05aecba2c6d5ec168225f7864f59e9ab764efac01458de04dce37c822eeb85c06",
        ),
    ];
    for (alg, a, b) in expected {
        let (got_a, got_b) = script(alg, Some(&[]));
        assert_eq!(hex::encode(got_a), a, "{alg:?} first generate");
        assert_eq!(hex::encode(got_b), b, "{alg:?} generate after reseed");
    }
}

/// The continuous test used to compare whole *requests*, so two consecutive
/// 1-byte requests collided with probability 1/256 and failed a healthy DRBG.
/// It now compares full outlen-byte blocks (2^-256 for SHA-256).
#[test]
fn one_byte_requests_never_trip_the_continuous_test() {
    let mut d = HmacDrbg::new(&[0x42u8; 32], None, None, HashAlgorithm::Sha256).unwrap();
    let mut b = [0u8; 1];
    for i in 0..20_000 {
        d.generate(&mut b, None).unwrap_or_else(|e| panic!("request {i}: {e:?}"));
    }
}

/// SP 800-90A Table 2: max_number_of_bits_per_request = 2^19 bits.
#[test]
fn request_limit_is_2_pow_19_bits() {
    assert_eq!(MAX_REQUEST_LENGTH * 8, 1 << 19);
    let mut d = HmacDrbg::new(&[7u8; 32], None, None, HashAlgorithm::Sha512).unwrap();
    let mut buf = vec![0u8; MAX_REQUEST_LENGTH + 1];
    assert!(d.generate(&mut buf[..MAX_REQUEST_LENGTH], None).is_ok());
    assert!(d.generate(&mut buf, None).is_err());
}
