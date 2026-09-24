use metamui_slhdsa::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PortableVectors {
    vectors: Vec<PortableVector>,
}

#[derive(Debug, Deserialize)]
// `secret_key` is read by serde but not currently asserted against in
// test bodies; cargo's dead-code analysis doesn't see the serde path.
#[allow(dead_code)]
struct PortableVector {
    context: String,
    message: String,
    parameter_set: String,
    public_key: String,
    secret_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpVectors {
    test_groups: Vec<AcvpGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpGroup {
    parameter_set: String,
    test_type: String,
    tests: Vec<AcvpTest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpTest {
    tc_id: u32,
    test_passed: bool,
    pk: Option<String>,
    sk: Option<String>,
    message: Option<String>,
    signature: Option<String>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex")
}

#[test]
fn test_portable_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/slh-dsa/slh_dsa_portable_vectors.json"
    );
    // Tracked vector file: absence is a broken checkout, not a skip (audit A28).
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let data: PortableVectors = serde_json::from_str(&json).unwrap();

    let mut passed = 0;

    for vec in data.vectors {
        let msg = hex_decode(&vec.message);
        let ctx = hex_decode(&vec.context);
        let pk_bytes = hex_decode(&vec.public_key);
        let sig_bytes = hex_decode(&vec.signature);

        let is_valid = match vec.parameter_set.as_str() {
            "SLH-DSA-SHAKE-128s" => {
                let pk = VerifyingKey::<SlhDsa128s>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa128s>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            "SLH-DSA-SHAKE-128f" => {
                let pk = VerifyingKey::<SlhDsa128f>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa128f>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            "SLH-DSA-SHAKE-192s" => {
                let pk = VerifyingKey::<SlhDsa192s>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa192s>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            "SLH-DSA-SHAKE-192f" => {
                let pk = VerifyingKey::<SlhDsa192f>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa192f>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            "SLH-DSA-SHAKE-256s" => {
                let pk = VerifyingKey::<SlhDsa256s>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa256s>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            "SLH-DSA-SHAKE-256f" => {
                let pk = VerifyingKey::<SlhDsa256f>::from_bytes(&pk_bytes).unwrap();
                let sig = Signature::<SlhDsa256f>::from_bytes(&sig_bytes).unwrap();
                pk.verify_with_context(&msg, &ctx, &sig).is_ok()
            }
            _ => continue,
        };

        assert!(is_valid, "Signature validation failed for parameter set: {}", vec.parameter_set);
        passed += 1;
    }

    println!("Successfully verified {} portable vectors.", passed);
}

#[test]
fn test_acvp_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/slh-dsa/slh_dsa_acvp_like_vectors.json"
    );
    // Tracked vector file: absence is a broken checkout, not a skip (audit A28).
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let data: AcvpVectors = serde_json::from_str(&json).unwrap();

    let mut tested = 0;
    let mut passed = 0;

    for group in data.test_groups {
        for test in group.tests {
            if group.test_type == "sigVer" || group.test_type == "sigGen" {
                if let (Some(pk_hex), Some(msg_hex), Some(sig_hex)) = (&test.pk, &test.message, &test.signature) {
                    let msg = hex_decode(msg_hex);
                    let pk_bytes = hex_decode(pk_hex);
                    let sig_bytes = hex_decode(sig_hex);

                    let verify_result = match group.parameter_set.as_str() {
                        "SLH-DSA-SHAKE-128s" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa128s>::from_bytes(&pk_bytes), Signature::<SlhDsa128s>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-128f" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa128f>::from_bytes(&pk_bytes), Signature::<SlhDsa128f>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-192s" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa192s>::from_bytes(&pk_bytes), Signature::<SlhDsa192s>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-192f" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa192f>::from_bytes(&pk_bytes), Signature::<SlhDsa192f>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-256s" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa256s>::from_bytes(&pk_bytes), Signature::<SlhDsa256s>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-256f" => {
                            if let (Ok(pk), Ok(sig)) = (VerifyingKey::<SlhDsa256f>::from_bytes(&pk_bytes), Signature::<SlhDsa256f>::from_bytes(&sig_bytes)) {
                                pk.verify_with_context(&msg, &[], &sig).is_ok()
                            } else { false }
                        }
                        _ => continue,
                    };

                    tested += 1;
                    if verify_result == test.test_passed {
                        passed += 1;
                    } else {
                        println!("Failed TC: {}, expected {}, got {}", test.tc_id, test.test_passed, verify_result);
                    }
                }
            } else if group.test_type == "keyGen" {
                if let (Some(pk_hex), Some(sk_hex)) = (&test.pk, &test.sk) {
                    let pk_bytes = hex_decode(pk_hex);
                    let sk_bytes = hex_decode(sk_hex);
                    
                    let verify_result = match group.parameter_set.as_str() {
                        "SLH-DSA-SHAKE-128s" => {
                            if let Ok(sk) = SigningKey::<SlhDsa128s>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-128f" => {
                            if let Ok(sk) = SigningKey::<SlhDsa128f>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-192s" => {
                            if let Ok(sk) = SigningKey::<SlhDsa192s>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-192f" => {
                            if let Ok(sk) = SigningKey::<SlhDsa192f>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-256s" => {
                            if let Ok(sk) = SigningKey::<SlhDsa256s>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        "SLH-DSA-SHAKE-256f" => {
                            if let Ok(sk) = SigningKey::<SlhDsa256f>::from_bytes(&sk_bytes) {
                                sk.verifying_key().to_bytes() == pk_bytes
                            } else { false }
                        }
                        _ => continue,
                    };
                    
                    tested += 1;
                    if verify_result == test.test_passed {
                        passed += 1;
                    } else {
                        println!("Failed keyGen TC: {}, expected {}, got {}", test.tc_id, test.test_passed, verify_result);
                    }
                }
            }
        }
    }

    assert_eq!(tested, passed, "Not all ACVP-like tests passed ({} out of {})", passed, tested);
    println!("Successfully verified {} ACVP-like vectors.", passed);
}
