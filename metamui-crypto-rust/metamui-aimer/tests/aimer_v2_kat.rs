use metamui_aimer::{
    aim2::Aim2,
    signing::{PublicKey, Signature},
    Aim2erI, Aim2erIF, Aim2erIII, Aim2erIIIF, Aim2erV, Aim2erVF, Aimer, AimerParams,
};

struct KatEntry {
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
    msg: Vec<u8>,
    sm_bytes: Vec<u8>,
    mlen: usize,
}

// Section 1: KAT parser

fn parse_rsp(path: &str) -> Vec<KatEntry> {
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Cannot read {}: {}", path, e));
    let mut entries = Vec::new();
    let mut pk = None;
    let mut sk = None;
    let mut msg = None;
    let mut sm = None;
    let mut mlen = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if let (Some(p), Some(s), Some(m), Some(sm_val), Some(ml)) =
                (pk.take(), sk.take(), msg.take(), sm.take(), mlen.take())
            {
                entries.push(KatEntry {
                    pk_bytes: p,
                    sk_bytes: s,
                    msg: m,
                    sm_bytes: sm_val,
                    mlen: ml,
                });
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("pk = ") {
            pk = Some(hex::decode(v).expect("bad pk hex"));
        } else if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(hex::decode(v).expect("bad sk hex"));
        } else if let Some(v) = line.strip_prefix("msg = ") {
            msg = Some(hex::decode(v).expect("bad msg hex"));
        } else if let Some(v) = line.strip_prefix("sm = ") {
            sm = Some(hex::decode(v).expect("bad sm hex"));
        } else if let Some(v) = line.strip_prefix("mlen = ") {
            mlen = Some(v.parse::<usize>().expect("bad mlen"));
        }
    }
    // flush last entry
    if let (Some(p), Some(s), Some(m), Some(sm_val), Some(ml)) = (pk, sk, msg, sm, mlen) {
        entries.push(KatEntry {
            pk_bytes: p,
            sk_bytes: s,
            msg: m,
            sm_bytes: sm_val,
            mlen: ml,
        });
    }

    assert!(!entries.is_empty(), "No entries parsed from {}", path);
    entries
}

fn reconstruct_pk<P: AimerParams>(pk_bytes: &[u8]) -> PublicKey {
    assert_eq!(
        pk_bytes.len(),
        P::PUBLIC_KEY_SIZE,
        "pk size mismatch : got {} want {}",
        pk_bytes.len(),
        P::PUBLIC_KEY_SIZE
    );

    PublicKey {
        iv: pk_bytes[..P::FIELD_SIZE].to_vec(),
        ct: pk_bytes[P::FIELD_SIZE..].to_vec(),
    }
}

// Section 2: Key-size tests

#[test]
fn test_key_sizes_aimer128f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128f/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erI::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erI::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
#[test]
fn test_key_sizes_aimer128s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128s/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erI::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erI::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
#[test]
fn test_key_sizes_aimer192f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192f/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erIII::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erIII::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
#[test]
fn test_key_sizes_aimer192s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192s/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erIII::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erIII::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
#[test]
fn test_key_sizes_aimer256f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256f/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erV::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erV::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
#[test]
fn test_key_sizes_aimer256s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256s/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.pk_bytes.len(),
            Aim2erV::PUBLIC_KEY_SIZE,
            "entry {}: pk size",
            i
        );
        assert_eq!(
            e.sk_bytes.len(),
            Aim2erV::SECRET_KEY_SIZE,
            "entry {}: sk size",
            i
        );
    }
}
// Section 3: AIM function tests (diagnostic)

#[test]
fn test_aim_function_aimer128f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128f/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erI>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erI::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erI::FIELD_SIZE..Aim2erI::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erI::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}
#[test]
fn test_aim_function_aimer128s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128s/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erI>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erI::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erI::FIELD_SIZE..Aim2erI::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erI::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}
#[test]
fn test_aim_function_aimer192f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192f/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erIII>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erIII::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erIII::FIELD_SIZE..Aim2erIII::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erIII::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}
#[test]
fn test_aim_function_aimer192s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192s/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erIII>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erIII::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erIII::FIELD_SIZE..Aim2erIII::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erIII::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}
#[test]
fn test_aim_function_aimer256f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256f/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erV>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erV::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erV::FIELD_SIZE..Aim2erV::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erV::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}
#[test]
fn test_aim_function_aimer256s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256s/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);
    let aim = Aim2::<Aim2erV>::new();
    let mut failures = 0;

    for (i, e) in entries.iter().enumerate() {
        let raw_sk = &e.sk_bytes[..Aim2erV::FIELD_SIZE];
        let iv = &e.sk_bytes[Aim2erV::FIELD_SIZE..Aim2erV::FIELD_SIZE * 2];
        let ct_expected = &e.sk_bytes[Aim2erV::FIELD_SIZE * 2..];
        let ct_got = aim.evaluate(iv, raw_sk).expect("AIM eval failed");

        if ct_got != ct_expected {
            failures += 1;
            eprintln!(
                "entry {}: AIM mismatch\n  got:      {}\n  expected: {}",
                i,
                hex::encode(&ct_got),
                hex::encode(ct_expected)
            );
        }
    }
    assert_eq!(
        failures,
        0,
        "{}/{} AIM entries  failed - see stderr",
        failures,
        entries.len()
    )
}

// Section 4: Genuine-upstream signature verification (sm field)
//
// These tests parse the `sm` field from the vendored *genuine* Samsung SDS KAT
// (test-vectors/aimer-upstream/, spec v260130) and verify it with our verifier.
// They pass as of the v260130 conformance fix (per-variant H0_PREFIX + the
// ctxlen=0x00 pre-byte in mu); previously the whole file pointed at the
// self-generated `aimer-kpqc-official/` vectors, a circular check.
// `tests/aimer_upstream_kat.rs` is the canonical, exhaustive conformance gate.

#[test]
fn test_sm_verify_aimer128s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128s/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().take(3).enumerate() {
        let pk = reconstruct_pk::<Aim2erI>(&e.pk_bytes);

        // sm = msg || signature_bytes  (reference: smlen = mlen + CRYPTO_BYTES)
        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erI>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erI>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}

#[test]
fn test_sm_verify_aimer128f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-128f/PQCsignKAT_48.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().take(3).enumerate() {
        let pk = reconstruct_pk::<Aim2erIF>(&e.pk_bytes);

        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erIF>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erIF>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}

#[test]
fn test_sm_verify_aimer192s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192s/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().take(3).enumerate() {
        let pk = reconstruct_pk::<Aim2erIII>(&e.pk_bytes);

        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erIII>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erIII>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}

#[test]
fn test_sm_verify_aimer192f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-192f/PQCsignKAT_72.rsp";
    let entries = parse_rsp(path);

    for (i, e) in entries.iter().take(3).enumerate() {
        let pk = reconstruct_pk::<Aim2erIIIF>(&e.pk_bytes);

        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erIIIF>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erIIIF>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}

#[test]
fn test_sm_verify_aimer256s() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256s/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);

    // Partial: 1 entry — 256-bit field with L=3 S-boxes is the heaviest parameter set
    for (i, e) in entries.iter().take(1).enumerate() {
        let pk = reconstruct_pk::<Aim2erV>(&e.pk_bytes);

        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erV>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erV>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}

#[test]
fn test_sm_verify_aimer256f() {
    let path = "../../test-vectors/aimer-upstream/v2.1/aimer-256f/PQCsignKAT_96.rsp";
    let entries = parse_rsp(path);

    // Partial: 1 entry — 256-bit field with L=3 S-boxes and tau=65 is the heaviest variant
    for (i, e) in entries.iter().take(1).enumerate() {
        let pk = reconstruct_pk::<Aim2erVF>(&e.pk_bytes);

        assert_eq!(
            &e.sm_bytes[..e.mlen],
            e.msg.as_slice(),
            "entry {}: sm prefix does not match msg",
            i
        );
        let sig_bytes = &e.sm_bytes[e.mlen..];

        let sig = Signature::from_bytes::<Aim2erVF>(sig_bytes)
            .unwrap_or_else(|err| panic!("entry {}: from_bytes failed: {:?}", i, err));

        let ok = Aimer::<Aim2erVF>::verify(&e.msg, &sig, &pk)
            .unwrap_or_else(|err| panic!("entry {}: verify failed: {:?}", i, err));

        assert!(
            ok,
            "entry {}: reference signature rejected by our verifier",
            i
        );
    }
}
