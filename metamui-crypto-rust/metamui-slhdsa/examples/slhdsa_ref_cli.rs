//! Reference CLI bridge for canonical SLH-DSA operations.
//!
//! This executable provides a minimal command-line interface so non-Rust
//! language implementations can delegate keygen/sign/verify to the canonical
//! Rust backend during remediation.

use metamui_slhdsa::params::{
    SlhDsa128f, SlhDsa128s, SlhDsa192f, SlhDsa192s, SlhDsa256f, SlhDsa256s,
};
use metamui_slhdsa::{slh_keygen, slh_sign, slh_verify, Error};

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  slhdsa_ref_cli keygen <variant>");
    eprintln!("  slhdsa_ref_cli sign <variant> <message_hex> <secret_key_hex>");
    eprintln!("  slhdsa_ref_cli verify <variant> <message_hex> <signature_hex> <public_key_hex>");
    eprintln!();
    eprintln!("variants: 128s, 128f, 192s, 192f, 256s, 256f");
    std::process::exit(2);
}

fn normalize_variant(raw: &str) -> Option<&'static str> {
    let lower = raw.trim().to_ascii_lowercase();
    let compact = lower
        .replace("slh-dsa-shake-", "")
        .replace("slh-dsa-", "")
        .replace("shake-", "")
        .replace("sha2-", "")
        .replace("sha-", "");
    match compact.as_str() {
        "128s" => Some("128s"),
        "128f" => Some("128f"),
        "192s" => Some("192s"),
        "192f" => Some("192f"),
        "256s" => Some("256s"),
        "256f" => Some("256f"),
        _ => None,
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    hex::decode(input).map_err(|e| format!("invalid hex input: {e}"))
}

fn keygen_variant(variant: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    use rand::rngs::OsRng;
    match variant {
        "128s" => Ok(slh_keygen::<SlhDsa128s, _>(&mut OsRng)),
        "128f" => Ok(slh_keygen::<SlhDsa128f, _>(&mut OsRng)),
        "192s" => Ok(slh_keygen::<SlhDsa192s, _>(&mut OsRng)),
        "192f" => Ok(slh_keygen::<SlhDsa192f, _>(&mut OsRng)),
        "256s" => Ok(slh_keygen::<SlhDsa256s, _>(&mut OsRng)),
        "256f" => Ok(slh_keygen::<SlhDsa256f, _>(&mut OsRng)),
        _ => Err(format!("unsupported variant: {variant}")),
    }
}

fn sign_variant(variant: &str, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Error> {
    match variant {
        "128s" => slh_sign::<SlhDsa128s, rand::rngs::OsRng>(secret_key, message, None),
        "128f" => slh_sign::<SlhDsa128f, rand::rngs::OsRng>(secret_key, message, None),
        "192s" => slh_sign::<SlhDsa192s, rand::rngs::OsRng>(secret_key, message, None),
        "192f" => slh_sign::<SlhDsa192f, rand::rngs::OsRng>(secret_key, message, None),
        "256s" => slh_sign::<SlhDsa256s, rand::rngs::OsRng>(secret_key, message, None),
        "256f" => slh_sign::<SlhDsa256f, rand::rngs::OsRng>(secret_key, message, None),
        _ => Err(Error::InvalidParameters),
    }
}

fn verify_variant(
    variant: &str,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), Error> {
    match variant {
        "128s" => slh_verify::<SlhDsa128s>(public_key, message, signature),
        "128f" => slh_verify::<SlhDsa128f>(public_key, message, signature),
        "192s" => slh_verify::<SlhDsa192s>(public_key, message, signature),
        "192f" => slh_verify::<SlhDsa192f>(public_key, message, signature),
        "256s" => slh_verify::<SlhDsa256s>(public_key, message, signature),
        "256f" => slh_verify::<SlhDsa256f>(public_key, message, signature),
        _ => Err(Error::InvalidParameters),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let op = args[1].as_str();
    let variant = normalize_variant(&args[2]).unwrap_or_else(|| {
        eprintln!("unsupported variant: {}", args[2]);
        usage();
    });

    match op {
        "keygen" => {
            if args.len() != 3 {
                usage();
            }
            match keygen_variant(variant) {
                Ok((pk, sk)) => println!("{}:{}", hex::encode(pk), hex::encode(sk)),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "sign" => {
            if args.len() != 5 {
                usage();
            }
            let message = match decode_hex(&args[3]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            let secret_key = match decode_hex(&args[4]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            match sign_variant(variant, &message, &secret_key) {
                Ok(sig) => println!("{}", hex::encode(sig)),
                Err(e) => {
                    eprintln!("sign failed: {e:?}");
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            if args.len() != 6 {
                usage();
            }
            let message = match decode_hex(&args[3]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            let signature = match decode_hex(&args[4]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            let public_key = match decode_hex(&args[5]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            match verify_variant(variant, &message, &signature, &public_key) {
                Ok(()) => println!("OK"),
                Err(_) => println!("FAIL"),
            }
        }
        _ => usage(),
    }
}
