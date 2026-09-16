# MetaMUI ML-KEM

Pure Rust implementation of ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as specified in NIST FIPS 203.

## Features

- ✅ All three parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ✅ NIST Level 1, 3, and 5 security
- ✅ Written with constant-time idioms (designed for constant time; unmeasured)
- ✅ No external cryptographic dependencies
- ✅ Memory-safe implementation with zeroization
- ✅ FIPS 203 compliant

## Security Levels

| Parameter Set | NIST Level | Classical Security | Post-Quantum Security |
|--------------|------------|-------------------|----------------------|
| ML-KEM-512   | Level 1    | ≥ AES-128         | ~128 bits           |
| ML-KEM-768   | Level 3    | ≥ AES-192         | ~192 bits           |
| ML-KEM-1024  | Level 5    | ≥ AES-256         | ~256 bits           |

## Usage

```rust
use metamui_mlkem::{MLKem768, Kem};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    
    // Generate keypair
    let (public_key, secret_key) = MLKem768::generate_keypair(&mut rng)?;
    
    // Encapsulate (sender)
    let (ciphertext, shared_secret_sender) = MLKem768::encapsulate(&public_key, &mut rng)?;
    
    // Decapsulate (receiver)
    let shared_secret_receiver = MLKem768::decapsulate(&secret_key, &ciphertext)?;
    
    // Both parties now have the same shared secret
    assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
    
    Ok(())
}
```

## Parameter Selection

- **ML-KEM-512**: Lightweight applications, IoT devices
- **ML-KEM-768**: General purpose, recommended default
- **ML-KEM-1024**: High-security applications, long-term secrets

## Performance

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| KeyGen    | < 1ms      | < 2ms      | < 3ms       |
| Encapsulate | < 1ms    | < 1ms      | < 2ms       |
| Decapsulate | < 1ms    | < 1ms      | < 2ms       |

*Benchmarked on Apple M1 Pro*

## Implementation Details

This implementation follows NIST FIPS 203 exactly:
- Uses SHAKE-128 for matrix generation
- Uses SHAKE-256 for noise sampling
- Uses SHA3-256/512 for hashing
- Implements NTT for polynomial multiplication
- Uses centered binomial distribution for noise

## License

Apache License 2.0 - see the LICENSE file at the root of the distribution.

## Author

Phantom Seokgu Yun <phantom@metamui.id>