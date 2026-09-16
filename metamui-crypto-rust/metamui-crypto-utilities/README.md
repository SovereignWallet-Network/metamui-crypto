# MetaMUI Crypto Utilities

Shared cryptographic utilities and primitives for the MetaMUI ecosystem.

## Features

- **Secure Random**: Cryptographically secure random number generation
- **Constant-Time Helpers**: branch-free comparison for sensitive data (designed for constant time; unmeasured)
- **Memory Security**: Secure memory clearing with compiler optimization resistance
- **Bit Operations**: Efficient bit manipulation utilities
- **Endianness**: Byte order conversion utilities
- **Mathematical Operations**: Modular arithmetic and number theory utilities

## Usage

```rust
use metamui_crypto_utilities::prelude::*;

// Generate secure random bytes
let mut rng = SecureRandom::new();
let random_bytes = rng.generate_bytes(32)?;

// Constant-time comparison
let a = b"secret";
let b = b"secret";
assert!(ConstantTime::compare(a, b));

// Secure memory clearing
let mut sensitive_data = vec![1, 2, 3, 4];
SecureClear::clear_bytes(&mut sensitive_data);
```

## Features

- `std` (default): Standard library support
- `full` (default): All utilities enabled
- `hmac`: HMAC support
- `kdf`: Key derivation functions
- `encoding`: Encoding utilities (hex, base64, base58)
- `padding`: Padding schemes
- `mnemonic`: BIP39 mnemonic support

## Security

This library implements:
- Branch-free comparison helpers (designed for constant time; no timing measurement has been made)
- Secure memory clearing to prevent data leakage
- Validated entropy sources for random generation
- No unsafe code

## License

Apache License 2.0 — see the LICENSE file at the root of the distribution.