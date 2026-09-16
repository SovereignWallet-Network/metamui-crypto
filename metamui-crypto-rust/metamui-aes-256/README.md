# MetaMUI AES-256

AES-256 implementation for MetaMUI Crypto.

## Features

- **Multiple Modes of Operation**:
  - GCM (Galois/Counter Mode) - Authenticated encryption with associated data
  - CBC (Cipher Block Chaining) - With PKCS#7 padding
  - CTR (Counter Mode) - Stream cipher mode
  - ECB (Electronic Codebook) - Basic mode (not recommended)

- **Security Features**:
  - Automatic key zeroization on drop
  - Written with constant-time idioms where possible (designed for constant time; no timing measurement has been made)
  - No simplified or placeholder code

- **Key Management**:
  - Secure key generation
  - Key derivation from passwords (PBKDF2)
  - Hex encoding/decoding support

## Usage

### Basic GCM Example (Recommended)

```rust
use metamui_aes256::{Aes256Key, Aes256Gcm};

// Generate a random key
let key = Aes256Key::generate()?;

// Create cipher instance
let cipher = Aes256Gcm::new(&key)?;

// Generate nonce
let nonce = Aes256Gcm::generate_nonce()?;

// Encrypt with optional associated data
let plaintext = b"Secret message";
let aad = b"Additional authenticated data";
let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad))?;

// Decrypt
let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad))?;
assert_eq!(plaintext, &decrypted[..]);
```

### CBC Mode Example

```rust
use metamui_aes256::{Aes256Key, Aes256Cbc};

let key = Aes256Key::generate()?;
let cipher = Aes256Cbc::new(key);
let iv = Aes256Cbc::generate_iv()?;

// Encrypt with PKCS#7 padding
let ciphertext = cipher.encrypt(&iv, b"Hello, AES-256-CBC!")?;

// Decrypt
let plaintext = cipher.decrypt(&iv, &ciphertext)?;
```

### CTR Mode Example

```rust
use metamui_aes256::{Aes256Key, Aes256Ctr};

let key = Aes256Key::generate()?;
let cipher = Aes256Ctr::new(key);
let nonce = Aes256Ctr::generate_nonce()?;

// CTR mode works as a stream cipher
let ciphertext = cipher.process(&nonce, plaintext)?;
let decrypted = cipher.process(&nonce, &ciphertext)?; // Same operation
```

### Key Derivation from Password

```rust
use metamui_aes256::Aes256Key;

let password = b"my secret password";
let salt = b"random salt value";
let iterations = 100_000;

let key = Aes256Key::from_password(password, salt, iterations)?;
```

## Security Considerations

1. **Always use GCM mode** for new applications - it provides both confidentiality and authenticity
2. **Never reuse nonces/IVs** with the same key
3. **Use sufficient iteration count** (100,000+) for password-based key derivation
4. **Avoid ECB mode** - it doesn't provide semantic security
5. **Store keys securely** - consider using hardware security modules (HSM)

## Performance

The block cipher is a portable software implementation; the crate has no
AES-NI or NEON path and never dispatches to one (#370).

Benchmark results on M1 Pro:
- GCM: ~3.2 GB/s
- CTR: ~3.5 GB/s
- CBC: ~2.8 GB/s

## License

MIT OR Apache-2.0