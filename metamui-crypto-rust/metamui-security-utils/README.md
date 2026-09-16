# MetaMUI Security Utils

Native security utilities: constant-time selection and comparison primitives, and secure memory clearing.

## Features

- **Constant-Time Primitives**: branch-free selection and comparison helpers
  - `Choice` type for constant-time booleans
  - `ConditionallySelectable` trait for branchless selection
  - `ConstantTimeEq` trait for timing-safe equality
  - `ConstantTimeGreater` trait for timing-safe comparisons

- **Secure Memory Clearing**: Prevent sensitive data recovery
  - `Zeroize` trait for secure memory clearing
  - Compiler optimization barriers
  - Platform-specific memory locking (Linux)
  - `Zeroizing` wrapper for automatic cleanup

## Usage

### Constant-Time Operations

```rust
use metamui_security_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

// Constant-time equality check
let a = 5u32;
let b = 5u32;
let equal = a.ct_eq(&b); // Choice(1)

// Constant-time conditional selection
let x = 10u32;
let y = 20u32;
let choice = Choice::from_u8(1);
let result = u32::conditional_select(&x, &y, choice); // Returns x
```

### Secure Memory Clearing

```rust
use metamui_security_utils::{Zeroize, Zeroizing};

// Manual zeroization
let mut secret = [1u8, 2, 3, 4];
secret.zeroize();
assert_eq!(secret, [0, 0, 0, 0]);

// Automatic zeroization on drop
{
    let secret = Zeroizing::new([1u8, 2, 3, 4]);
    // Use secret...
} // Automatically zeroized here
```

## Design properties

These are design intentions, not measured guarantees: no timing measurement has been made on any target.

1. **Constant-Time idioms**: the selection and comparison helpers are written without secret-dependent branches
2. **No Compiler Optimization**: Memory clearing uses volatile writes and barriers
3. **Memory Locking**: Optional memory locking to prevent swapping (Linux)
4. **No Unsafe Code**: Safe Rust implementation with minimal unsafe blocks

## Performance

This implementation is designed to match or exceed the performance of external
crates like `subtle` and `zeroize` while providing full control over the code.

## License

Apache License 2.0 - see the LICENSE file at the root of the distribution.