// MetaMUI metamui sr25519   native
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// See LICENSE for full terms.
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Native Sr25519 implementation
/// This module provides a pure Rust implementation of Sr25519
/// without external dependencies

pub mod field_radix51;
pub use field_radix51 as field;
pub mod curve;
pub mod scalar;
pub mod ristretto;
pub mod constant_time_wrapper;
// pub use constant_time_wrapper as constant_time; // TODO: Re-enable when needed

#[cfg(test)]
mod test_scalar_mul;
#[cfg(test)]
mod sqrt_test;

// Phase 4 (sr25519 compliance plan): the `schnorrkel` submodule was a
// legacy stub that did its own SHA-512 / Edwards-based sign/verify
// and exposed `{PublicKey, SecretKey, Signature, generate_keypair}`
// that silently diverged from Ristretto. It has been retired; the
// canonical and only schnorrkel-compatible sign path lives in
// `crate::default_impl::sr25519::Sr25519` and operates on
// `RistrettoPoint` via the `ristretto` submodule above.
