// MetaMUI metamui crypto utilities   kdf
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Key derivation functions

#[cfg(feature = "kdf")]
pub mod hkdf;

#[cfg(feature = "kdf")]
/// PBKDF2 (Password-Based Key Derivation Function 2) implementation
pub mod pbkdf2;

// Future additions:
// pub mod argon2;
// pub mod argon2id;
// pub mod blake3_kdf;
