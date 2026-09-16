// MetaMUI metamui aes 256   modes
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// AES-256 modes of operation

/// Cipher Block Chaining mode.
pub mod cbc;
/// Counter mode (stream cipher).
pub mod ctr;
/// Electronic Codebook mode.
pub mod ecb;
/// Galois/Counter Mode (authenticated encryption).
pub mod gcm;

// Native implementation traits - no external dependencies

/// Common trait for AES-256 cipher modes
pub trait Aes256Mode {
    /// Get the name of the cipher mode
    fn mode_name(&self) -> &'static str;
    
    /// Check if this mode provides authenticated encryption
    fn is_authenticated(&self) -> bool {
        false
    }
}
