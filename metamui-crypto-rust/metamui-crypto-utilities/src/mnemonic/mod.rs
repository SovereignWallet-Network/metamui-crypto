// MetaMUI metamui crypto utilities   mnemonic
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Mnemonic seed phrase utilities

#[cfg(feature = "mnemonic")]
pub mod bip39;

#[cfg(feature = "mnemonic")]
/// BIP39 wordlist implementations
pub mod wordlist;

// Re-export main types
#[cfg(feature = "mnemonic")]
pub use bip39::Bip39;
