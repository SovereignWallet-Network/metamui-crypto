// MetaMUI metamui crypto utilities   encoding
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Encoding and decoding utilities

#[cfg(feature = "encoding")]
pub mod hex;

#[cfg(feature = "encoding")]
/// Base64 encoding and decoding utilities
pub mod base64;

#[cfg(feature = "encoding")]
/// Base58 encoding and decoding utilities
pub mod base58;
