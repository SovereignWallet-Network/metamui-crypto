// MetaMUI metamui crypto utilities   operations
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Secure operations utilities

pub mod constant_time;
/// Secure memory clearing operations
pub mod secure_clear;

pub use constant_time::ConstantTime;
pub use secure_clear::Clear;
