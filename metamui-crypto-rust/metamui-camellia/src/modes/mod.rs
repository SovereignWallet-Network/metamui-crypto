// MetaMUI metamui camellia   modes
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


/// Block cipher modes of operation

pub mod cbc;
pub mod ctr;
pub mod ecb;
pub mod gcm;

// Re-export mode functions when needed
// pub use cbc::{decrypt_cbc, encrypt_cbc};
// pub use ctr::{decrypt_ctr, encrypt_ctr, process_ctr};
// pub use ecb::{decrypt_ecb, encrypt_ecb};
// pub use gcm::{decrypt_gcm, encrypt_gcm};
