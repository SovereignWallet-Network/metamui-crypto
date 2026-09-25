// MetaMUI metamui flathash
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


/// MetaMUI FlatHash Implementation
/// 
/// This crate provides a convenient re-export of the FlatHash implementation
/// from the metamui-crypto-utilities crate.

// Re-export specific items from the utilities implementation
pub use metamui_crypto_utilities::flathash::{
    MetaMUIFlatHash,
    flat_hash,
    flat_hash_hex,
    FlatHash,
    FLATHASH_OUTPUT_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flathash_reexports_work() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{"test": "data"}"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
        
        // Test convenience functions
        let hash2 = flat_hash(json).unwrap();
        assert_eq!(hash, hash2);
    }
}
