/// Type definitions for Camellia

use metamui_security_utils::Zeroize;

/// 128-bit block type
pub type Block = [u8; 16];

/// 128-bit key type

// #[zeroize(drop)] // Manual Drop impl added below
pub struct Key128(pub [u8; 16]);

/// 192-bit key type

// #[zeroize(drop)] // Manual Drop impl added below
pub struct Key192(pub [u8; 24]);

/// 256-bit key type

// #[zeroize(drop)] // Manual Drop impl added below
pub struct Key256(pub [u8; 32]);

impl AsRef<[u8]> for Key128 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for Key128 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for Key192 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for Key256 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Key256 {
    fn drop(&mut self) {
        use metamui_security_utils::Zeroize;
        self.zeroize();
    }
}

impl Drop for Key192 {
    fn drop(&mut self) {
        use metamui_security_utils::Zeroize;
        self.zeroize();
    }
}

impl Drop for Key128 {
    fn drop(&mut self) {
        use metamui_security_utils::Zeroize;
        self.zeroize();
    }
}

impl AsRef<[u8]> for Key192 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Key256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 16]> for Key128 {
    fn from(key: [u8; 16]) -> Self {
        Key128(key)
    }
}

impl From<[u8; 24]> for Key192 {
    fn from(key: [u8; 24]) -> Self {
        Key192(key)
    }
}

impl From<[u8; 32]> for Key256 {
    fn from(key: [u8; 32]) -> Self {
        Key256(key)
    }
}