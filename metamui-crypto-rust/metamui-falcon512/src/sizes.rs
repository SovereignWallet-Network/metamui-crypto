//! Wire-size constants for every Falcon signature profile, in one place.
//!
//! The Round-3 reference API (`falcon.h`) defines three signature encodings:
//! **compressed** (variable length, bounded by `FALCON_SIG_COMPRESSED_MAXSIZE`),
//! **padded** (fixed length, `FALCON_SIG_PADDED_SIZE`) and **constant-time**
//! (fixed length, `FALCON_SIG_CT_SIZE`; not implemented in this crate). The NIST
//! submission's `api.h` adds a fourth number, `CRYPTO_BYTES`, which is *not* a
//! signature size: it is the maximum overhead of the NIST signed-message format
//! (`2-byte length ‖ 40-byte nonce ‖ compressed body`). Consumers that sized
//! buffers from `CRYPTO_BYTES` (690) and copied `min(690)` bytes truncated valid
//! compressed signatures (consumer issue #7057).
//!
//! Detached signature layout used by this crate for both the compressed and the
//! padded profile: `(0x30 | logn) ‖ nonce(40) ‖ Golomb-Rice(s2) [‖ zero padding]`.

/// Length of the header byte that opens every detached signature.
pub const SIG_HEADER_LEN: usize = 1;
/// Length of the nonce (salt) that follows the header.
pub const NONCE_LEN: usize = 40;
/// Header + nonce: the bytes that precede the compressed body.
pub const SIG_PREFIX_LEN: usize = SIG_HEADER_LEN + NONCE_LEN;

/// `FALCON_SIG_COMPRESSED_MAXSIZE(logn)` from the reference `falcon.h`:
/// `(((11 << logn) + (101 >> (10 - logn)) + 7) >> 3) + 41`.
pub const fn sig_compressed_max(logn: u32) -> usize {
    ((((11usize << logn) + (101usize >> (10 - logn))) + 7) >> 3) + SIG_PREFIX_LEN
}

/// Sizes for Falcon-512 (`logn = 9`).
pub mod falcon512 {
    pub const LOGN: u32 = 9;
    pub const PUBLIC_KEY: usize = 897;
    pub const SECRET_KEY: usize = 1281;
    /// Largest detached compressed signature the reference can emit (752).
    pub const SIG_COMPRESSED_MAX: usize = super::sig_compressed_max(LOGN);
    /// Exact length of a padded-profile signature (666).
    pub const SIG_PADDED: usize = 666;
    /// Exact length of a constant-time-profile signature (809); not implemented.
    pub const SIG_CT: usize = 809;
    /// NIST `api.h` `CRYPTO_BYTES`: signed-message overhead, **not** a signature bound.
    pub const NIST_SM_OVERHEAD: usize = 690;
}

/// Sizes for Falcon-1024 (`logn = 10`).
pub mod falcon1024 {
    pub const LOGN: u32 = 10;
    pub const PUBLIC_KEY: usize = 1793;
    pub const SECRET_KEY: usize = 2305;
    /// Largest detached compressed signature the reference can emit (1462).
    pub const SIG_COMPRESSED_MAX: usize = super::sig_compressed_max(LOGN);
    /// Exact length of a padded-profile signature (1280).
    pub const SIG_PADDED: usize = 1280;
    /// Exact length of a constant-time-profile signature (1577); not implemented.
    pub const SIG_CT: usize = 1577;
    /// NIST `api.h` `CRYPTO_BYTES`: signed-message overhead, **not** a signature bound.
    pub const NIST_SM_OVERHEAD: usize = 1330;
}

/// Padded-profile signature length for a degree, if the profile is defined for it.
pub const fn sig_padded(logn: u32) -> Option<usize> {
    match logn {
        9 => Some(falcon512::SIG_PADDED),
        10 => Some(falcon1024::SIG_PADDED),
        _ => None,
    }
}

const _: () = assert!(falcon512::SIG_COMPRESSED_MAX == 752);
const _: () = assert!(falcon1024::SIG_COMPRESSED_MAX == 1462);
const _: () = assert!(falcon512::SIG_PADDED > SIG_PREFIX_LEN && falcon1024::SIG_PADDED > SIG_PREFIX_LEN);
