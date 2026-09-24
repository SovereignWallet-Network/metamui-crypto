//! The backend hook of the v3 scheme.
//!
//! Every code path in this crate is portable scalar Rust: there is no SIMD,
//! assembly or GPU path and no CPU-feature detection. Key generation, signing
//! and verification in [`mod@super::sign`] go through the backend [`backend`]
//! returns; when none is installed, which is always the case with this crate
//! alone, they run the reference (`*_ref`) functions of that module.
//!
//! A separately maintained crate may install another implementation once,
//! with [`install`], before the first v3 operation of the process. After the
//! first operation the choice is fixed: `install` returns `Err` with the name
//! of the implementation in use, and that one stays, so a signature never
//! depends on which call came first. This crate ships no other backend.
//!
//! # Contract of a backend
//!
//! A backend is an implementation of the same scheme, not a different
//! algorithm. For every parameter set and every input it must reproduce the
//! reference bytes exactly: the same `(pk, sk)` from a `(pt, iv)` pair,
//! including which pairs are rejected with [`V3Error::ZeroSboxInput`], the
//! same signature bytes from the same `(m, pre, rnd, sk)`, and the same
//! verdict on every signature. The dispatcher checks argument lengths before
//! calling a backend; the backend receives slices of exactly `P::FB`,
//! `P::SK_BYTES`, `P::PK_BYTES` and `P::SIG_BYTES` bytes, as
//! [`AimerV3Params`] defines them for the [`ParamSet`] it is handed. The
//! upstream KAT gate (`tests/aimer_v3_upstream_kat.rs`) runs through the
//! dispatching functions, so a backend that is installed before that gate is
//! measured by it.
//!
//! The functions of [`mod@super::sign`] are generic over the parameter set;
//! function pointers cannot be, so a backend is a trait object that receives
//! the set as a [`ParamSet`] value and dispatches to its own generic code.

use super::params::AimerV3Params;
use super::V3Error;
use alloc::vec::Vec;

/// The six parameter sets, as a value a backend can match on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParamSet {
    /// [`super::Aimer128f`]
    Aimer128f,
    /// [`super::Aimer128s`]
    Aimer128s,
    /// [`super::Aimer192f`]
    Aimer192f,
    /// [`super::Aimer192s`]
    Aimer192s,
    /// [`super::Aimer256f`]
    Aimer256f,
    /// [`super::Aimer256s`]
    Aimer256s,
}

impl ParamSet {
    /// The upstream name, `AimerV3Params::NAME` of the matching type.
    pub fn name(self) -> &'static str {
        match self {
            ParamSet::Aimer128f => "aimer-128f",
            ParamSet::Aimer128s => "aimer-128s",
            ParamSet::Aimer192f => "aimer-192f",
            ParamSet::Aimer192s => "aimer-192s",
            ParamSet::Aimer256f => "aimer-256f",
            ParamSet::Aimer256s => "aimer-256s",
        }
    }
}

/// An implementation of the v3 scheme that [`mod@super::sign`] can run on.
///
/// Every method receives arguments whose lengths the dispatcher has already
/// checked against `set`, and must return what the reference function of the
/// same name in [`mod@super::sign`] returns for them (see the module
/// documentation).
pub trait V3Backend: Send + Sync {
    /// A short name for diagnostics, e.g. `"avx2+pclmul"`.
    fn name(&self) -> &'static str;

    /// [`super::sign::keypair_from_pt_iv_ref`] for `set`; `pt` and `iv` are
    /// `FB` bytes each.
    fn keypair_from_pt_iv(&self, set: ParamSet, pt: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), V3Error>;

    /// [`super::sign::sign_internal_ref`] for `set`; `rnd` is `FB` bytes and
    /// `sk` is `SK_BYTES`. Returns the `SIG_BYTES`-byte detached signature.
    fn sign_internal(&self, set: ParamSet, m: &[u8], pre: &[u8], rnd: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error>;

    /// [`super::sign::verify_internal_ref`] for `set`; `sig` is `SIG_BYTES`
    /// and `pk` is `PK_BYTES`.
    fn verify_internal(&self, set: ParamSet, sig: &[u8], m: &[u8], pre: &[u8], pk: &[u8]) -> bool;
}

/// The name reported for the reference path.
pub const REFERENCE_NAME: &str = "reference";

#[cfg(feature = "std")]
static BACKEND: std::sync::OnceLock<Option<&'static dyn V3Backend>> = std::sync::OnceLock::new();

/// The backend in use: what [`install`] set, or `None` for the reference.
///
/// The first call fixes the choice for the rest of the process. Without the
/// `std` feature there is no installation and this is always `None`.
#[inline]
pub fn backend() -> Option<&'static dyn V3Backend> {
    #[cfg(feature = "std")]
    {
        *BACKEND.get_or_init(|| None)
    }
    #[cfg(not(feature = "std"))]
    {
        None
    }
}

/// The name of the implementation in use: [`V3Backend::name`] of the
/// installed backend, or [`REFERENCE_NAME`].
pub fn backend_name() -> &'static str {
    backend().map_or(REFERENCE_NAME, |b| b.name())
}

/// Install `b` as the process-wide backend.
///
/// Succeeds once, and only before the first call of [`backend`] (which every
/// v3 key generation, signing and verification makes). Afterwards it returns
/// `Err` with the name of the implementation in use, and that one stays.
/// Only available with the `std` feature.
#[cfg(feature = "std")]
pub fn install(b: &'static dyn V3Backend) -> Result<(), &'static str> {
    match BACKEND.set(Some(b)) {
        Ok(()) => Ok(()),
        Err(_) => Err(backend_name()),
    }
}

/// `P` as a [`ParamSet`] value.
#[inline]
pub fn set_of<P: AimerV3Params>() -> ParamSet {
    P::SET
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    struct Other;
    impl V3Backend for Other {
        fn name(&self) -> &'static str {
            "other"
        }
        fn keypair_from_pt_iv(&self, _: ParamSet, _: &[u8], _: &[u8]) -> Result<(Vec<u8>, Vec<u8>), V3Error> {
            unreachable!()
        }
        fn sign_internal(&self, _: ParamSet, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>, V3Error> {
            unreachable!()
        }
        fn verify_internal(&self, _: ParamSet, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool {
            unreachable!()
        }
    }

    #[test]
    fn reference_is_the_default_and_install_is_refused_after_first_use() {
        // Any earlier test in this binary may already have fixed the backend;
        // either way it is the reference, because nothing here installs another.
        assert!(backend().is_none());
        assert_eq!(backend_name(), REFERENCE_NAME);
        static OTHER: Other = Other;
        assert_eq!(install(&OTHER), Err(REFERENCE_NAME));
        assert!(backend().is_none());
    }

    #[test]
    fn param_set_names_match_the_types() {
        use crate::v3::*;
        assert_eq!(set_of::<Aimer128f>().name(), Aimer128f::NAME);
        assert_eq!(set_of::<Aimer128s>().name(), Aimer128s::NAME);
        assert_eq!(set_of::<Aimer192f>().name(), Aimer192f::NAME);
        assert_eq!(set_of::<Aimer192s>().name(), Aimer192s::NAME);
        assert_eq!(set_of::<Aimer256f>().name(), Aimer256f::NAME);
        assert_eq!(set_of::<Aimer256s>().name(), Aimer256s::NAME);
    }
}
