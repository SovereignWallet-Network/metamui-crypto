//! A wasm32 `getrandom` backend that reports randomness as unavailable.
//!
//! # Why this crate exists
//!
//! `getrandom` has no ambient entropy source on `wasm32-unknown-unknown`, so
//! it refuses to compile there until the graph names a backend: `js`, which
//! calls the browser's `crypto.getRandomValues` through `wasm-bindgen`, or
//! `custom`, which links a caller-supplied one. There is no default, by
//! design — the runtime environment is the consumer's to know.
//!
//! Several crates in this workspace declare `crate-type = ["cdylib", …]`, so
//! cargo links them for wasm32 even when a consumer only wants the rlib. Each
//! of those links needs a backend to resolve, which is why `js` used to be
//! enabled workspace-wide: it made everything link. The cost was that every
//! wasm32 consumer inherited a JavaScript dependency — feature unification is
//! additive, so no consumer could decline it — including consumers with no
//! JavaScript environment at all.
//!
//! This crate is the other answer. It registers `custom` with a handler that
//! always reports failure, so a wasm32 link resolves without asserting that a
//! browser is present.
//!
//! # Depending on it does not take randomness away
//!
//! `getrandom` prefers `js` when both features are enabled, so a browser
//! consumer that enables `js` keeps Web Crypto and this registration is inert
//! (an unused symbol). It takes effect only where nothing selected `js` —
//! exactly the builds that previously could not link at all.
//!
//! # Who wants "unavailable" as an answer
//!
//! A deterministic consumer: a blockchain runtime compiled to wasm32 computes
//! a state root that every validator must reproduce bit for bit, so ambient
//! entropy on that path is a fork, not a feature. For such a consumer this is
//! not a degraded backend but the correct one — a failure it can surface,
//! rather than a silent source of divergence. Callers see the ordinary
//! `getrandom::Error`; nothing special-cases this backend.

#![no_std]

/// The symbol `getrandom`'s `custom` backend resolves against.
///
/// This is `getrandom::register_custom_getrandom!`'s expansion **minus** the
/// `const __GETRANDOM_INTERNAL: () = { … }` wrapper the macro puts around it.
/// That wrapper is never referenced, and a release profile with `lto = true`
/// drops it before the linker sees it, so the macro yields
/// `undefined symbol: __getrandom_custom` in exactly the cdylib builds this
/// crate exists to fix. The ABI is pinned by `getrandom`'s own `extern "Rust"`
/// declaration: `(*mut u8, usize) -> u32`, `0` for success, otherwise an
/// error code.
///
/// # Safety
///
/// Called only by `getrandom`, which passes a pointer to `len` writable
/// bytes. This body dereferences neither argument, so the contract is
/// trivially upheld — and the buffer is left untouched, which matters: a
/// backend that reports failure must never leave a caller believing it
/// received entropy.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe fn __getrandom_custom(_dest: *mut u8, _len: usize) -> u32 {
    // `CUSTOM_START` is the base of the range reserved for caller-defined
    // codes. Callers only ever surface "randomness unavailable"; the exact
    // value is opaque to them.
    getrandom::Error::CUSTOM_START
}
