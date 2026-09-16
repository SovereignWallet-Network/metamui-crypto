//! Run a deep-recursing routine where there is stack for it.
//!
//! Falcon's NTRU solve recurses over log2(n) levels with large locals at
//! every level. Linux's 8 MB default thread stack hides that; Windows' 1 MB
//! default does not: on the #188 host Falcon-1024 keygen and signing
//! overflowed a default-stack thread (fixed in #194, 1, 1.5 and 2 MB overflow,
//! 3 and 8 MB pass), and the #265 run found Falcon-512 keygen doing the same
//! from the facade's doctest — the `main` thread, 1 MB — while it passed every
//! unit test, because the test harness gives its threads 2 MB. Measured there:
//! 1 MB overflows, 1.5 MB passes. Signing and verification for Falcon-512
//! stay on the caller's thread; they were measured clean at 1 MB.
//!
//! The worker is a scoped thread, so the caller's `&mut R` is borrowed rather
//! than reseeded and a deterministic RNG stream does not move — the property
//! the KAT gates depend on. The price is `R: Send` on every entry point that
//! reaches the solver.

/// Enough for both parameter sets with margin; the same figure #194 chose.
pub(crate) const DEEP_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(not(target_family = "wasm"))]
pub(crate) fn with_deep_stack<T, F>(f: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(DEEP_STACK_BYTES)
            .spawn_scoped(scope, f)
            .expect("falcon: could not spawn the deep-stack worker thread")
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

/// wasm32 has no threads. It also has no 1 MB stack limit imposed by an OS
/// thread, so the recursion runs in place.
#[cfg(target_family = "wasm")]
pub(crate) fn with_deep_stack<T, F>(f: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    f()
}
