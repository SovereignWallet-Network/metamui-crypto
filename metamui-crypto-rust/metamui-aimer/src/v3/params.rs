//! AIMer specification v3 parameter sets (`params/params-aimer-*.h` upstream).

use super::backend::ParamSet;

/// Compile-time parameters of one AIMer v3 set.
///
/// Field width, seed/salt/commitment sizes and key sizes all derive from
/// `SECURITY_BITS`; only the repetition/party counts, the domain-separation
/// prefix of `H_0`, the signature size and the S-box exponents differ per set.
pub trait AimerV3Params: Clone + Send + Sync + 'static {
    /// Upstream parameter-set name (`aimer-128s`, …).
    const NAME: &'static str;
    /// This set as a value, for a [`super::backend::V3Backend`] to match on.
    const SET: ParamSet;
    /// λ.
    const SECURITY_BITS: usize;
    /// Number of parallel repetitions τ.
    const T: usize;
    /// Number of MPC parties N.
    const N: usize;
    /// log₂ N.
    const LOGN: usize;
    /// `AIMER_HASH_PREFIX_0`: the domain byte of the message pre-hash.
    const HASH_PREFIX_0: u8;
    /// `AIMER_SIG_BYTES`.
    const SIG_BYTES: usize;
    /// AIM3 S-box exponents `e_0 … e_L` (the last is the output S-box).
    const EXPONENTS: &'static [usize];

    /// 64-bit words per field element.
    const W: usize = Self::SECURITY_BITS / 64;
    /// Bytes per field element; also the IV, seed and salt size.
    const FB: usize = Self::SECURITY_BITS / 8;
    /// Number of input S-boxes (`AIMER_L`).
    const L: usize = Self::EXPONENTS.len() - 1;
    /// Commitment / digest size (2λ bits).
    const COMMIT: usize = 2 * Self::FB;
    /// `pk = iv ‖ ct`.
    const PK_BYTES: usize = 2 * Self::FB;
    /// `sk = pt ‖ iv ‖ ct`.
    const SK_BYTES: usize = 3 * Self::FB;
    /// Bytes squeezed per party tape: `pt ‖ y[L] ‖ a[L+1] ‖ c`.
    const TAPE_BYTES: usize = (2 * Self::L + 3) * Self::FB;
}

macro_rules! aimer_v3_set {
    ($(#[$m:meta])* $name:ident, $str:literal, $bits:literal, $t:literal, $n:literal, $logn:literal, $pre:literal, $sig:literal, $exp:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name;
        impl AimerV3Params for $name {
            const NAME: &'static str = $str;
            const SET: ParamSet = ParamSet::$name;
            const SECURITY_BITS: usize = $bits;
            const T: usize = $t;
            const N: usize = $n;
            const LOGN: usize = $logn;
            const HASH_PREFIX_0: u8 = $pre;
            const SIG_BYTES: usize = $sig;
            const EXPONENTS: &'static [usize] = $exp;
        }
    };
}

aimer_v3_set!(/// AIMer-128f (level 1, fast): τ=33, N=16.
    Aimer128f, "aimer-128f", 128, 33, 16, 4, 0x00, 6944, &[3, 7, 11]);
aimer_v3_set!(/// AIMer-128s (level 1, small): τ=17, N=256.
    Aimer128s, "aimer-128s", 128, 17, 256, 8, 0x10, 4704, &[3, 7, 11]);
aimer_v3_set!(/// AIMer-192f (level 3, fast): τ=49, N=16.
    Aimer192f, "aimer-192f", 192, 49, 16, 4, 0x20, 15408, &[11, 23, 47]);
aimer_v3_set!(/// AIMer-192s (level 3, small): τ=25, N=256.
    Aimer192s, "aimer-192s", 192, 25, 256, 8, 0x30, 10320, &[11, 23, 47]);
aimer_v3_set!(/// AIMer-256f (level 5, fast): τ=65, N=16.
    Aimer256f, "aimer-256f", 256, 65, 16, 4, 0x40, 31360, &[3, 7, 11, 19]);
aimer_v3_set!(/// AIMer-256s (level 5, small): τ=33, N=256.
    Aimer256s, "aimer-256s", 256, 33, 256, 8, 0x50, 20224, &[3, 7, 11, 19]);

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_formula<P: AimerV3Params>() -> usize {
        // salt ‖ h1 ‖ h2 ‖ τ · (LOGN seeds ‖ commitment ‖ (L+2) + (L+1) field elements)
        P::FB + 2 * P::COMMIT + P::T * (P::LOGN * P::FB + P::COMMIT + (2 * P::L + 3) * P::FB)
    }

    #[test]
    fn signature_sizes_match_upstream() {
        assert_eq!(sig_formula::<Aimer128f>(), Aimer128f::SIG_BYTES);
        assert_eq!(sig_formula::<Aimer128s>(), Aimer128s::SIG_BYTES);
        assert_eq!(sig_formula::<Aimer192f>(), Aimer192f::SIG_BYTES);
        assert_eq!(sig_formula::<Aimer192s>(), Aimer192s::SIG_BYTES);
        assert_eq!(sig_formula::<Aimer256f>(), Aimer256f::SIG_BYTES);
        assert_eq!(sig_formula::<Aimer256s>(), Aimer256s::SIG_BYTES);
    }
}
