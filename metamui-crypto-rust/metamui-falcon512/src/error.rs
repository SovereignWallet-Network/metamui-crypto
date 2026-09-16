//! Error types for Falcon-512

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Falcon512Error {
    NotImplemented,
    InvalidKey,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    SignatureFailed,
    KeyGenerationFailed,
    SignatureTooLarge,
    InvalidPolynomialSize,
    SamplingFailed,
    InvalidParameter,
    NTRUSolverFailed,
    NormTooLarge,
    NotInvertible,
    NotPositiveDefinite,
    NumericalInstability,
    AccumulatedErrorTooLarge,
    Overflow,
    NearOverflow,
    DivisionByZero,
    XGCDTimeout,
    NotCoprime,
    VerificationFailed,
    SigningFailed,
    InvalidNonce,
    SelfTestFailed,
    SelfTestNotRun,
    InvalidState,
    SecurityViolation,
    AlreadyInitialized,
    NotInitialized,
    InvalidBasis,
    CompressionFailed,
    DecompressionFailed,
    IntegrityCheckFailed,
    FaultDetected,
    InvalidFormat,
    /// An LDL tree leaf width fell outside the `(0, SIGMA_MAX]` band the
    /// rejection sampler requires. Post-#141 keygen enforces the GS bound that
    /// keeps every leaf in band, so this fires only for keys minted by the
    /// pre-#141 keygen — such a key must be treated as compromised and
    /// regenerated, not retried: the violation is a deterministic property of
    /// the key, and signing with it would emit a wrong-distribution signature
    /// (the NTRUSign / Nguyen–Regev transcript-leak shape #141 fixed).
    LdlSigmaOutOfBand,
    /// The compressed body of a signature would not fit the selected profile's
    /// bound (`sizes::*::SIG_COMPRESSED_MAX` / `SIG_PADDED`). Never truncate a
    /// signature: the caller either retries (padded profile) or reports this.
    SignatureTooLong,
    /// A padded-profile signature has the wrong total length or a non-zero byte
    /// after the compressed body (Round-3 `falcon.h` FALCON_SIG_PADDED rule).
    InvalidPadding,
    /// The operating-system randomness source reported failure (for example a
    /// wasm32 build with no JavaScript host, where the only `getrandom`
    /// backend linked is `metamui-getrandom-unavailable`). Nothing was signed.
    EntropyUnavailable,
}

#[cfg(feature = "std")]
impl std::error::Error for Falcon512Error {}

impl fmt::Display for Falcon512Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => write!(f, "Operation not implemented; refusing placeholder cryptographic output"),
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::SignatureFailed => write!(f, "Signature failed"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::SignatureTooLarge => write!(f, "Signature too large"),
            Self::InvalidPolynomialSize => write!(f, "Invalid polynomial size"),
            Self::SamplingFailed => write!(f, "Sampling failed"),
            Self::InvalidParameter => write!(f, "Invalid parameter"),
            Self::NTRUSolverFailed => write!(f, "NTRU solver failed"),
            Self::NormTooLarge => write!(f, "Norm too large"),
            Self::NotInvertible => write!(f, "Polynomial not invertible"),
            Self::NotPositiveDefinite => write!(f, "Matrix not positive definite"),
            Self::NumericalInstability => write!(f, "Numerical instability detected"),
            Self::AccumulatedErrorTooLarge => write!(f, "Accumulated error too large"),
            Self::Overflow => write!(f, "Arithmetic overflow"),
            Self::NearOverflow => write!(f, "Near arithmetic overflow"),
            Self::DivisionByZero => write!(f, "Division by zero"),
            Self::XGCDTimeout => write!(f, "XGCD algorithm timeout"),
            Self::NotCoprime => write!(f, "Polynomials are not coprime"),
            Self::VerificationFailed => write!(f, "Verification failed"),
            Self::SigningFailed => write!(f, "Signing failed after maximum attempts"),
            Self::InvalidNonce => write!(f, "Invalid nonce size"),
            Self::SelfTestFailed => write!(f, "Self-test failed"),
            Self::SelfTestNotRun => write!(f, "Self-tests have not been run"),
            Self::InvalidState => write!(f, "Invalid state"),
            Self::SecurityViolation => write!(f, "Security violation detected"),
            Self::AlreadyInitialized => write!(f, "Already initialized"),
            Self::NotInitialized => write!(f, "Not initialized"),
            Self::InvalidBasis => write!(f, "Invalid NTRU basis"),
            Self::CompressionFailed => write!(f, "Compression failed"),
            Self::DecompressionFailed => write!(f, "Decompression failed"),
            Self::IntegrityCheckFailed => write!(f, "Integrity check failed"),
            Self::FaultDetected => write!(f, "Fault injection detected"),
            Self::InvalidFormat => write!(f, "Invalid format"),
            Self::SignatureTooLong => write!(
                f,
                "signature exceeds the profile's maximum length; refusing to emit \
                 a truncatable signature"
            ),
            Self::InvalidPadding => write!(
                f,
                "padded signature has the wrong length or non-zero bytes after the \
                 compressed body"
            ),
            Self::EntropyUnavailable => write!(f, "operating-system randomness unavailable"),
            Self::LdlSigmaOutOfBand => write!(
                f,
                "LDL leaf width outside (0, SIGMA_MAX]: key predates the #141 \
                 keygen GS bound and must be regenerated; signing with it would \
                 not follow the Falcon signature distribution"
            ),
        }
    }
}

pub type Result<T> = core::result::Result<T, Falcon512Error>;
