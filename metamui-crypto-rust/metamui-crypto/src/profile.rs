//! Explicit profile selection.
//!
//! A [`Profile`] names one algorithm, one parameter set and one wire
//! encoding. The identifiers are the profile identifiers of the release
//! support table, so a configuration file, a registry entry and this enum
//! all spell the same thing.

use crate::Error;

/// What kind of primitive a profile is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Digital signature: `keygen`, `sign`, `verify`.
    Signature,
    /// Key encapsulation: `keygen`, `encapsulate`, `decapsulate`.
    Kem,
}

/// The profiles this facade implements.
///
/// There is no `Default`: a caller must name the profile. Parsing an
/// identifier that is not listed here fails with
/// [`Error::UnsupportedProfile`] — including identifiers of algorithms that
/// exist elsewhere in the workspace but are not admitted to the facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Falcon-512, NIST Round-3 **compressed** signature encoding:
    /// `0x39 ‖ nonce(40) ‖ Golomb-Rice(s2)`, variable length, at most 752 bytes.
    Falcon512R3Compressed,
    /// Falcon-512, NIST Round-3 **padded** signature encoding: exactly 666
    /// bytes, `0x39 ‖ nonce(40) ‖ Golomb-Rice(s2) ‖ zero padding`.
    Falcon512R3Padded,
    /// ML-KEM-768 (FIPS 203) with the standard byte encodings.
    MlKem768,
}

impl Profile {
    /// Every profile the facade implements, in catalog order.
    pub const ALL: [Profile; 3] = [
        Profile::Falcon512R3Compressed,
        Profile::Falcon512R3Padded,
        Profile::MlKem768,
    ];

    /// The catalog `profile_id`.
    pub const fn id(self) -> &'static str {
        match self {
            Profile::Falcon512R3Compressed => "falcon-512.r3-compressed",
            Profile::Falcon512R3Padded => "falcon-512.r3-padded",
            Profile::MlKem768 => "ml-kem-768",
        }
    }

    /// The catalog family this profile belongs to.
    pub const fn family(self) -> &'static str {
        match self {
            Profile::Falcon512R3Compressed | Profile::Falcon512R3Padded => "falcon",
            Profile::MlKem768 => "ml-kem",
        }
    }

    /// Signature or KEM.
    pub const fn kind(self) -> Kind {
        match self {
            Profile::Falcon512R3Compressed | Profile::Falcon512R3Padded => Kind::Signature,
            Profile::MlKem768 => Kind::Kem,
        }
    }

    /// Resolve a catalog identifier. Exact, case-sensitive match only.
    pub fn parse(id: &str) -> Result<Profile, Error> {
        Profile::ALL
            .iter()
            .copied()
            .find(|p| p.id() == id)
            .ok_or_else(|| Error::UnsupportedProfile { requested: id.into() })
    }
}

impl core::fmt::Display for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.id())
    }
}

impl core::str::FromStr for Profile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Profile::parse(s)
    }
}
