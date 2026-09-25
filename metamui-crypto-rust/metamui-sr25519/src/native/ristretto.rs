//! Ristretto255 point encoding and decoding per RFC 9496.
//!
//! This module previously wrapped an `EdwardsPoint` and used raw
//! Ed25519 compressed encoding — which is **not** Ristretto. That
//! stub produced the wrong public keys, which in turn made
//! `Sr25519::get_public_key` diverge from every schnorrkel-compatible
//! verifier.
//!
//! The implementation below follows RFC 9496 §4.3 (Encoding and
//! Decoding) using the extended twisted Edwards coordinates already
//! in `native::curve::EdwardsPoint`. It is **not** yet fully
//! constant-time — `is_negative` uses `to_bytes()` which currently
//! reduces mod p non-uniformly. Hardening is tracked as part of the
//! Phase 3 cleanup of the Sr25519 compliance plan.
//!
//! Reference implementations consulted:
//!   - RFC 9496 <https://www.rfc-editor.org/rfc/rfc9496.html>
//!   - curve25519-dalek <https://github.com/dalek-cryptography/curve25519-dalek>
//!   - Appendix A "Test Vectors" — validated via `tests/ristretto_kat.rs`.

use super::curve::EdwardsPoint;
use super::field_radix51::FieldElement51 as FieldElement;

/// A Ristretto point. Internally an extended-coordinate Edwards point
/// with the guarantee (maintained by `decompress`) that it lies in the
/// prime-order subgroup after Ristretto's 4-torsion canonicalization.
#[derive(Clone, Copy, Debug)]
pub struct RistrettoPoint {
    pub(crate) point: EdwardsPoint,
}

// ---------------------------------------------------------------------------
// Ristretto255 constants (RFC 9496 Appendix A)
// ---------------------------------------------------------------------------
//
// All bytes little-endian — matching `FieldElement::from_bytes` /
// `to_bytes` convention across this crate.

/// SQRT_M1 = sqrt(-1) mod p, chosen as the nonnegative root.
/// Big-endian hex: 2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
    0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
    0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// INVSQRT_A_MINUS_D = 1 / sqrt(a - d) = 1 / sqrt(-1 - d).
/// Used by `encode_ristretto`'s "rotate" branch to compute the
/// enchanted-denominator factor. The closely-related constant
/// `SQRT_AD_MINUS_ONE` from RFC 9496 is unused here because we
/// encode via `den1 * INVSQRT_A_MINUS_D` rather than
/// `den1 / SQRT_AD_MINUS_ONE` — algebraically equivalent.
//
/// Big-endian hex: 786c8905cfaffca216c27b91fe01d8409d2f16175a4172be99c8fdaa805d40ea
const INVSQRT_A_MINUS_D_BYTES: [u8; 32] = [
    0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
    0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
    0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
    0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
];

fn sqrt_m1() -> FieldElement { FieldElement::from_bytes(&SQRT_M1_BYTES) }
fn invsqrt_a_minus_d() -> FieldElement { FieldElement::from_bytes(&INVSQRT_A_MINUS_D_BYTES) }

// ---------------------------------------------------------------------------
// Conditional-move helpers
// ---------------------------------------------------------------------------
//
// `choice` is 0 (keep a) or 1 (use b). NOT constant-time — see module
// docs. Used internally by `sqrt_ratio_i` and the encoder.

#[inline]
fn cmov_fe(a: FieldElement, b: FieldElement, choice: u8) -> FieldElement {
    if choice == 1 { b } else { a }
}

#[inline]
fn cneg_fe(a: FieldElement, choice: u8) -> FieldElement {
    if choice == 1 { a.negate() } else { a }
}

#[inline]
fn fe_eq(a: &FieldElement, b: &FieldElement) -> bool {
    a.to_bytes() == b.to_bytes()
}

#[inline]
fn fe_is_negative(a: &FieldElement) -> bool {
    // RFC 9496: the "is_negative" predicate is the low bit of the
    // canonical byte encoding.
    a.is_negative()
}

#[inline]
fn fe_abs(a: FieldElement) -> FieldElement {
    cneg_fe(a, fe_is_negative(&a) as u8)
}

// ---------------------------------------------------------------------------
// sqrt_ratio_i — the core primitive from RFC 9496 §4.2
// ---------------------------------------------------------------------------
//
// Returns (was_square, r) where:
//   if u/v is a nonzero square:      was_square=1, r = nonneg_sqrt(u/v)
//   if u is zero (regardless of v):  was_square=1, r = 0
//   if u/v is a nonsquare of form u/v = -w^2 for some w: was_square=0, r = nonneg_sqrt(i * u/v)
//   else (v zero with u nonzero):    was_square=0, r = 0
fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (bool, FieldElement) {
    // Shortest correct path without requiring a dedicated pow-pm5d8:
    // we already have `FieldElement::sqrt` that returns an Option.
    //
    // Compute r = sqrt(u / v) by inverting v if nonzero.
    //
    // Corner case: v == 0. If u == 0 also, then u/v is defined as 0
    // per RFC 9496 and we return (true, 0). Otherwise RFC semantics
    // say (false, 0).
    let v_bytes = v.to_bytes();
    if v_bytes.iter().all(|&b| b == 0) {
        // v == 0
        let u_bytes = u.to_bytes();
        if u_bytes.iter().all(|&b| b == 0) {
            return (true, FieldElement::ZERO);
        } else {
            return (false, FieldElement::ZERO);
        }
    }

    let v_inv = v.invert().expect("v != 0 was checked above");
    let ratio = u.mul(&v_inv);

    match ratio.sqrt() {
        Some(root) => (true, fe_abs(root)),
        None => {
            // u/v is not a square in Fp. For Ristretto, we still need
            // sqrt(i * u/v) if THAT is a square — the "flipped" case.
            let i = sqrt_m1();
            let flipped = ratio.mul(&i);
            match flipped.sqrt() {
                Some(root) => (false, fe_abs(root)),
                None => (false, FieldElement::ZERO),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RistrettoPoint — group operations and group-level methods
// ---------------------------------------------------------------------------

impl RistrettoPoint {
    /// The group identity.
    pub fn identity() -> Self {
        RistrettoPoint { point: EdwardsPoint::identity() }
    }

    /// Ristretto basepoint. Same numeric Edwards point as the Ed25519
    /// basepoint; the distinction is purely in the encoding layer.
    pub fn base_point() -> Self {
        RistrettoPoint { point: EdwardsPoint::base_point() }
    }

    /// Encode to 32 bytes per RFC 9496 §4.3.2.
    pub fn compress(&self) -> [u8; 32] {
        encode_ristretto(&self.point)
    }

    /// Decode 32 bytes per RFC 9496 §4.3.1. Returns `None` on any of:
    /// non-canonical `s`, negative `s`, or a point that fails the
    /// Ristretto validity check.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        decode_ristretto(bytes).map(|point| RistrettoPoint { point })
    }

    pub fn add(&self, other: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint { point: self.point.add(&other.point) }
    }
    pub fn sub(&self, other: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint { point: self.point.add(&other.point.negate()) }
    }
    pub fn negate(&self) -> RistrettoPoint {
        RistrettoPoint { point: self.point.negate() }
    }

    /// Scalar multiplication. For sr25519 / Polkadot, the scalar is
    /// generally the cofactor-divided clamped bytes produced by
    /// `expand_ed25519`.
    pub fn mul(&self, scalar: &[u8; 32]) -> RistrettoPoint {
        RistrettoPoint { point: self.point.scalar_mul(scalar) }
    }

    pub fn is_identity(&self) -> bool {
        // Two extended-Edwards representations denote the same
        // Ristretto element iff (X1·Y2 - X2·Y1) == 0. For identity,
        // Y/Z = 1 and X/Z = 0.
        // Simplest correct test: encode and compare.
        self.compress() == [0u8; 32]
    }
}

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &Self) -> bool {
        // RFC 9496: P == Q iff (x1·y2 == x2·y1) OR (y1·y2 == -x1·x2).
        // We use affine coordinates after z-inversion.
        let a = &self.point;
        let b = &other.point;
        let x1y2 = a.x.mul(&b.y);
        let y1x2 = a.y.mul(&b.x);
        let x1x2 = a.x.mul(&b.x);
        let y1y2 = a.y.mul(&b.y);
        // Compare after projective normalization: x1·y2·z2 vs y1·x2·z1 etc
        // Here we compare x1/z1 · y2/z2 == x2/z2 · y1/z1 which reduces to
        //    x1·y2·z1_inv·z2_inv == y1·x2·z1_inv·z2_inv
        // i.e.    x1·y2·z2 == y1·x2·z1    after cross-multiplying with z1·z2.
        let lhs1 = x1y2.mul(&b.z); let _ = lhs1; // kept for readability
        let cond1 = fe_eq(&x1y2.mul(&b.point_z_equivalent()), &y1x2.mul(&a.point_z_equivalent()));
        let cond2 = fe_eq(&y1y2.mul(&b.point_z_equivalent()), &x1x2.negate().mul(&a.point_z_equivalent()));
        cond1 || cond2
    }
}
impl Eq for RistrettoPoint {}

// Trait-ish accessor so the PartialEq above reads clearly. EdwardsPoint
// stores z directly; this is purely syntactic sugar.
trait PointZ { fn point_z_equivalent(&self) -> FieldElement; }
impl PointZ for EdwardsPoint { fn point_z_equivalent(&self) -> FieldElement { self.z } }

// ---------------------------------------------------------------------------
// Multi-scalar multiplication (kept from previous impl for API stability)
// ---------------------------------------------------------------------------

pub fn multiscalar_mul(scalars: &[[u8; 32]], points: &[RistrettoPoint]) -> RistrettoPoint {
    assert_eq!(scalars.len(), points.len());
    let mut acc = RistrettoPoint::identity();
    for (s, p) in scalars.iter().zip(points.iter()) {
        acc = acc.add(&p.mul(s));
    }
    acc
}

// ---------------------------------------------------------------------------
// RFC 9496 §4.3.2 — encode
// ---------------------------------------------------------------------------

fn encode_ristretto(p: &EdwardsPoint) -> [u8; 32] {
    // Extended coordinates (X, Y, Z, T) with a = -1.
    let x = p.x;
    let y = p.y;
    let z = p.z;
    let t = p.t;

    // u1 = (Z + Y) * (Z - Y)
    let u1 = z.add(&y).mul(&z.sub(&y));
    // u2 = X * Y
    let u2 = x.mul(&y);

    // invsqrt = 1 / sqrt(u1 * u2^2)
    let u1_u2sq = u1.mul(&u2.square());
    let (_, invsqrt) = sqrt_ratio_i(&FieldElement::ONE, &u1_u2sq);

    let den1 = invsqrt.mul(&u1);
    let den2 = invsqrt.mul(&u2);
    let z_inv = den1.mul(&den2).mul(&t);

    // If T*z_inv is negative: "rotate" the coordinates by SQRT_M1.
    let i = sqrt_m1();
    let rotate = fe_is_negative(&t.mul(&z_inv)) as u8;

    let ix = x.mul(&i);
    let iy = y.mul(&i);
    let enchanted_denominator = den1.mul(&invsqrt_a_minus_d());

    let x_rot = cmov_fe(x, iy, rotate);
    let y_rot = cmov_fe(y, ix, rotate);
    let den_inv = cmov_fe(den2, enchanted_denominator, rotate);

    // If X*z_inv is negative, negate Y so that Y*den_inv has the
    // canonical "positive" sign.
    let y_final = cneg_fe(y_rot, fe_is_negative(&x_rot.mul(&z_inv)) as u8);

    // s = |den_inv * (Z - Y)|
    let s = fe_abs(den_inv.mul(&z.sub(&y_final)));
    s.to_bytes()
}

// ---------------------------------------------------------------------------
// RFC 9496 §4.3.1 — decode
// ---------------------------------------------------------------------------

fn decode_ristretto(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    // 1. Reject non-canonical inputs. The canonical check:
    //    parse, re-serialize, compare.
    let s = FieldElement::from_bytes(bytes);
    let s_canonical = s.to_bytes();
    if s_canonical != *bytes {
        return None;
    }
    // 2. Reject negative s (low bit of canonical bytes).
    if fe_is_negative(&s) {
        return None;
    }

    // 3. Curve equation pieces.
    let ss = s.square();
    let u1 = FieldElement::ONE.sub(&ss);               // 1 + a·s² for a=-1
    let u2 = FieldElement::ONE.add(&ss);               // 1 - a·s²
    let u2_sqr = u2.square();

    // v = -(d · u1²) - u2²   (using a=-1; schnorrkel's constant is d)
    let d = EdwardsPoint::edwards_d();
    let v = d.mul(&u1.square()).negate().sub(&u2_sqr);

    // I = 1 / sqrt(v · u2²)
    let (was_square, i) = sqrt_ratio_i(&FieldElement::ONE, &v.mul(&u2_sqr));

    let den_x = i.mul(&u2);
    let den_y = i.mul(&den_x).mul(&v);

    let x = fe_abs(s.add(&s).mul(&den_x));             // |2·s·den_x|
    let y = u1.mul(&den_y);
    let t = x.mul(&y);

    // Reject if non-square, t is negative, or y is zero.
    if !was_square || fe_is_negative(&t) || y.to_bytes().iter().all(|&b| b == 0) {
        return None;
    }

    Some(EdwardsPoint {
        x,
        y,
        z: FieldElement::ONE,
        t,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity (the zero point) must encode to all-zero bytes.
    #[test]
    fn encode_identity_is_all_zero() {
        let id = RistrettoPoint::identity();
        assert_eq!(id.compress(), [0u8; 32]);
    }

    /// Decoding the all-zero encoding must produce the identity.
    #[test]
    fn decode_all_zero_is_identity() {
        let decoded = RistrettoPoint::decompress(&[0u8; 32]).expect("id decodes");
        assert!(decoded.is_identity());
    }

    /// Basepoint encoding matches RFC 9496 Appendix A vector 1.
    #[test]
    fn basepoint_encoding_matches_rfc9496() {
        // RFC 9496 Appendix A: 1 * B
        let expected_hex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
        let got = RistrettoPoint::base_point().compress();
        assert_eq!(hex::encode(got), expected_hex, "basepoint encoding mismatch");
    }

    /// Round-trip: encode → decode → encode must be stable.
    #[test]
    fn encode_decode_roundtrip_basepoint() {
        let b = RistrettoPoint::base_point();
        let enc = b.compress();
        let dec = RistrettoPoint::decompress(&enc).expect("basepoint decodes");
        assert_eq!(dec.compress(), enc);
    }
}
