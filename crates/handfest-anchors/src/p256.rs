//! Zero-dependency, pure-Rust NIST P-256 (`secp256r1`) ECDSA signature verifier.
//!
//! Implements constant-time 256-bit Montgomery arithmetic over the P-256 base field `F_p`
//! and scalar field `F_n` using `[u64; 4]` little-endian limbs (`#![forbid(unsafe_code)]`),
//! strict uncompressed SEC1 public-key validation, and ECDSA verification over 32-byte
//! SHA-256 digests.

use std::fmt;

/// Exact byte length of an uncompressed SEC1 NIST P-256 public key (`0x04 || X || Y`).
pub const P256_UNCOMPRESSED_KEY_LEN: usize = 65;

const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

type U256 = [u64; 4];

const U256_ZERO: U256 = [0, 0, 0, 0];
const U256_ONE: U256 = [1, 0, 0, 0];

#[derive(Clone, Copy)]
struct Modulus {
    limbs: U256,
    r: U256,
    r2: U256,
    m_inv: u64,
}

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const FIELD_P: Modulus = Modulus {
    limbs: [
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ],
    r: [
        0x0000_0000_0000_0001,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_fffe,
    ],
    r2: [
        0x0000_0000_0000_0003,
        0xffff_fffb_ffff_ffff,
        0xffff_ffff_ffff_fffe,
        0x0000_0004_ffff_fffd,
    ],
    m_inv: 0x0000_0000_0000_0001,
};

// p - 2 (for Fermat inversion in F_p)
const P_MINUS_2: U256 = [
    0xffff_ffff_ffff_fffd,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
const SCALAR_N: Modulus = Modulus {
    limbs: [
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ],
    r: [
        0x0c46_353d_039c_daaf,
        0x4319_0552_58e8_617b,
        0x0000_0000_0000_0000,
        0x0000_0000_ffff_ffff,
    ],
    r2: [
        0x8324_4c95_be79_eea2,
        0x4699_799c_49bd_6fa6,
        0x2845_b239_2b6b_ec59,
        0x66e1_2d94_f3d9_5620,
    ],
    m_inv: 0xccd1_c8aa_ee00_bc4f,
};

// n - 2 (for Fermat inversion in F_n)
const N_MINUS_2: U256 = [
    0xf3b9_cac2_fc63_254f,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

// Curve parameter b in Montgomery form over F_p.
const CURVE_B_MONT: Fe = Fe([
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
]);

// Generator G = (Gx, Gy) in Montgomery form over F_p.
const GENERATOR_X_MONT: Fe = Fe([
    0x79e7_30d4_18a9_143c,
    0x75ba_95fc_5fed_b601,
    0x79fb_732b_7762_2510,
    0x1890_5f76_a537_55c6,
]);

const GENERATOR_Y_MONT: Fe = Fe([
    0xddf2_5357_ce95_560a,
    0x8b4a_b8e4_ba19_e45c,
    0xd2e8_8688_dd21_f325,
    0x8571_ff18_2588_5d85,
]);

/// Errors returned while parsing NIST P-256 public keys or verifying ECDSA signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256Error {
    /// Uncompressed SEC1 public key did not have exact length 65 bytes.
    InvalidLength(usize),
    /// Uncompressed SEC1 public key did not begin with `0x04`.
    InvalidPrefix(u8),
    /// Affine coordinate `X` or `Y` is `>= p`.
    CoordinateOutOfRange,
    /// Affine point `(X, Y)` does not satisfy `Y^2 == X^3 - 3X + b (mod p)`.
    NotOnCurve,
    /// Signature scalar `r` or `s` is not in `1..n`.
    InvalidSignatureScalar,
    /// Verification point `u1 * G + u2 * Q` resolved to the point at infinity.
    PointAtInfinity,
    /// Recomputed `x_R mod n` did not match `r`.
    SignatureMismatch,
}

impl fmt::Display for P256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => write!(
                f,
                "invalid P-256 uncompressed SEC1 public key length {len}, expected {P256_UNCOMPRESSED_KEY_LEN}"
            ),
            Self::InvalidPrefix(prefix) => write!(
                f,
                "invalid P-256 SEC1 point prefix 0x{prefix:02x}, expected 0x{SEC1_UNCOMPRESSED_PREFIX:02x}"
            ),
            Self::CoordinateOutOfRange => {
                f.write_str("P-256 public key coordinate is out of field range (>= p)")
            }
            Self::NotOnCurve => f.write_str("P-256 public key point is not on curve secp256r1"),
            Self::InvalidSignatureScalar => {
                f.write_str("P-256 ECDSA signature scalar (r or s) is out of range (must be 1..n)")
            }
            Self::PointAtInfinity => {
                f.write_str("P-256 ECDSA verification point evaluated to infinity")
            }
            Self::SignatureMismatch => f.write_str("P-256 ECDSA signature verification failed"),
        }
    }
}

impl std::error::Error for P256Error {}

/// Strictly validated NIST P-256 (`secp256r1`) affine public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256PublicKey {
    sec1: [u8; P256_UNCOMPRESSED_KEY_LEN],
    x: Fe,
    y: Fe,
}

impl P256PublicKey {
    /// Parses and validates a 65-byte uncompressed SEC1 P-256 public key (`0x04 || X || Y`).
    pub fn from_sec1_uncompressed(bytes: &[u8]) -> Result<Self, P256Error> {
        let sec1: [u8; P256_UNCOMPRESSED_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| P256Error::InvalidLength(bytes.len()))?;
        if sec1[0] != SEC1_UNCOMPRESSED_PREFIX {
            return Err(P256Error::InvalidPrefix(sec1[0]));
        }

        let x_raw = u256_from_be_slice(&sec1[1..33]);
        let y_raw = u256_from_be_slice(&sec1[33..65]);
        if u256_gte(x_raw, FIELD_P.limbs) || u256_gte(y_raw, FIELD_P.limbs) {
            return Err(P256Error::CoordinateOutOfRange);
        }

        let x = Fe::from_u256(x_raw);
        let y = Fe::from_u256(y_raw);
        if !is_on_curve(x, y) {
            return Err(P256Error::NotOnCurve);
        }

        Ok(Self { sec1, x, y })
    }

    /// Borrows the canonical 65-byte uncompressed SEC1 encoding.
    #[must_use]
    pub const fn as_sec1_bytes(&self) -> &[u8; P256_UNCOMPRESSED_KEY_LEN] {
        &self.sec1
    }

    /// Verifies a NIST P-256 ECDSA signature `(r, s)` over a 32-byte SHA-256 digest `digest`.
    pub fn verify_prehash(
        &self,
        digest: &[u8; 32],
        r_bytes: &[u8; 32],
        s_bytes: &[u8; 32],
    ) -> Result<(), P256Error> {
        let r_raw = u256_from_be_slice(r_bytes);
        let s_raw = u256_from_be_slice(s_bytes);
        if u256_is_zero(r_raw)
            || u256_gte(r_raw, SCALAR_N.limbs)
            || u256_is_zero(s_raw)
            || u256_gte(s_raw, SCALAR_N.limbs)
        {
            return Err(P256Error::InvalidSignatureScalar);
        }

        let z_raw = reduce_u256_mod_n(u256_from_be_slice(digest));
        let z = Scalar::from_u256(z_raw);
        let r = Scalar::from_u256(r_raw);
        let s = Scalar::from_u256(s_raw);

        let w = s.invert();
        let u1 = z.mul(w).to_u256();
        let u2 = r.mul(w).to_u256();

        let q = JacobianPoint::from_affine(self.x, self.y);
        let point = JacobianPoint::mul_add(u1, u2, &q);
        let x_affine = point.to_affine_x().ok_or(P256Error::PointAtInfinity)?;
        let v = reduce_u256_mod_n(x_affine);

        if v != r_raw {
            return Err(P256Error::SignatureMismatch);
        }
        Ok(())
    }
}

/// Checks `y^2 == x^3 - 3x + b (mod p)`.
fn is_on_curve(x: Fe, y: Fe) -> bool {
    let lhs = y.square();
    let x2 = x.square();
    let x3 = x2.mul(x);
    let three_x = x.double().add(x);
    let rhs = x3.sub(three_x).add(CURVE_B_MONT);
    lhs == rhs
}

// ============================================================================
// Fixed-width 256-bit unsigned integer primitives (little-endian `[u64; 4]`)
// ============================================================================

fn u256_from_be_slice(bytes: &[u8]) -> U256 {
    let read_be_u64 = |start: usize| -> u64 {
        let chunk: [u8; 8] = bytes[start..start + 8]
            .try_into()
            .expect("32-byte slice contains four 8-byte limbs");
        u64::from_be_bytes(chunk)
    };
    [
        read_be_u64(24),
        read_be_u64(16),
        read_be_u64(8),
        read_be_u64(0),
    ]
}

#[cfg(test)]
fn u256_to_be_bytes(v: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v[3].to_be_bytes());
    out[8..16].copy_from_slice(&v[2].to_be_bytes());
    out[16..24].copy_from_slice(&v[1].to_be_bytes());
    out[24..32].copy_from_slice(&v[0].to_be_bytes());
    out
}

const fn u256_is_zero(v: U256) -> bool {
    (v[0] | v[1] | v[2] | v[3]) == 0
}

const fn u256_add(a: U256, b: U256) -> (U256, u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
        i += 1;
    }
    (out, carry)
}

const fn u256_sub(a: U256, b: U256) -> (U256, u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
        i += 1;
    }
    (out, borrow)
}

const fn u256_gte(a: U256, b: U256) -> bool {
    u256_sub(a, b).1 == 0
}

const fn u256_ct_select(choose_a: bool, a: U256, b: U256) -> U256 {
    let mask = 0u64.wrapping_sub(choose_a as u64);
    [
        (a[0] & mask) | (b[0] & !mask),
        (a[1] & mask) | (b[1] & !mask),
        (a[2] & mask) | (b[2] & !mask),
        (a[3] & mask) | (b[3] & !mask),
    ]
}

/// Reduces any 256-bit unsigned integer modulo `n` (`n > 2^255`, so at most one subtraction).
const fn reduce_u256_mod_n(x: U256) -> U256 {
    let (diff, borrow) = u256_sub(x, SCALAR_N.limbs);
    u256_ct_select(borrow == 0, diff, x)
}

const fn u256_bit(v: U256, bit_index: usize) -> u8 {
    ((v[bit_index / 64] >> (bit_index % 64)) & 1) as u8
}

// ============================================================================
// Constant-time Montgomery arithmetic shared by `F_p` and `F_n`
// ============================================================================

impl Modulus {
    const fn add(&self, a: U256, b: U256) -> U256 {
        let (sum, carry) = u256_add(a, b);
        let (diff, borrow) = u256_sub(sum, self.limbs);
        u256_ct_select(carry != 0 || borrow == 0, diff, sum)
    }

    const fn sub(&self, a: U256, b: U256) -> U256 {
        let (diff, borrow) = u256_sub(a, b);
        let (adjusted, _) = u256_add(diff, self.limbs);
        u256_ct_select(borrow != 0, adjusted, diff)
    }

    /// CIOS Montgomery multiplication: computes `a * b * 2^{-256} mod m`.
    fn mont_mul(&self, a: U256, b: U256) -> U256 {
        let mut t = [0u64; 5];
        for &ai in &a {
            let t5 = mac_row(&mut t, ai, &b);
            let u = t[0].wrapping_mul(self.m_inv);
            reduce_row(&mut t, t5, u, &self.limbs);
        }
        let lo = [t[0], t[1], t[2], t[3]];
        let (diff, borrow) = u256_sub(lo, self.limbs);
        u256_ct_select(t[4] != 0 || borrow == 0, diff, lo)
    }

    fn encode_mont(self, x: U256) -> U256 {
        self.mont_mul(x, self.r2)
    }

    fn decode_mont(self, x_mont: U256) -> U256 {
        self.mont_mul(x_mont, U256_ONE)
    }

    /// Binary exponentiation in Montgomery form (constant-time conditional selection).
    fn mont_pow(&self, base_mont: U256, exp: U256) -> U256 {
        let mut acc = self.r;
        let mut bit = 256;
        while bit > 0 {
            bit -= 1;
            acc = self.mont_mul(acc, acc);
            let multiplied = self.mont_mul(acc, base_mont);
            acc = u256_ct_select(u256_bit(exp, bit) == 1, multiplied, acc);
        }
        acc
    }
}

fn mac_row(t: &mut [u64; 5], ai: u64, b: &U256) -> u64 {
    let mut carry = 0u128;
    for j in 0..4 {
        let prod = u128::from(t[j]) + u128::from(ai) * u128::from(b[j]) + carry;
        t[j] = prod as u64;
        carry = prod >> 64;
    }
    let sum = u128::from(t[4]) + carry;
    t[4] = sum as u64;
    (sum >> 64) as u64
}

fn reduce_row(t: &mut [u64; 5], t5: u64, u: u64, m: &U256) {
    let mut carry = (u128::from(t[0]) + u128::from(u) * u128::from(m[0])) >> 64;
    for j in 1..4 {
        let prod = u128::from(t[j]) + u128::from(u) * u128::from(m[j]) + carry;
        t[j - 1] = prod as u64;
        carry = prod >> 64;
    }
    let sum = u128::from(t[4]) + carry;
    t[3] = sum as u64;
    t[4] = t5 + ((sum >> 64) as u64);
}

// ============================================================================
// Strongly-typed field (`Fe` in `F_p`) and scalar (`Scalar` in `F_n`) wrappers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fe(U256);

impl Fe {
    const ZERO: Self = Self(U256_ZERO);
    const ONE: Self = Self(FIELD_P.r);

    fn from_u256(x: U256) -> Self {
        Self(FIELD_P.encode_mont(x))
    }

    fn to_u256(self) -> U256 {
        FIELD_P.decode_mont(self.0)
    }

    const fn is_zero(self) -> bool {
        u256_is_zero(self.0)
    }

    const fn add(self, rhs: Self) -> Self {
        Self(FIELD_P.add(self.0, rhs.0))
    }

    const fn sub(self, rhs: Self) -> Self {
        Self(FIELD_P.sub(self.0, rhs.0))
    }

    const fn double(self) -> Self {
        self.add(self)
    }

    fn mul(self, rhs: Self) -> Self {
        Self(FIELD_P.mont_mul(self.0, rhs.0))
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn invert(self) -> Self {
        Self(FIELD_P.mont_pow(self.0, P_MINUS_2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scalar(U256);

impl Scalar {
    fn from_u256(x: U256) -> Self {
        Self(SCALAR_N.encode_mont(x))
    }

    fn to_u256(self) -> U256 {
        SCALAR_N.decode_mont(self.0)
    }

    #[cfg(test)]
    const fn add(self, rhs: Self) -> Self {
        Self(SCALAR_N.add(self.0, rhs.0))
    }

    fn mul(self, rhs: Self) -> Self {
        Self(SCALAR_N.mont_mul(self.0, rhs.0))
    }

    fn invert(self) -> Self {
        Self(SCALAR_N.mont_pow(self.0, N_MINUS_2))
    }
}

// ============================================================================
// Jacobian projective point arithmetic on P-256 (`a = -3`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JacobianPoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl JacobianPoint {
    const INFINITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    const GENERATOR: Self = Self {
        x: GENERATOR_X_MONT,
        y: GENERATOR_Y_MONT,
        z: Fe::ONE,
    };

    const fn from_affine(x: Fe, y: Fe) -> Self {
        Self { x, y, z: Fe::ONE }
    }

    const fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Jacobian point doubling using EFD `dbl-2001-b` for `a = -3`.
    fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::INFINITY;
        }
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(gamma);

        let x_minus_delta = self.x.sub(delta);
        let x_plus_delta = self.x.add(delta);
        let t = x_minus_delta.mul(x_plus_delta);
        let alpha = t.double().add(t);

        let four_beta = beta.double().double();
        let eight_beta = four_beta.double();
        let x3 = alpha.square().sub(eight_beta);

        let z3 = self.y.add(self.z).square().sub(gamma).sub(delta);

        let eight_gamma_sq = gamma.square().double().double().double();
        let y3 = alpha.mul(four_beta.sub(x3)).sub(eight_gamma_sq);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete Jacobian point addition handling infinity, doubling, and inverses.
    fn add(&self, rhs: &Self) -> Self {
        if self.is_infinity() {
            return *rhs;
        }
        if rhs.is_infinity() {
            return *self;
        }

        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x.mul(z2z2);
        let u2 = rhs.x.mul(z1z1);
        let s1 = self.y.mul(rhs.z).mul(z2z2);
        let s2 = rhs.y.mul(self.z).mul(z1z1);

        let h = u2.sub(u1);
        let r = s2.sub(s1);
        if h.is_zero() {
            return if r.is_zero() {
                self.double()
            } else {
                Self::INFINITY
            };
        }

        let h2 = h.square();
        let h3 = h.mul(h2);
        let v = u1.mul(h2);

        let x3 = r.square().sub(h3).sub(v.double());
        let y3 = r.mul(v.sub(x3)).sub(s1.mul(h3));
        let z3 = h.mul(self.z).mul(rhs.z);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Computes `u1 * G + u2 * Q` via Shamir's simultaneous double-and-add trick.
    fn mul_add(u1: U256, u2: U256, q: &Self) -> Self {
        let g = Self::GENERATOR;
        let g_plus_q = g.add(q);
        let mut acc = Self::INFINITY;

        let mut bit = 256;
        while bit > 0 {
            bit -= 1;
            acc = acc.double();
            match (u256_bit(u1, bit), u256_bit(u2, bit)) {
                (0, 0) => {}
                (1, 0) => acc = acc.add(&g),
                (0, 1) => acc = acc.add(q),
                _ => acc = acc.add(&g_plus_q),
            }
        }
        acc
    }

    /// Converts a non-infinity Jacobian point to its affine `x`-coordinate (`X / Z^2 mod p`).
    fn to_affine_x(self) -> Option<U256> {
        if self.is_infinity() {
            return None;
        }
        let z2_inv = self.z.square().invert();
        Some(self.x.mul(z2_inv).to_u256())
    }

    #[cfg(test)]
    fn scalar_mul_generator(k: U256) -> Self {
        Self::mul_add(k, U256_ZERO, &Self::INFINITY)
    }

    #[cfg(test)]
    fn to_affine(self) -> Option<(U256, U256)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.invert();
        let z2_inv = z_inv.square();
        let z3_inv = z2_inv.mul(z_inv);
        Some((self.x.mul(z2_inv).to_u256(), self.y.mul(z3_inv).to_u256()))
    }
}

#[cfg(test)]
pub(crate) fn test_public_key_from_secret(secret: &[u8; 32]) -> [u8; P256_UNCOMPRESSED_KEY_LEN] {
    let d = u256_from_be_slice(secret);
    let (x, y) = JacobianPoint::scalar_mul_generator(d)
        .to_affine()
        .expect("non-zero test secret produces affine point");
    let mut sec1 = [0u8; P256_UNCOMPRESSED_KEY_LEN];
    sec1[0] = SEC1_UNCOMPRESSED_PREFIX;
    sec1[1..33].copy_from_slice(&u256_to_be_bytes(x));
    sec1[33..65].copy_from_slice(&u256_to_be_bytes(y));
    sec1
}

#[cfg(test)]
pub(crate) fn test_sign_prehash_with_nonce(
    secret: &[u8; 32],
    nonce: &[u8; 32],
    digest: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let d = Scalar::from_u256(u256_from_be_slice(secret));
    let k_raw = u256_from_be_slice(nonce);
    let k = Scalar::from_u256(k_raw);
    let (rx, _) = JacobianPoint::scalar_mul_generator(k_raw)
        .to_affine()
        .expect("non-zero test nonce produces affine point");
    let r_raw = reduce_u256_mod_n(rx);
    let r = Scalar::from_u256(r_raw);
    let z = Scalar::from_u256(reduce_u256_mod_n(u256_from_be_slice(digest)));
    let s_raw = k.invert().mul(z.add(r.mul(d))).to_u256();
    (u256_to_be_bytes(r_raw), u256_to_be_bytes(s_raw))
}

#[cfg(test)]
#[path = "p256_tests.rs"]
mod tests;
