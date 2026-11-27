use sha2::{Digest, Sha256};

use super::*;

fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    bytes.try_into().expect("32 bytes")
}

fn sec1_from_xy_hex(x_hex: &str, y_hex: &str) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&hex32(x_hex));
    out[33..65].copy_from_slice(&hex32(y_hex));
    out
}

#[test]
fn rfc6979_a25_sample_and_test_vectors_verify_both_low_and_high_s() {
    // RFC 6979 Appendix A.2.5 (ECDSA, 256 Bits, P-256, SHA-256)
    let priv_d = hex32("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let expected_sec1 = sec1_from_xy_hex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    );
    assert_eq!(test_public_key_from_secret(&priv_d), expected_sec1);
    let pk = P256PublicKey::from_sec1_uncompressed(&expected_sec1).expect("valid RFC 6979 pubkey");
    assert_eq!(pk.as_sec1_bytes(), &expected_sec1);

    // Vector 1: msg = "sample" (high-S native, plus low-S twin n - s)
    let z_sample: [u8; 32] = Sha256::digest(b"sample").into();
    let r_sample = hex32("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    let s_sample_high = hex32("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    let s_sample_low = hex32("0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9");
    pk.verify_prehash(&z_sample, &r_sample, &s_sample_high)
        .expect("RFC 6979 sample high-S must verify");
    pk.verify_prehash(&z_sample, &r_sample, &s_sample_low)
        .expect("RFC 6979 sample low-S must verify");

    // Vector 2: msg = "test" (low-S native, plus high-S twin n - s)
    let z_test: [u8; 32] = Sha256::digest(b"test").into();
    let r_test = hex32("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367");
    let s_test_low = hex32("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
    let s_test_high = hex32("fe60beeb8bd5d4ec42da6d94b639b6ea5dc07c4cd3965338e6f1887217f424ce");
    pk.verify_prehash(&z_test, &r_test, &s_test_low)
        .expect("RFC 6979 test low-S must verify");
    pk.verify_prehash(&z_test, &r_test, &s_test_high)
        .expect("RFC 6979 test high-S must verify");

    // Bit flips in r, s, and digest must all fail with SignatureMismatch.
    let mut bad_r = r_sample;
    bad_r[31] ^= 0x01;
    assert_eq!(
        pk.verify_prehash(&z_sample, &bad_r, &s_sample_high),
        Err(P256Error::SignatureMismatch)
    );

    let mut bad_s = s_sample_high;
    bad_s[0] ^= 0x01;
    assert_eq!(
        pk.verify_prehash(&z_sample, &r_sample, &bad_s),
        Err(P256Error::SignatureMismatch)
    );

    let mut bad_z = z_sample;
    bad_z[15] ^= 0x80;
    assert_eq!(
        pk.verify_prehash(&bad_z, &r_sample, &s_sample_high),
        Err(P256Error::SignatureMismatch)
    );
}

#[test]
fn public_key_validation_rejects_length_prefix_range_and_off_curve() {
    // Wrong lengths
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&[]),
        Err(P256Error::InvalidLength(0))
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&[0x04; 33]),
        Err(P256Error::InvalidLength(33))
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&[0x04; 64]),
        Err(P256Error::InvalidLength(64))
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&[0x04; 66]),
        Err(P256Error::InvalidLength(66))
    );

    // Wrong prefixes (infinity 0x00, compressed 0x02/0x03, hybrid 0x06, arbitrary 0x05)
    let mut valid_sec1 = sec1_from_xy_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    P256PublicKey::from_sec1_uncompressed(&valid_sec1).expect("generator G is valid");
    for bad_prefix in [0x00u8, 0x02, 0x03, 0x05, 0x06, 0xff] {
        valid_sec1[0] = bad_prefix;
        assert_eq!(
            P256PublicKey::from_sec1_uncompressed(&valid_sec1),
            Err(P256Error::InvalidPrefix(bad_prefix))
        );
    }

    // Coordinates >= p (exact p and 0xff..ff)
    let p_hex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    let ff_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let zero_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&sec1_from_xy_hex(p_hex, zero_hex)),
        Err(P256Error::CoordinateOutOfRange)
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&sec1_from_xy_hex(zero_hex, p_hex)),
        Err(P256Error::CoordinateOutOfRange)
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&sec1_from_xy_hex(ff_hex, zero_hex)),
        Err(P256Error::CoordinateOutOfRange)
    );

    // Origin (0, 0) and perturbed generator (Gx, Gy + 1) are off-curve.
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&sec1_from_xy_hex(zero_hex, zero_hex)),
        Err(P256Error::NotOnCurve)
    );
    let mut off_curve = sec1_from_xy_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
    );
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&off_curve),
        Err(P256Error::NotOnCurve)
    );
    off_curve[32] ^= 0x01;
    assert_eq!(
        P256PublicKey::from_sec1_uncompressed(&off_curve),
        Err(P256Error::NotOnCurve)
    );
}

#[test]
fn scalar_bounds_infinity_and_edge_cases_are_strictly_enforced() {
    let g_sec1 = sec1_from_xy_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    let g_pk = P256PublicKey::from_sec1_uncompressed(&g_sec1).expect("G valid");
    let zero = [0u8; 32];
    let one = hex32("0000000000000000000000000000000000000000000000000000000000000001");
    let n_bytes = hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let n_plus_1 = hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    let z_ff = [0xffu8; 32];

    // r = 0, s = 0, r = n, s = n, r > n, s > n all fail with InvalidSignatureScalar.
    for (r, s) in [
        (zero, one),
        (one, zero),
        (n_bytes, one),
        (one, n_bytes),
        (n_plus_1, one),
        (one, n_plus_1),
    ] {
        assert_eq!(
            g_pk.verify_prehash(&z_ff, &r, &s),
            Err(P256Error::InvalidSignatureScalar)
        );
    }

    // Digest z >= n (0xff..ff) signed with d = 1 (Q = G) exercises Q == G doubling & z mod n reduction.
    let k = hex32("0000000000000000000000000000000000000000000000000000000000000003");
    let (r, s) = test_sign_prehash_with_nonce(&one, &k, &z_ff);
    g_pk.verify_prehash(&z_ff, &r, &s)
        .expect("z >= n with Q == G must verify");

    // Point at infinity in verification: Q = G, r = 1, s = 1, z = n - 1 => u1 = n - 1, u2 = 1 => (n-1)G + G = ∞!
    let n_minus_1 = hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
    assert_eq!(
        g_pk.verify_prehash(&n_minus_1, &one, &one),
        Err(P256Error::PointAtInfinity)
    );

    // Also exercise Q == -G (d = n - 1) in Shamir's trick where G + Q = ∞!
    let neg_g_sec1 = test_public_key_from_secret(&n_minus_1);
    let neg_g_pk = P256PublicKey::from_sec1_uncompressed(&neg_g_sec1).expect("-G valid");
    let (r_ng, s_ng) = test_sign_prehash_with_nonce(&n_minus_1, &k, &z_ff);
    neg_g_pk
        .verify_prehash(&z_ff, &r_ng, &s_ng)
        .expect("Q == -G must verify cleanly when G + Q = infinity");

    // Exercise Jacobian point arithmetic edge cases directly (infinity doubling/addition/to_affine).
    assert!(JacobianPoint::INFINITY.double().is_infinity());
    assert_eq!(
        JacobianPoint::INFINITY.add(&JacobianPoint::GENERATOR),
        JacobianPoint::GENERATOR
    );
    assert_eq!(
        JacobianPoint::GENERATOR.add(&JacobianPoint::INFINITY),
        JacobianPoint::GENERATOR
    );
    assert_eq!(
        JacobianPoint::GENERATOR.add(&JacobianPoint::GENERATOR),
        JacobianPoint::GENERATOR.double()
    );
    assert!(JacobianPoint::INFINITY.to_affine_x().is_none());
    assert!(JacobianPoint::INFINITY.to_affine().is_none());

    // Cover Display on every P256Error variant.
    let errs = [
        P256Error::InvalidLength(10),
        P256Error::InvalidPrefix(0x02),
        P256Error::CoordinateOutOfRange,
        P256Error::NotOnCurve,
        P256Error::InvalidSignatureScalar,
        P256Error::PointAtInfinity,
        P256Error::SignatureMismatch,
    ];
    for err in errs {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn affine_x_greater_than_n_reduces_modulo_n() {
    // Valid P-256 curve point Q with x = n + 3 (< p, >= n):
    // With digest z = 0 and r = s = 3, u1 = 0 and u2 = r * s^-1 = 1,
    // so u1*G + u2*Q = Q has affine x = n + 3, which MUST reduce mod n to 3 == r.
    let q_sec1 = sec1_from_xy_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632554",
        "484f0c0fda434ef0a808458914f328715d7a545e198ac7eee31dffe861b5d23f",
    );
    let pk = P256PublicKey::from_sec1_uncompressed(&q_sec1).expect("Q=(n+3, y) is on P-256");
    let z_zero = [0u8; 32];
    let mut three = [0u8; 32];
    three[31] = 3;
    pk.verify_prehash(&z_zero, &three, &three)
        .expect("affine x = n + 3 must reduce mod n to r = 3");

    let mut four = [0u8; 32];
    four[31] = 4;
    assert_eq!(
        pk.verify_prehash(&z_zero, &four, &four),
        Err(P256Error::SignatureMismatch)
    );
}
