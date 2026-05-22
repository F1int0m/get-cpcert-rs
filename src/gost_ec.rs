//! GOST R 34.10 elliptic curves and the bare minimum of group operations
//! we need to:
//!
//!   1. Compute `mask^-1 mod q`.
//!   2. Compute `raw_secret = key_with_mask * mask^-1  mod q`.
//!   3. Compute `Q = raw_secret * G` to recover the public key.
//!   4. Compare `Q.x[0..8]` (little-endian) against the 8-byte tag stored
//!      in `header.key`.
//!
//! Curves used by the original utility:
//!   * GOST-2001         → id-GostR3410-2001-CryptoPro-XchA-ParamSet
//!                         (OID 1.2.643.2.2.36.0)
//!   * GOST-2012-256     → same curve as above
//!   * GOST-2012-512     → id-tc26-gost-3410-2012-512-paramSetA
//!                         (OID 1.2.643.7.1.2.1.2.1)
//!
//! Curves are in short Weierstrass form: y² = x³ + a·x + b  (mod p).

use num_bigint_dig::{BigUint, ModInverse};
use num_traits::Zero;

#[derive(Debug, Clone)]
pub struct Curve {
    pub p: BigUint, // field prime
    pub a: BigUint, // curve coefficient a
    pub b: BigUint, // curve coefficient b
    pub q: BigUint, // order of base point
    pub gx: BigUint,
    pub gy: BigUint,
    /// Coordinate / scalar byte length (32 for 256-bit, 64 for 512-bit).
    pub coord_bytes: usize,
}

impl Curve {
    /// CryptoPro_XchA_ParamSet (used for GOST-2001 and GOST-2012-256).
    pub fn cryptopro_xch_a() -> Self {
        Self {
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
            a: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
            b: hex("00000000000000000000000000000000000000000000000000000000000000A6"),
            q: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
            gx: hex("0000000000000000000000000000000000000000000000000000000000000001"),
            gy: hex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
            coord_bytes: 32,
        }
    }

    /// tc26-gost-3410-12-512-paramSetA.
    pub fn tc26_512_a() -> Self {
        Self {
            p: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            ),
            a: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
            ),
            b: hex(
                "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265\
                 EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
            ),
            q: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                 27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
            ),
            gx: hex(
                "00000000000000000000000000000000000000000000000000000000000000\
                 00000000000000000000000000000000000000000000000000000000000003",
            ),
            gy: hex(
                "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921\
                 DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
            ),
            coord_bytes: 64,
        }
    }

    fn add_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x + y) % &self.p
    }

    fn sub_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        if x >= y {
            (x - y) % &self.p
        } else {
            (&self.p - ((y - x) % &self.p)) % &self.p
        }
    }

    fn mul_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x * y) % &self.p
    }

    fn inv_mod_p(&self, x: &BigUint) -> BigUint {
        x.mod_inverse(&self.p)
            .expect("non-invertible in F_p")
            .to_biguint()
            .expect("negative result")
    }
}

#[derive(Debug, Clone)]
pub enum Point {
    Infinity,
    Affine { x: BigUint, y: BigUint },
}

impl Point {
    pub fn base(curve: &Curve) -> Self {
        Point::Affine {
            x: curve.gx.clone(),
            y: curve.gy.clone(),
        }
    }

    pub fn double(&self, curve: &Curve) -> Point {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => {
                if y.is_zero() {
                    return Point::Infinity;
                }
                // λ = (3x² + a) / (2y) mod p
                let three = BigUint::from(3u32);
                let two = BigUint::from(2u32);
                let num = curve.add_mod(&curve.mul_mod(&three, &curve.mul_mod(x, x)), &curve.a);
                let den = curve.mul_mod(&two, y);
                let lam = curve.mul_mod(&num, &curve.inv_mod_p(&den));

                // x3 = λ² - 2x
                let lam_sq = curve.mul_mod(&lam, &lam);
                let two_x = curve.mul_mod(&two, x);
                let x3 = curve.sub_mod(&lam_sq, &two_x);

                // y3 = λ·(x - x3) - y
                let y3 = curve.sub_mod(&curve.mul_mod(&lam, &curve.sub_mod(x, &x3)), y);
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    pub fn add(&self, other: &Point, curve: &Curve) -> Point {
        match (self, other) {
            (Point::Infinity, p) | (p, Point::Infinity) => p.clone(),
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.double(curve);
                    }
                    return Point::Infinity;
                }
                // λ = (y2 - y1) / (x2 - x1) mod p
                let num = curve.sub_mod(y2, y1);
                let den = curve.sub_mod(x2, x1);
                let lam = curve.mul_mod(&num, &curve.inv_mod_p(&den));

                // x3 = λ² - x1 - x2
                let lam_sq = curve.mul_mod(&lam, &lam);
                let x3 = curve.sub_mod(&curve.sub_mod(&lam_sq, x1), x2);

                // y3 = λ·(x1 - x3) - y1
                let y3 = curve.sub_mod(&curve.mul_mod(&lam, &curve.sub_mod(x1, &x3)), y1);
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    /// k · P via left-to-right double-and-add.
    pub fn scalar_mul(&self, k: &BigUint, curve: &Curve) -> Point {
        if k.is_zero() {
            return Point::Infinity;
        }
        let mut result = Point::Infinity;
        // Walk bits of k from MSB to LSB via its big-endian byte form.
        let bytes = k.to_bytes_be();
        let mut started = false;
        for byte in bytes {
            for bit_idx in (0..8).rev() {
                let bit = (byte >> bit_idx) & 1 == 1;
                if !started {
                    if !bit {
                        continue;
                    }
                    started = true;
                    result = self.clone();
                    continue;
                }
                result = result.double(curve);
                if bit {
                    result = result.add(self, curve);
                }
            }
        }
        result
    }
}

fn hex(s: &str) -> BigUint {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    BigUint::parse_bytes(cleaned.as_bytes(), 16).expect("bad hex literal")
}

/// Convenience: given an integer with arbitrary number of bytes, encode it
/// big-endian zero-padded to `n` bytes.
pub fn to_be_bytes_padded(x: &BigUint, n: usize) -> Vec<u8> {
    let raw = x.to_bytes_be();
    if raw.len() >= n {
        return raw[raw.len() - n..].to_vec();
    }
    let mut out = vec![0u8; n - raw.len()];
    out.extend_from_slice(&raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    fn affine(p: &Point) -> (BigUint, BigUint) {
        match p {
            Point::Affine { x, y } => (x.clone(), y.clone()),
            Point::Infinity => panic!("expected affine point"),
        }
    }

    #[test]
    fn base_point_is_on_curve() {
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            // y² ≟ x³ + a·x + b   (mod p)
            let lhs = curve.mul_mod(&curve.gy, &curve.gy);
            let x3 = curve.mul_mod(&curve.gx, &curve.mul_mod(&curve.gx, &curve.gx));
            let ax = curve.mul_mod(&curve.a, &curve.gx);
            let rhs = curve.add_mod(&curve.add_mod(&x3, &ax), &curve.b);
            assert_eq!(lhs, rhs, "base point not on curve");
        }
    }

    #[test]
    fn order_kills_base_point() {
        // q · G must be the point at infinity for both curves.
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let result = Point::base(&curve).scalar_mul(&curve.q, &curve);
            assert!(matches!(result, Point::Infinity), "q·G ≠ ∞");
        }
    }

    #[test]
    fn double_equals_add_self() {
        // 2G == G + G  via two different code paths
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let via_double = g.double(&curve);
            let via_add = g.add(&g, &curve);
            assert_eq!(affine(&via_double), affine(&via_add));
        }
    }

    #[test]
    fn scalar_mul_one_is_identity() {
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let one = BigUint::one();
            let r = g.scalar_mul(&one, &curve);
            assert_eq!(affine(&r), (curve.gx.clone(), curve.gy.clone()));
        }
    }

    #[test]
    fn scalar_mul_two_equals_double() {
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let two = BigUint::from(2u32);
            let via_mul = g.scalar_mul(&two, &curve);
            let via_double = g.double(&curve);
            assert_eq!(affine(&via_mul), affine(&via_double));
        }
    }

    #[test]
    fn addition_is_associative() {
        // (G + 2G) + 3G  ==  G + (2G + 3G)  — a non-trivial associativity check.
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let g2 = g.scalar_mul(&BigUint::from(2u32), &curve);
            let g3 = g.scalar_mul(&BigUint::from(3u32), &curve);
            let left = g.add(&g2, &curve).add(&g3, &curve);
            let right = g.add(&g2.add(&g3, &curve), &curve);
            assert_eq!(affine(&left), affine(&right));
        }
    }

    #[test]
    fn scalar_distributes_over_addition() {
        // 5G == 2G + 3G   (and is the same as scalar_mul(5))
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let g2 = g.scalar_mul(&BigUint::from(2u32), &curve);
            let g3 = g.scalar_mul(&BigUint::from(3u32), &curve);
            let g5_via_add = g2.add(&g3, &curve);
            let g5_via_mul = g.scalar_mul(&BigUint::from(5u32), &curve);
            assert_eq!(affine(&g5_via_add), affine(&g5_via_mul));
        }
    }

    #[test]
    fn scalar_q_minus_one_then_plus_g_is_infinity() {
        // (q-1)·G + G  ==  q·G  ==  ∞
        for curve in [Curve::cryptopro_xch_a(), Curve::tc26_512_a()] {
            let g = Point::base(&curve);
            let q_minus_1 = &curve.q - BigUint::one();
            let p = g.scalar_mul(&q_minus_1, &curve);
            let result = p.add(&g, &curve);
            assert!(matches!(result, Point::Infinity));
        }
    }
}
