//! GOST 28147-89 (a.k.a. "Magma") block cipher with selectable S-box sets.
//!
//! We need this because the CryptoPro KDF decrypts the wrapped private key
//! with either:
//!   * CryptoPro Set A   (used together with GOST R 34.10-2001)
//!   * TC26 Set Z        (used together with GOST R 34.10-2012)
//!
//! Off-the-shelf Rust crates (e.g. `magma`) hardcode one S-box set, so we
//! implement the cipher here. It's a tiny Feistel cipher — easy to verify.
//!
//! Block size: 64 bit (two little-endian 32-bit halves)
//! Key size:   256 bit (eight little-endian 32-bit subkeys k0..k7)
//! Rounds:     32, with key schedule
//!     enc: k0 k1 k2 k3 k4 k5 k6 k7  ×3,  k7 k6 k5 k4 k3 k2 k1 k0
//!     dec: k0 k1 k2 k3 k4 k5 k6 k7,  k7 k6 k5 k4 k3 k2 k1 k0  ×3
//! (i.e. decryption reverses the order of the 32 round keys.)

use zeroize::Zeroize;

#[derive(Debug, Clone, Copy)]
pub struct SBox {
    /// 8 rows × 16 columns of 4-bit values.
    pub rows: [[u8; 16]; 8],
}

impl SBox {
    /// CryptoPro paramset A (id-Gost28147-89-CryptoPro-A-ParamSet).
    pub const CRYPTOPRO_A: SBox = SBox {
        rows: [
            [9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5],
            [3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1],
            [14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9],
            [14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6],
            [11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6],
            [3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6],
            [1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14],
            [11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4],
        ],
    };

    /// TC26 paramset Z (id-tc26-gost-28147-param-Z).
    pub const TC26_Z: SBox = SBox {
        rows: [
            [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
            [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
            [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
            [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
            [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
            [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
            [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
            [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
        ],
    };
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Gost28147 {
    /// 8 round subkeys (little-endian u32s of the 32-byte key).
    keys: [u32; 8],
    #[zeroize(skip)]
    sbox: SBox,
}

impl Gost28147 {
    /// Build a cipher instance from a 32-byte key and a parameter set.
    pub fn new(key: &[u8; 32], sbox: SBox) -> Self {
        let mut keys = [0u32; 8];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            keys[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Self { keys, sbox }
    }

    /// Core round function f(a, k) = rol11( SBox( a + k mod 2^32 ) ).
    #[inline(always)]
    fn f(&self, a: u32, k: u32) -> u32 {
        let v = a.wrapping_add(k);
        let mut out: u32 = 0;
        for i in 0..8 {
            let nibble = ((v >> (i * 4)) & 0xf) as usize;
            let sub = u32::from(self.sbox.rows[i][nibble]) & 0xf;
            out |= sub << (i * 4);
        }
        out.rotate_left(11)
    }

    /// Build the round-key schedule.  `decrypting == true` reverses the
    /// order so that decryption is the inverse of encryption.
    ///
    /// Encryption schedule:
    ///   k0 k1 k2 k3 k4 k5 k6 k7  ×3 ,  then  k7 k6 k5 k4 k3 k2 k1 k0
    fn schedule(&self, decrypting: bool) -> [u32; 32] {
        let mut s = [0u32; 32];
        // First 24 rounds: three repetitions of k0..k7.
        for r in 0..3 {
            for i in 0..8 {
                s[r * 8 + i] = self.keys[i];
            }
        }
        // Last 8 rounds: k7..k0.
        for i in 0..8 {
            s[24 + i] = self.keys[7 - i];
        }
        if decrypting {
            s.reverse();
        }
        s
    }

    /// Encrypt one 8-byte block in place (ECB mode).
    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        self.run_block(block, self.schedule(false));
    }

    /// Decrypt one 8-byte block in place (ECB mode).
    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        self.run_block(block, self.schedule(true));
    }

    fn run_block(&self, block: &mut [u8; 8], sched: [u32; 32]) {
        // Two 32-bit halves, little-endian as per GOST.
        let mut n1 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(block[4..8].try_into().unwrap());

        for &k in &sched[..31] {
            let t = n1;
            n1 = n2 ^ self.f(n1, k);
            n2 = t;
        }
        // Last round: no swap.
        n2 ^= self.f(n1, sched[31]);

        block[0..4].copy_from_slice(&n1.to_le_bytes());
        block[4..8].copy_from_slice(&n2.to_le_bytes());
    }

    /// Decrypt a multi-block buffer in place (ECB).
    pub fn decrypt_ecb(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "data length must be multiple of 8");
        for chunk in data.chunks_exact_mut(8) {
            let mut block: [u8; 8] = chunk.try_into().unwrap();
            self.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(sbox: SBox, key: [u8; 32], plaintext: [u8; 8]) {
        let cipher = Gost28147::new(&key, sbox);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, plaintext, "encryption was a no-op");
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "dec(enc(x)) != x");
    }

    #[test]
    fn roundtrip_cryptopro_a() {
        // A handful of different (key, plaintext) pairs.
        roundtrip(SBox::CRYPTOPRO_A, [0u8; 32], [0u8; 8]);
        roundtrip(SBox::CRYPTOPRO_A, [0xffu8; 32], [0xffu8; 8]);
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        roundtrip(SBox::CRYPTOPRO_A, k, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn roundtrip_tc26_z() {
        roundtrip(SBox::TC26_Z, [0u8; 32], [0u8; 8]);
        roundtrip(SBox::TC26_Z, [0xa5u8; 32], [0x5a; 8]);
    }

    #[test]
    fn ecb_roundtrip_multiblock() {
        let key = [0x33u8; 32];
        let cipher = Gost28147::new(&key, SBox::TC26_Z);
        let plaintext: Vec<u8> = (0..64).collect();
        let mut buf = plaintext.clone();
        // Encrypt block-by-block.
        for chunk in buf.chunks_exact_mut(8) {
            let mut b: [u8; 8] = chunk.try_into().unwrap();
            cipher.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
        }
        cipher.decrypt_ecb(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn different_sboxes_diverge() {
        // Same key, same plaintext, different S-box → different ciphertext.
        let key = [0x55u8; 32];
        let pt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut b1 = pt;
        let mut b2 = pt;
        Gost28147::new(&key, SBox::CRYPTOPRO_A).encrypt_block(&mut b1);
        Gost28147::new(&key, SBox::TC26_Z).encrypt_block(&mut b2);
        assert_ne!(b1, b2);
    }
}
