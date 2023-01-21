use librypt_hash::{Hash, HashFn};

pub struct Blake2b {
    total: u128,
    state: [u64; 8],
    buffer: (usize, [u8; 128]),
}

impl Blake2b {
    pub const STATE: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    fn compute(&mut self) {}
}

impl HashFn<128, 64> for Blake2b {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::STATE,
            buffer: (0, [0u8; 128]),
        }
    }

    fn update(&mut self, data: &[u8]) {}

    fn finalize(self) -> Hash<64> {
        todo!()
    }

    fn finalize_reset(&mut self) -> Hash<64> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_blake2b() {
        let hash = Blake2b::hash(b"Hello, world!");

        assert_eq!(hash.encode_hex::<String>(), "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d7d46337812f87327ad7108fbaa955f009afa495ca8c05c33eb050002ac9b99bc");
    }
}
