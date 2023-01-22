use librypt_hash::{Hash, HashFn};

pub struct Blake2s {
    total: u64,
    state: [u32; 8],
    secret: (u8, [u8; 64]),
    buffer: (usize, [u8; 64]),
}

impl Blake2s {
    pub const STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub const SIGMA: [[u8; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    pub const MIX_INDICIES: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    pub fn with_secret<const OUTPUT_SIZE: usize>(secret: &[u8]) -> Self {
        let key_length = secret.len().min(32);

        let mut key = [0u8; 64];

        key[0..key_length].copy_from_slice(&secret[..key_length]);

        let mut state = Self::STATE;

        state[0] ^= 0x01010000 ^ ((key_length as u32) << 8) ^ OUTPUT_SIZE as u32;

        let mut hasher = Self {
            total: 0,
            state,
            secret: (key_length as u8, key),
            buffer: (0, [0u8; 64]),
        };

        <_ as HashFn<64, OUTPUT_SIZE>>::update(&mut hasher, &key);

        hasher
    }

    fn mix(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: u32, y: u32) {
        *a = a.wrapping_add(b.wrapping_add(x));
        *d = (*d ^ *a).rotate_right(16);

        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_right(12);

        *a = a.wrapping_add(b.wrapping_add(y));
        *d = (*d ^ *a).rotate_right(8);

        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_right(7);
    }

    fn compute(&mut self, last: bool) {
        let mut state = [0u32; 16];

        state[0..8].copy_from_slice(&self.state);
        state[8..16].copy_from_slice(&Self::STATE);

        state[12] ^= self.total as u32;
        state[13] ^= (self.total >> 32) as u32;

        if last {
            state[14] = !state[14];
        }

        let words: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(self.buffer.1[i * 4..i * 4 + 4].try_into().unwrap())
        });

        for i in 0..10 {
            let s = Self::SIGMA[i];

            for j in 0..8 {
                let indicies = Self::MIX_INDICIES[j];

                let mut a = state[indicies[0]];
                let mut b = state[indicies[1]];
                let mut c = state[indicies[2]];
                let mut d = state[indicies[3]];

                let x = words[s[j * 2] as usize];
                let y = words[s[j * 2 + 1] as usize];

                Self::mix(&mut a, &mut b, &mut c, &mut d, x, y);

                state[indicies[0]] = a;
                state[indicies[1]] = b;
                state[indicies[2]] = c;
                state[indicies[3]] = d;
            }
        }

        for i in 0..8 {
            self.state[i] ^= state[i] ^ state[i + 8];
        }
    }
}

impl<const OUTPUT_SIZE: usize> HashFn<64, OUTPUT_SIZE> for Blake2s {
    fn new() -> Self {
        let mut state = Self::STATE;

        state[0] ^= 0x01010000 ^ OUTPUT_SIZE as u32;

        Self {
            total: 0,
            state,
            secret: (0, [0u8; 64]),
            buffer: (0, [0u8; 64]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        for i in 0..data.len() {
            self.buffer.1[self.buffer.0] = data[i];
            self.buffer.0 += 1;

            if self.buffer.0 == 64 {
                self.total += 64;

                self.compute(false);

                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<OUTPUT_SIZE> {
        self.total += self.buffer.0 as u64;

        for i in self.buffer.0..64 {
            self.buffer.1[i] = 0;
        }

        self.compute(true);

        let mut hash = [0u8; OUTPUT_SIZE];

        for i in 0..((OUTPUT_SIZE - 1) / 4) + 1 {
            hash[i * 4..OUTPUT_SIZE.min((i * 4) + 4)].copy_from_slice(
                &self.state[i].to_le_bytes()[..OUTPUT_SIZE.min((i * 4) + 4) - (i * 4)],
            );
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<OUTPUT_SIZE> {
        self.total += self.buffer.0 as u64;

        for i in self.buffer.0..64 {
            self.buffer.1[i] = 0;
        }

        self.compute(true);

        let mut hash = [0u8; OUTPUT_SIZE];

        for i in 0..((OUTPUT_SIZE - 1) / 4) + 1 {
            hash[i * 4..OUTPUT_SIZE.min((i * 4) + 4)].copy_from_slice(
                &self.state[i].to_le_bytes()[..OUTPUT_SIZE.min((i * 4) + 4) - (i * 4)],
            );
        }

        // reset state
        self.total = 0;

        let mut state = Self::STATE;

        state[0] ^= 0x01010000 ^ ((self.secret.0 as u32) << 8) ^ OUTPUT_SIZE as u32;

        self.state = state;
        self.buffer = (0, [0u8; 64]);

        if self.secret.0 > 0 {
            let secret = self.secret.1;

            <_ as HashFn<64, OUTPUT_SIZE>>::update(self, &secret);
        }

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_blake2s() {
        let hash: [u8; 32] = Blake2s::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "30d8777f0e178582ec8cd2fcdc18af57c828ee2f89e978df52c8e7af078bd5cf"
        );
    }

    #[test]
    fn test_blake2s_keyed() {
        let mut hasher = Blake2s::with_secret::<32>(b"test");

        <_ as HashFn<64, 32>>::update(&mut hasher, b"Hello, world!");

        let hash: [u8; 32] = hasher.finalize();

        assert_eq!(
            hash.encode_hex::<String>(),
            "6c70f35f9ef5a265b1e774e9f1baa3dc50622966158b0808b2e302c9564e2844"
        );
    }
}
