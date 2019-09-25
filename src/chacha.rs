//! #ChaCha stream cipher
//! Implementation of the [ChaCha stream cipher](https://tools.ietf.org/html/rfc7539), and the
//! [XChaCha extention](https://tools.ietf.org/html/draft-arciszewski-xchacha-02)

use std::cmp;
use std::ops::{Add, AddAssign};

type u32x4 = [u32; 4];
const CHACHA_CONST_HEADER: u32x4 = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

macro_rules! QR {
    ($s:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {{
        let idx_a = $a;
        let idx_b = $b - 4;
        let idx_c = $c - 8;
        let idx_d = $d - 12;

        $s.a[idx_a] = $s.a[idx_a].wrapping_add($s.b[idx_b]);
        $s.d[idx_d] ^= $s.a[idx_a];
        $s.d[idx_d] = $s.d[idx_d].rotate_left(16);

        $s.c[idx_c] = $s.c[idx_c].wrapping_add($s.d[idx_d]);
        $s.b[idx_b] ^= $s.c[idx_c];
        $s.b[idx_b] = $s.b[idx_b].rotate_left(12);

        $s.a[idx_a] = $s.a[idx_a].wrapping_add($s.b[idx_b]);
        $s.d[idx_d] ^= $s.a[idx_a];
        $s.d[idx_d] = $s.d[idx_d].rotate_left(8);

        $s.c[idx_c] = $s.c[idx_c].wrapping_add($s.d[idx_d]);
        $s.b[idx_b] ^= $s.c[idx_c];
        $s.b[idx_b] = $s.b[idx_b].rotate_left(7);
    }};
}

macro_rules! to_u32_le {
    ($x:expr) => {{
        (($x[0] as u32) << 0)
            | (($x[1] as u32) << 8)
            | (($x[2] as u32) << 16)
            | (($x[3] as u32) << 24)
    }};
}

macro_rules! to_buf_le {
    ($buf:expr, $n:expr) => {{
        $buf[0] = (($n >> 0) & 0xffu32) as u8;
        $buf[1] = (($n >> 8) & 0xffu32) as u8;
        $buf[2] = (($n >> 16) & 0xffu32) as u8;
        $buf[3] = (($n >> 24) & 0xffu32) as u8;
    }};
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct ChaChaState {
    a: u32x4,
    b: u32x4,
    c: u32x4,
    d: u32x4,
}

impl ChaChaState {
    pub fn new() -> Self {
        ChaChaState {
            a: [0, 0, 0, 0],
            b: [0, 0, 0, 0],
            c: [0, 0, 0, 0],
            d: [0, 0, 0, 0],
        }
    }

    pub fn from_params(key: &[u8], nonce: &[u8], b_cnt: u32) -> Self {
        ChaChaState {
            a: CHACHA_CONST_HEADER,
            b: [
                to_u32_le!(&key[0..4]),
                to_u32_le!(&key[4..8]),
                to_u32_le!(&key[8..12]),
                to_u32_le!(&key[12..16]),
            ],
            c: [
                to_u32_le!(&key[16..20]),
                to_u32_le!(&key[20..24]),
                to_u32_le!(&key[24..28]),
                to_u32_le!(&key[28..32]),
            ],
            d: [
                b_cnt,
                to_u32_le!(&nonce[0..4]),
                to_u32_le!(&nonce[4..8]),
                to_u32_le!(&nonce[8..12]),
            ],
        }
    }

    pub fn get_ctr_mut(&mut self) -> &mut u32 {
        &mut self.d[0]
    }

    pub fn get_ctr(&self) -> u32 {
        self.d[0]
    }

    pub fn to_buf(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf.chunks_mut(4)
            .zip(
                self.a
                    .iter()
                    .chain(self.b.iter())
                    .chain(self.c.iter())
                    .chain(self.d.iter()),
            )
            .for_each(|(b, n)| {
                to_buf_le!(b, n);
            });
        buf
    }
}

impl Add for ChaChaState {
    type Output = ChaChaState;

    fn add(self, other: ChaChaState) -> ChaChaState {
        ChaChaState {
            a: [
                self.a[0].wrapping_add(other.a[0]),
                self.a[1].wrapping_add(other.a[1]),
                self.a[2].wrapping_add(other.a[2]),
                self.a[3].wrapping_add(other.a[3]),
            ],
            b: [
                self.b[0].wrapping_add(other.b[0]),
                self.b[1].wrapping_add(other.b[1]),
                self.b[2].wrapping_add(other.b[2]),
                self.b[3].wrapping_add(other.b[3]),
            ],
            c: [
                self.c[0].wrapping_add(other.c[0]),
                self.c[1].wrapping_add(other.c[1]),
                self.c[2].wrapping_add(other.c[2]),
                self.c[3].wrapping_add(other.c[3]),
            ],
            d: [
                self.d[0].wrapping_add(other.d[0]),
                self.d[1].wrapping_add(other.d[1]),
                self.d[2].wrapping_add(other.d[2]),
                self.d[3].wrapping_add(other.d[3]),
            ],
        }
    }
}

impl AddAssign for ChaChaState {
    fn add_assign(&mut self, other: ChaChaState) {
        *self = *self + other;
    }
}

pub struct ChaCha {
    NROUNDS: usize,
    state: ChaChaState,
    out: [u8; 64],
    offset: usize,
}

/// #ChaCha
/// An implementation of the [ChaCha20](https://tools.ietf.org/html/rfc7539).
/// The number of rounds may be optionally changed, plus [XChaCha](https://tools.ietf.org/html/draft-arciszewski-xchacha-02)
/// may be produced.
impl ChaCha {
    pub fn new(rounds: usize, key: &[u8], nonce: &[u8], b_cnt: u32) -> ChaCha {
        assert!(key.len() == 32 && nonce.len() == 12); // the length of the params is strictly specified

        ChaCha {
            NROUNDS: rounds,
            state: ChaChaState::from_params(key, nonce, b_cnt),
            out: [0; 64],
            offset: 64,
        }
    }

    pub fn new_chacha20(key: &[u8], nonce: &[u8], b_cnt: u32) -> ChaCha {
        Self::new(20, key, nonce, b_cnt)
    }

    fn chacha_blk(&mut self) {
        let mut state = self.state;

        for _ in 0..(self.NROUNDS >> 1) {
            //IDEA maybe store this val and now the whole num of rounds?
            // column round
            QR!(state, 0, 4, 8, 12);
            QR!(state, 1, 5, 9, 13);
            QR!(state, 2, 6, 10, 14);
            QR!(state, 3, 7, 11, 15);
            // diagonal round
            QR!(state, 0, 5, 10, 15);
            QR!(state, 1, 6, 11, 12);
            QR!(state, 2, 7, 8, 13);
            QR!(state, 3, 4, 9, 14);
        }

        state += self.state;
        self.out = state.to_buf();

        *self.state.get_ctr_mut() += 1; // Rust does not allow addition without carry, thus it will panic on exhaustion
        self.offset = 0;
    }

    pub fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(
            input.len(),
            output.len(),
            "Input and output buffers must be of the same size."
        );

        let len = input.len();
        let mut i = 0;

        while i < len {
            if self.offset == 64 {
                self.chacha_blk();
            }

            let cnt = cmp::min(64 - self.offset, len - i);
            (&mut output[i..i + cnt]).copy_from_slice(
                (&input[i..i + cnt])
                    .iter()
                    .zip((&self.out[self.offset..]).iter())
                    .map(|(x, y)| x ^ y)
                    .collect::<Vec<u8>>()
                    .as_slice(),
            );

            i += cnt;
            self.offset += cnt;
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn quater_round_test_vals() {
        let mut state = super::ChaChaState {
            a: [0x11111111, 0, 0, 0],
            b: [0x01020304, 0, 0, 0],
            c: [0x9b8d6f43, 0, 0, 0],
            d: [0x01234567, 0, 0, 0],
        };
        let expected = super::ChaChaState {
            a: [0xea2a92f4, 0, 0, 0],
            b: [0xcb1cf8ce, 0, 0, 0],
            c: [0x4581472e, 0, 0, 0],
            d: [0x5881c4bb, 0, 0, 0],
        };
        QR!(state, 0, 4, 8, 12);
        assert_eq!(state, expected);
    }

    #[test]
    fn quater_round_test_idx() {
        let mut state = super::ChaChaState {
            a: [0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a],
            b: [0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c],
            c: [0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963],
            d: [0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320],
        };

        let expected = super::ChaChaState {
            a: [0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a],
            b: [0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2],
            c: [0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963],
            d: [0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320],
        };

        QR!(state, 2, 7, 8, 13);
        assert_eq!(state, expected);
    }

    #[test]
    fn test_chacha_block_function() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let cnt = 1;
        let expected_state = super::ChaChaState {
            a: [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
            b: [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c],
            c: [0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c],
            d: [0x00000001, 0x09000000, 0x4a000000, 0x00000000],
        };
        let expected_out = super::ChaChaState {
            a: [0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3],
            b: [0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3],
            c: [0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9],
            d: [0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2],
        };

        let mut chacha20 = super::ChaCha::new_chacha20(&key, &nonce, cnt);
        assert_eq!(
            chacha20.state, expected_state,
            "The initial state is not formed right"
        );
        chacha20.chacha_blk();
        assert_eq!(
            &chacha20.out[..],
            &expected_out.to_buf()[..],
            "The produced state is not right"
        );
    }

    #[test]
    fn test_encryption_and_decryption() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let b_cnt = 1;

        let plaintxt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertxt = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut output = vec![0u8; plaintxt.len()];
        let mut chacha = super::ChaCha::new_chacha20(&key, &nonce, b_cnt);

        chacha.process(plaintxt, &mut output);

        assert_eq!(
            &output[..],
            &ciphertxt[..],
            "The encryption is wrong, result does not match expexted ciphertext"
        );
    }
}
