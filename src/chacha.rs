//! #ChaCha stream cypher
//! Implementation of the [ChaCha stream cypher](https://tools.ietf.org/html/rfc7539), and the
//! [XChaCha extention](https://tools.ietf.org/html/draft-arciszewski-xchacha-02)

type u32x4 = [u32; 4];

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct ChaChaState {
    a: u32x4,
    b: u32x4,
    c: u32x4,
    d: u32x4,
}

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

#[cfg(test)]
mod test {
    #[test]
    fn quater_round_test() {
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
}
