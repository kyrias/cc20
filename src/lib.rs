extern crate byteorder;

use byteorder::{LittleEndian, WriteBytesExt};


const CHACHA20_BLOCK_SIZE: usize = 64;

fn quarterround(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] = (state[d]^state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] = (state[b]^state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] = (state[d]^state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] = (state[b]^state[c]).rotate_left(7);
}

fn chacha20_block(state: [u32; 16], keystream: &mut Vec<u8>) {
    let mut working_state: [u32; 16] = state;

    for _ in 1..=10 {
        // Column round
        quarterround(&mut working_state, 0, 4, 8,12);
        quarterround(&mut working_state, 1, 5, 9,13);
        quarterround(&mut working_state, 2, 6,10,14);
        quarterround(&mut working_state, 3, 7,11,15);

        // Diagonal round
        quarterround(&mut working_state, 0, 5,10,15);
        quarterround(&mut working_state, 1, 6,11,12);
        quarterround(&mut working_state, 2, 7, 8,13);
        quarterround(&mut working_state, 3, 4, 9,14);
    }

    for (idx, value) in working_state.iter().enumerate() {
        let new_value: u32 = state[idx].wrapping_add(*value);
        keystream.write_u32::<LittleEndian>(new_value).unwrap();
    }

}

pub fn chacha20(key: [u32; 8], counter: u32, nonce: [u32; 3], data: &mut Vec<u8>) {
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];

    let mut keystream = Vec::new();
    for block in 0..((data.len() as f64 / CHACHA20_BLOCK_SIZE as f64).ceil() as usize) {
        chacha20_block(state, &mut keystream);
        state[12] += 1; // Update counter
    }

    for (dst_byte, key_byte) in data.iter_mut().zip(keystream.iter()) {
        *dst_byte ^= key_byte;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_vector_quarterround() {
        let mut state = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
        ];
        super::quarterround(&mut state, 2, 7, 8, 13);
        let expected = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
            0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
        ];
        assert_eq!(state, expected);
    }

    #[test]
    fn test_vector_chacha20() {
        use super::CHACHA20_BLOCK_SIZE;
        use std::io::Cursor;
        use byteorder::{LittleEndian, ReadBytesExt};

        struct test_vector {
            key: [u8; 32],
            nonce: [u8; 12],
            counter: u32,
            data: Vec<u8>,
            expected: Vec<u8>,
        }

        let tests = [
            test_vector {
                key: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
                nonce: [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00],
                counter: 1,
                data: [0; 64].to_vec(),
                expected: vec![0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
                               0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
                               0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
                               0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
                               0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
                               0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
                               0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                               0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e],
            },

            test_vector {
                key: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
                nonce: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00],
                counter: 1,
                data: b"Ladies and Gentlemen of the class of '99: If I could offer \
                        you only one tip for the future, sunscreen would be it.".to_vec(),
                expected: vec![0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
                               0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
                               0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
                               0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
                               0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
                               0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
                               0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
                               0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
                               0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
                               0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
                               0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
                               0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
                               0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
                               0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
                               0x87, 0x4d],
            }
        ];

        for test in tests.iter() {
            let mut raw_key = Cursor::new(test.key);
            let mut key: [u32; 8] = [0; 8];
            for idx in 0..key.len() {
                key[idx] = raw_key.read_u32::<LittleEndian>().unwrap();
            }


            let mut raw_nonce = Cursor::new(test.nonce);
            let mut nonce: [u32; 3] = [0; 3];
            for idx in 0..nonce.len() {
                nonce[idx] = raw_nonce.read_u32::<LittleEndian>().unwrap();
            }

            let mut actual = test.data.clone();

            // Encrypt data, and check that encrypted_data == expected
            super::chacha20(key, test.counter, nonce, &mut actual);
            assert_eq!(test.expected.len(), actual.len());
            for (expected, actual) in test.expected.chunks(CHACHA20_BLOCK_SIZE).zip(actual.chunks(CHACHA20_BLOCK_SIZE)) {
                assert_eq!(expected, actual);
            }

            // Decrypt encrypted data, and check that decrypted_data == data
            super::chacha20(key, test.counter, nonce, &mut actual);
            assert_eq!(test.data.len(), actual.len());
            for (data, actual) in test.data.chunks(CHACHA20_BLOCK_SIZE).zip(actual.chunks(CHACHA20_BLOCK_SIZE)) {
                assert_eq!(data, actual);
            }
        }
    }
}
