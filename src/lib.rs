extern crate byteorder;


use byteorder::{LittleEndian, WriteBytesExt};


#[cfg(test)]
mod tests;


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
    for _ in 0..((data.len() as f64 / CHACHA20_BLOCK_SIZE as f64).ceil() as usize) {
        chacha20_block(state, &mut keystream);
        state[12] += 1; // Update counter
    }

    for (dst_byte, key_byte) in data.iter_mut().zip(keystream.iter()) {
        *dst_byte ^= key_byte;
    }
}
