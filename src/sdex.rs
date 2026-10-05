pub fn encrypt(data: &[u8], first_key: &[u8], second_key: &[u8]) -> Vec<u8> {
    let blocks = prepare_blocks(data, 4);
    encrypt_blocks(blocks, first_key, second_key).concat()
}

pub fn decrypt(data: &[u8], first_key: &[u8], second_key: &[u8]) -> Vec<u8> {
    let blocks = prepare_blocks(data, 4);
    decrypt_blocks(blocks, first_key, second_key).concat()
}

fn encrypt_blocks(data: Vec<Vec<u8>>, first_key: &[u8], second_key: &[u8]) -> Vec<Vec<u8>> {
    let mut encrypted_data = Vec::new(); // Result

    let first_key_hash = blake3::hash(first_key); // H1

    let second_key_hash = blake3::hash(second_key); // H2

    let concatenated_key_hash = blake3::hash(&[first_key, second_key].concat()); // H1 ++ H2, hash of concatenation of first and second session key

    let mut chunks_exact = data.chunks_exact(2); // Split blocks into pairs, process in pairs 2k+1 2k+2

    let mut next_hash: blake3::Hash = blake3::Hash::from([0u8; 32]); // Temporarily 0 for compiler, will be hk

    let mut previous_hash = concatenated_key_hash; // will be hk-1 in main loop

    // First pair C1 and C2
    if let Some(first_pair) = chunks_exact.next() {
        let a = &first_pair[0]; // M1
        let b = &first_pair[1]; // M2
        encrypted_data.push(xor_block_with_two_hashes(
            a,
            first_key_hash.as_bytes(),
            concatenated_key_hash.as_bytes(),
        )); // C1 = M1 XOR H1 XOR H1 ++ H2
        encrypted_data.push(xor_block_with_two_hashes(
            b,
            first_key_hash.as_bytes(),
            second_key_hash.as_bytes(),
        )); // C2 = M2 XOR H1 XOR H2

        next_hash = compute_hash(&[concatenated_key_hash.as_bytes(), a, b]); // h1 = hash(H1 ++ H2;M1++M2)
                                                                             // concatenation of M1 and M2 probably doesn't matter since we hash everything anyway
    }

    // Calculate the rest using remaining formulas
    for pair in chunks_exact.by_ref() {
        let a = &pair[0]; // M2k+1
        let b = &pair[1]; // M2k
        encrypted_data.push(xor_block_with_two_hashes(
            a,
            previous_hash.as_bytes(),
            next_hash.as_bytes(),
        )); // C2k+1 = M2k+1 XOR hk XOR hk-1
        encrypted_data.push(xor_block_with_two_hashes(
            b,
            next_hash.as_bytes(),
            second_key_hash.as_bytes(),
        )); // C2k = M2k XOR H2 XOR hk

        let next = compute_hash(&[
            xor_hash_into_vec(&previous_hash, &next_hash).as_slice(),
            a,
            b,
        ]); //hk+1 (next hash) = hash(hk XOR hk-1; M2k-1 ++ M2k)

        // works for h2 too, since in first iteration hk = h1, hk-1 = H1 ++ H2
        previous_hash = next_hash;
        next_hash = next;
    }
    // If number of blocks was odd, treat last as C2k + 1
    let remainder = chunks_exact.remainder();
    if !remainder.is_empty() {
        let last = &remainder[0];
        encrypted_data.push(xor_block_with_two_hashes(
            last,
            previous_hash.as_bytes(),
            next_hash.as_bytes(),
        ));
    }
    return encrypted_data;
}

fn decrypt_blocks(data: Vec<Vec<u8>>, first_key: &[u8], second_key: &[u8]) -> Vec<Vec<u8>> {
    let mut decrypted_data = Vec::new();

    let first_key_hash = blake3::hash(first_key); // H1

    let second_key_hash = blake3::hash(second_key); // H2

    let concatenated_key_hash = blake3::hash(&[first_key, second_key].concat()); // H1 ++ H2, hash of concatenation of first and second session key

    let mut chunks_exact = data.chunks_exact(2); // Split blocks into pairs, process in pairs 2k+1 2k+2

    let mut next_hash: blake3::Hash = blake3::Hash::from([0u8; 32]); // Temporarily 0 for compiler, will be hk

    let mut previous_hash = concatenated_key_hash; // will be hk-1 in main loop

    if let Some(first_pair) = chunks_exact.next() {
        let a = &first_pair[0]; //C1
        let b = &first_pair[1]; //C2
        let first_deciphered = xor_block_with_two_hashes(
            a,
            first_key_hash.as_bytes(),
            concatenated_key_hash.as_bytes(),
        ); // M1 = C1 XOR H1 XOR H1 ++ H2
        let second_deciphered = xor_block_with_combined_hashes(
            b,
            first_key_hash.as_bytes(),
            second_key_hash.as_bytes(),
        ); // M2 = C2 XOR( H1 XOR H2 )

        next_hash = compute_hash(&[
            concatenated_key_hash.as_bytes(),
            &first_deciphered,
            &second_deciphered,
        ]);
        // h1 = hash(H1 ++ H2;M1++M2)

        decrypted_data.push(first_deciphered);
        decrypted_data.push(second_deciphered);
    }

    // Calculate the rest using remaining formulas
    for pair in chunks_exact.by_ref() {
        let a = &pair[0]; // C2k+1
        let b = &pair[1]; // C2k
        let first_deciphered =
            xor_block_with_two_hashes(a, previous_hash.as_bytes(), next_hash.as_bytes()); // M2k+1 = C2k+1 XOR hk XOR hk-1
        let second_deciphered =
            xor_block_with_two_hashes(b, next_hash.as_bytes(), second_key_hash.as_bytes()); // M2k+2 = C2k XOR hk XOR H2

        let next = compute_hash(&[
            xor_hash_into_vec(&previous_hash, &next_hash).as_slice(),
            &first_deciphered,
            &second_deciphered,
        ]);
        //hk+1 (next hash) = hash(hk XOR hk-1; M2k-1 ++ M2k)

        // works for h2 too, since in first iteration hk = h1, hk-1 = H1 ++ H2
        previous_hash = next_hash;
        next_hash = next;

        decrypted_data.push(first_deciphered);
        decrypted_data.push(second_deciphered);
    }

    let remainder = chunks_exact.remainder();
    if !remainder.is_empty() {
        let last = &remainder[0];
        decrypted_data.push(xor_block_with_two_hashes(
            last,
            previous_hash.as_bytes(),
            next_hash.as_bytes(),
        ));
    }

    return decrypted_data;
}

fn xor_block_with_two_hashes(block: &[u8], h1: &[u8], h2: &[u8]) -> Vec<u8> {
    block
        .iter()
        .zip(h1.iter().cycle().zip(h2.iter().cycle()))
        .map(|(&b, (k1, k2))| b ^ k1 ^ k2)
        .collect()
}

fn compute_hash(parts: &[&[u8]]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

fn xor_hash_into_vec(h1: &blake3::Hash, h2: &blake3::Hash) -> Vec<u8> {
    h1.as_bytes()
        .iter()
        .zip(h2.as_bytes().iter())
        .map(|(a, b)| a ^ b)
        .collect()
}
fn xor_block_with_combined_hashes(block: &[u8], h1: &[u8], h2: &[u8]) -> Vec<u8> {
    block
        .iter()
        .zip(h1.iter().cycle().zip(h2.iter().cycle()))
        .map(|(&b, (k1, k2))| b ^ (k1 ^ k2))
        .collect()
}

fn prepare_blocks(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    if block_size == 0 {
        panic!("Block size must be greater than 0");
    }

    data.chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}
