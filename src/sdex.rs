pub const BLOCK_SIZE: usize = 1024;

pub fn encrypt(data: &[u8], first_key: &[u8], second_key: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    encrypt_into(data, &mut out, first_key, second_key);
    out
}

pub fn decrypt(data: &[u8], first_key: &[u8], second_key: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    decrypt_into(data, &mut out, first_key, second_key);
    out
}

/// Encrypt `src` into `dst` without allocating per block or per packet.
///
/// The output is always exactly `src.len()` bytes. Returns the number of bytes
/// written, or `0` if `dst` is shorter than `src` (nothing is written then).
pub fn encrypt_into(src: &[u8], dst: &mut [u8], first_key: &[u8], second_key: &[u8]) -> usize {
    if dst.len() < src.len() {
        return 0;
    }
    let dst = &mut dst[..src.len()];
    encrypt_blocks_into(src, dst, first_key, second_key);
    src.len()
}

/// Decrypt `src` into `dst` without allocating per block or per packet.
///
/// The output is always exactly `src.len()` bytes. Returns the number of bytes
/// written, or `0` if `dst` is shorter than `src` (nothing is written then).
pub fn decrypt_into(src: &[u8], dst: &mut [u8], first_key: &[u8], second_key: &[u8]) -> usize {
    if dst.len() < src.len() {
        return 0;
    }
    let dst = &mut dst[..src.len()];
    decrypt_blocks_into(src, dst, first_key, second_key);
    src.len()
}

fn encrypt_blocks_into(src: &[u8], dst: &mut [u8], first_key: &[u8], second_key: &[u8]) {
    let first_key_hash = blake3::hash(first_key); // H1

    let second_key_hash = blake3::hash(second_key); // H2

    let concatenated_key_hash = blake3::hash(&[first_key, second_key].concat()); // H1 ++ H2, hash of concatenation of first and second session key

    let mut blocks = src.chunks(BLOCK_SIZE); // Split blocks into pairs, process in pairs 2k+1 2k+2

    let mut next_hash: blake3::Hash = blake3::Hash::from([0u8; 32]); // Temporarily 0 for compiler, will be hk

    let mut previous_hash = concatenated_key_hash; // will be hk-1 in main loop

    let mut offset = 0usize;

    // First pair C1 and C2
    if let Some(a) = blocks.next() {
        if let Some(b) = blocks.next() {
            let a_len = a.len();
            let b_len = b.len();
            xor_block_into(
                a,
                &mut dst[offset..offset + a_len],
                first_key_hash.as_bytes(),
                concatenated_key_hash.as_bytes(),
            ); // C1 = M1 XOR H1 XOR H1 ++ H2
            offset += a_len;
            xor_block_into(
                b,
                &mut dst[offset..offset + b_len],
                first_key_hash.as_bytes(),
                second_key_hash.as_bytes(),
            ); // C2 = M2 XOR H1 XOR H2
            offset += b_len;

            next_hash = compute_hash(&[concatenated_key_hash.as_bytes(), a, b]); // h1 = hash(H1 ++ H2;M1++M2)
                                                                                 // concatenation of M1 and M2 probably doesn't matter since we hash everything anyway
        } else {
            // Only one block: handled like the odd remainder below.
            xor_block_into(
                a,
                &mut dst[offset..offset + a.len()],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            );
            return;
        }
    }

    // Calculate the rest using remaining formulas
    while let Some(a) = blocks.next() {
        if let Some(b) = blocks.next() {
            let a_len = a.len();
            let b_len = b.len();
            xor_block_into(
                a,
                &mut dst[offset..offset + a_len],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            ); // C2k+1 = M2k+1 XOR hk XOR hk-1
            offset += a_len;
            xor_block_into(
                b,
                &mut dst[offset..offset + b_len],
                next_hash.as_bytes(),
                second_key_hash.as_bytes(),
            ); // C2k = M2k XOR H2 XOR hk
            offset += b_len;

            let combined = xor_hashes(&previous_hash, &next_hash);
            let next = compute_hash(&[&combined, a, b]); //hk+1 (next hash) = hash(hk XOR hk-1; M2k-1 ++ M2k)

            // works for h2 too, since in first iteration hk = h1, hk-1 = H1 ++ H2
            previous_hash = next_hash;
            next_hash = next;
        } else {
            // If number of blocks was odd, treat last as C2k + 1
            xor_block_into(
                a,
                &mut dst[offset..offset + a.len()],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            );
            return;
        }
    }
}

fn decrypt_blocks_into(src: &[u8], dst: &mut [u8], first_key: &[u8], second_key: &[u8]) {
    let first_key_hash = blake3::hash(first_key); // H1

    let second_key_hash = blake3::hash(second_key); // H2

    let concatenated_key_hash = blake3::hash(&[first_key, second_key].concat()); // H1 ++ H2, hash of concatenation of first and second session key

    let mut blocks = src.chunks(BLOCK_SIZE); // Split blocks into pairs, process in pairs 2k+1 2k+2

    let mut next_hash: blake3::Hash = blake3::Hash::from([0u8; 32]); // Temporarily 0 for compiler, will be hk

    let mut previous_hash = concatenated_key_hash; // will be hk-1 in main loop

    let mut offset = 0usize;

    if let Some(a) = blocks.next() {
        if let Some(b) = blocks.next() {
            let a_len = a.len();
            let b_len = b.len();
            let a_start = offset;
            xor_block_into(
                a,
                &mut dst[offset..offset + a_len],
                first_key_hash.as_bytes(),
                concatenated_key_hash.as_bytes(),
            ); // M1 = C1 XOR H1 XOR H1 ++ H2
            offset += a_len;
            let b_start = offset;
            xor_block_into(
                b,
                &mut dst[offset..offset + b_len],
                first_key_hash.as_bytes(),
                second_key_hash.as_bytes(),
            ); // M2 = C2 XOR( H1 XOR H2 )
            offset += b_len;

            next_hash = compute_hash(&[
                concatenated_key_hash.as_bytes(),
                &dst[a_start..a_start + a_len],
                &dst[b_start..b_start + b_len],
            ]);
            // h1 = hash(H1 ++ H2;M1++M2)
        } else {
            xor_block_into(
                a,
                &mut dst[offset..offset + a.len()],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            );
            return;
        }
    }

    // Calculate the rest using remaining formulas
    while let Some(a) = blocks.next() {
        if let Some(b) = blocks.next() {
            let a_len = a.len();
            let b_len = b.len();
            let a_start = offset;
            xor_block_into(
                a,
                &mut dst[offset..offset + a_len],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            ); // M2k+1 = C2k+1 XOR hk XOR hk-1
            offset += a_len;
            let b_start = offset;
            xor_block_into(
                b,
                &mut dst[offset..offset + b_len],
                next_hash.as_bytes(),
                second_key_hash.as_bytes(),
            ); // M2k+2 = C2k XOR hk XOR H2
            offset += b_len;

            let combined = xor_hashes(&previous_hash, &next_hash);
            let next = compute_hash(&[
                &combined,
                &dst[a_start..a_start + a_len],
                &dst[b_start..b_start + b_len],
            ]);
            //hk+1 (next hash) = hash(hk XOR hk-1; M2k-1 ++ M2k)

            // works for h2 too, since in first iteration hk = h1, hk-1 = H1 ++ H2
            previous_hash = next_hash;
            next_hash = next;
        } else {
            xor_block_into(
                a,
                &mut dst[offset..offset + a.len()],
                previous_hash.as_bytes(),
                next_hash.as_bytes(),
            );
            return;
        }
    }
}

fn xor_block_into(block: &[u8], out: &mut [u8], h1: &[u8; 32], h2: &[u8; 32]) {
    for (i, &b) in block.iter().enumerate() {
        out[i] = b ^ h1[i & 31] ^ h2[i & 31];
    }
}

fn compute_hash(parts: &[&[u8]]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

fn xor_hashes(h1: &blake3::Hash, h2: &blake3::Hash) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = h1.as_bytes()[i] ^ h2.as_bytes()[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect()
    }

    #[test]
    fn round_trip_every_length_up_to_4096() {
        let k1 = b"key1";
        let k2 = b"key2";
        let data = payload(4096);

        for len in 1..=4096 {
            let src = &data[..len];

            let ciphertext = encrypt(src, k1, k2);
            assert_eq!(ciphertext.len(), len, "ciphertext length for {len}");
            assert_eq!(decrypt(&ciphertext, k1, k2), src, "round trip for {len}");

            let mut ciphertext_into = vec![0u8; len];
            assert_eq!(
                encrypt_into(src, &mut ciphertext_into, k1, k2),
                len,
                "encrypt_into length for {len}"
            );
            assert_eq!(ciphertext_into, ciphertext, "encrypt_into output for {len}");

            let mut plaintext_into = vec![0u8; len];
            assert_eq!(
                decrypt_into(&ciphertext_into, &mut plaintext_into, k1, k2),
                len,
                "decrypt_into length for {len}"
            );
            assert_eq!(plaintext_into, src, "decrypt_into output for {len}");
        }
    }

    #[test]
    fn into_returns_zero_when_destination_too_small() {
        let src = payload(1400);
        let mut dst = vec![0u8; 1399];
        assert_eq!(encrypt_into(&src, &mut dst, b"key1", b"key2"), 0);
        assert_eq!(decrypt_into(&src, &mut dst, b"key1", b"key2"), 0);
    }

    /// Golden vectors from doc/sdex-algorithm.md (Appendix B). If this test
    /// fails, the wire format changed: either revert the change or update the
    /// specification in the same commit, and bump the format version.
    #[test]
    fn golden_vectors_are_stable() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let pt = |n: usize| -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() };
        let (k1, k2): (&[u8], &[u8]) = (b"key1", b"key2");

        assert_eq!(BLOCK_SIZE, 1024, "block size is part of the wire format");

        assert_eq!(hex(&encrypt(&[], k1, k2)), "");
        assert_eq!(hex(&encrypt(&pt(1), k1, k2)), "73");
        assert_eq!(hex(&encrypt(&pt(10), k1, k2)), "73f733e79be3590da99e");
        assert_eq!(
            hex(&encrypt(&pt(32), k1, k2)),
            "73f733e79be3590da99e5bb30c46630eaade74db2d69b0e2f0056e5e83c6e33f"
        );
        assert_eq!(
            hex(&encrypt(&pt(64), k1, k2)),
            "73f733e79be3590da99e5bb30c46630eaade74db2d69b0e2f0056e5e83c6e33f\
             53d713c7bbc3792d89be7b932c66432e8afe54fb0d4990c2d0254e7ea3e6c31f"
        );

        // longer inputs: compare the digest of the ciphertext
        for (len, want) in [
            (1024usize, "e824be98fef50ea70371dfcffd473fd49e7eb7ffdf8be1c05a024e09a25ca7f4"),
            (1025, "ba0518a2e322d2e3e15cbbbc07babb01defb70701316663e58164fbf164e84a5"),
            (1400, "0e3c2449ca9b937720bdaee4a8e0cc663ba74a6fa134da13a1274a1bf938bab3"),
            (2048, "0df56659a6e306666c9eb5c58d24d295a19b73612ba7c5106908f45a63c4d48f"),
            (2049, "030b9ddff38cfcd7a06a3952ec569cf0ccff530412a1afc8c0937a96b9ab7aeb"),
        ] {
            let ct = encrypt(&pt(len), k1, k2);
            assert_eq!(ct.len(), len);
            assert_eq!(blake3::hash(&ct).to_hex().as_str(), want, "len {}", len);
            assert_eq!(decrypt(&ct, k1, k2), pt(len), "round trip, len {}", len);
        }

        // the password must actually enter the ciphertext
        assert_eq!(
            hex(&encrypt(&pt(64), k1, b"other"))[..32],
            "e24e8309292cee11d1d28d7a03dc482e"[..32]
        );
    }

    #[test]
    #[ignore = "timing helper; run with --ignored --nocapture"]
    fn timing_1400_bytes() {
        let src = payload(1400);
        let mut dst = vec![0u8; 1400];
        let iterations = 100_000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            encrypt_into(&src, &mut dst, b"key1", b"key2");
        }
        let encrypt_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            decrypt_into(&src, &mut dst, b"key1", b"key2");
        }
        let decrypt_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

        println!(
            "1400 B: encrypt_into {:.0} ns, decrypt_into {:.0} ns per packet",
            encrypt_ns, decrypt_ns
        );
    }
}
