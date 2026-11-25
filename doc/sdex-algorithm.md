# SDEx — normative algorithm specification

This file is the contract for `src/sdex.rs`. Refactoring must keep the observed
behaviour byte-identical; if the algorithm itself changes on purpose, change this
file in the same commit and bump the wire-format version in §8.

Status: verified against `src/sdex.rs` at commit `2711d02` (`BLOCK_SIZE = 1024`).
The reference implementation in Appendix A was written from this text alone and
reproduces the golden vectors in Appendix B exactly.

## 1. Sources and precedence

- Publication: A. Hałbaz, *Enhanced SDEx encryption method* — Figs 1–2 and
  equations (1)–(11) referenced below.
- Implementation: `src/sdex.rs`.
- Where they disagree, §7 records the decision the implementation actually makes.
  The code decides; the paper explains.

## 2. Notation

Publication symbols, reproduced:

    M1 … Mp      plaintext blocks          C1 … Cp   ciphertext blocks
    IV           initialisation vector (session key)
    h0           initialisation hash (predefined value for the hash function)
    h1 … hp      successive hash-function iterations
    Hy           hash of the initialisation vector (session key)
    Hxy          hash of the user password
    H_Y⊕IV⊕0     hash of the concatenation of IV and h0
    ⊕            XOR                        ++        concatenation of two strings
    hash( )      the hash function

Names in the implementation:

| paper | implementation | value |
|---|---|---|
| `Hy` | `first_key_hash` (`H1`) | `hash(first_key)` |
| `Hxy` | `second_key_hash` (`H2`) | `hash(second_key)` |
| `H_Y⊕IV⊕0` | `concatenated_key_hash` (`H3`) | `hash(first_key ++ second_key)` — see §7.1 |
| `h1 … hp` | `next_hash` / `previous_hash` | chain state, 32 bytes each |
| `hash( )` | `blake3::hash` | BLAKE3-256, 32-byte digest |
| a block `Mi` | `src.chunks(BLOCK_SIZE)` | `BLOCK_SIZE = 1024` bytes, last block may be shorter |
| `first_key` | `--key1` | IV / session key |
| `second_key` | `--key2` | user password |

Keys are used as raw bytes of the CLI strings (`--key1` default `key1`,
`--key2` default `key2`).

## 3. Equations as published

With `h0 := H_Y⊕IV⊕0` and `h1 := Hy`, equations (1)–(2) are the `k = 1` case of
(3)–(4). Encryption:

    (1)  C1        = M1      ⊕ Hy  ⊕ H_Y⊕IV⊕0
    (2)  C2        = M2      ⊕ Hy  ⊕ Hxy
    (3)  C2k-1     = M2k-1   ⊕ hk  ⊕ hk-1              k ≥ 1
    (4)  C2k       = M2k     ⊕ Hxy ⊕ hk                k ≥ 1
    (5)  h1        = hash(H_Y⊕IV⊕0 ⊕ M1 ⊕ M2)
    (6)  h2        = hash((h1 ⊕ h1) ⊕ M3 ⊕ M4)         see §7.3
    (7)  hk        = hash((hk-1 ⊕ hk-2) ⊕ M2k-1 ⊕ M2k) k ≥ 3

Decryption:

    (8)  M1        = C1      ⊕ Hy  ⊕ H_Y⊕IV⊕0
    (9)  M2        = C2      ⊕ (Hy ⊕ Hxy)
    (10) M2k-1     = C2k-1   ⊕ hk  ⊕ hk-1              k ≥ 1
    (11) M2k       = C2k     ⊕ Hxy ⊕ hk                k ≥ 1

## 4. Normative algorithm (pseudocode)

`hash(a, b, c)` means one hash over the concatenation `a ++ b ++ c`
(`hasher.update` per part, single `finalize`). `xor_block` extends a 32-byte hash
over an arbitrary block length by cycling it (§5).

```
xor_block(block, h1, h2):
    out[i] = block[i] XOR h1[i mod 32] XOR h2[i mod 32]     for every i

xor_hashes(hA, hB):
    out[i] = hA[i] XOR hB[i]                                 for i in 0..31

keys():
    Hy  = hash(first_key)
    Hxy = hash(second_key)
    H3  = hash(first_key ++ second_key)

blocks(src):
    src split into BLOCK_SIZE-byte chunks; last chunk may be shorter
```

### 4.1 encrypt(plaintext) -> ciphertext

```
if plaintext is empty: return empty                    (no blocks at all)

B  = blocks(plaintext)
out = buffer of len(plaintext)                          (same length, no padding)
prev = H3 ; next = 0^32                                 (initial chain state)

if len(B) == 1:                                         (single-block input)
    out[B0] = xor_block(B0, prev, next)                 (i.e. B0 ⊕ H3 ⊕ 0^32)
    return out

# first pair
out[B0] = xor_block(B0, Hy, H3)
out[B1] = xor_block(B1, Hy, Hxy)
next    = hash(H3, B0, B1)                              # eq (5)

# remaining blocks, two at a time
i = 2
while i < len(B):
    if i is the last block (no partner):                 # odd tail
        out[Bi] = xor_block(Bi, prev, next)              # eq (3)
        break
    a = B[i] ; b = B[i+1]
    out[a] = xor_block(a, prev, next)                    # eq (3)
    out[b] = xor_block(b, next, Hxy)                     # eq (4)
    new  = hash(xor_hashes(prev, next), a, b)            # eq (7)
    prev = next ; next = new
    i = i + 2
return out
```

### 4.2 decrypt(ciphertext) -> plaintext

Identical structure; the only difference is that the chain hash for the next pair
is computed from the **recovered plaintext**, not from the input.

```
if ciphertext is empty: return empty

B  = blocks(ciphertext)
out = buffer of len(ciphertext)
prev = H3 ; next = 0^32

if len(B) == 1:
    out[B0] = xor_block(B0, prev, next)
    return out

# first pair
out[B0] = xor_block(B0, Hy, H3)
out[B1] = xor_block(B1, Hy, Hxy)
next    = hash(H3, out[B0], out[B1])                     # eq (5), on plaintext

i = 2
while i < len(B):
    if i is the last block (no partner):
        out[Bi] = xor_block(Bi, prev, next)              # eq (10)
        break
    a = B[i] ; b = B[i+1]
    ma = xor_block(a, prev, next)                        # eq (10)
    mb = xor_block(b, next, Hxy)                         # eq (11)
    out[a] = ma ; out[b] = mb
    new  = hash(xor_hashes(prev, next), ma, mb)          # eq (7), on plaintext
    prev = next ; next = new
    i = i + 2
return out
```

### 4.3 Chain state, restated

The state is a pair `(prev, next)` that starts as `(H3, 0^32)` and rolls forward
one step per processed pair:

    (prev, next) <- (next, hash(prev ⊕ next, M2k-1, M2k))

Equations (5) and (7) are both instances of that one rule: the first pair seeds
`next` with `hash(H3, M1, M2)` while `prev` is still `H3`, which is the same as
`hash(prev ⊕ next, M1, M2)` with `next = 0^32`.

## 5. Byte-level rules that are part of the format

1. The hash digest is 32 bytes; blocks are `BLOCK_SIZE` bytes. A hash is applied
   over a block by **cycling** it: byte `i` uses hash byte `i mod 32`. This is an
   implementation rule, not something the equations state (§7.5).
2. Blocks are produced by chunking the input with `BLOCK_SIZE`; the final block
   may be shorter, and no padding is added.
3. Output length always equals input length. There is no length field, no nonce,
   no authentication tag.
4. The chain state is reset on every call: the algorithm is per-packet, not a
   stream across packets.
5. Block pairing is fixed: `(B0,B1)`, then `(B2,B3)`, `(B4,B5)`, … The odd tail
   block, if any, is the last one.

## 6. Invariants a refactor must preserve

- `decrypt(encrypt(M, k1, k2), k1, k2) == M` for every length, including 0 bytes,
  1 byte, exactly `BLOCK_SIZE`, `BLOCK_SIZE + 1`, an exact number of pairs, and a
  pair plus one tail block.
- `len(ciphertext) == len(plaintext)`.
- Identical `(plaintext, k1, k2)` produce identical ciphertext — the algorithm is
  deterministic and carries no randomness.
- The Appendix B vectors are unchanged.
- Only `k2` changing must change the ciphertext (it enters `Hxy` and `H3`).

Existing tests: `src/sdex.rs::tests::round_trip_every_length_up_to_4096` and
`into_returns_zero_when_destination_too_small`.

## 7. Decisions where the paper and the code differ — do not change silently

**7.1 `H_Y⊕IV⊕0`.** The paper defines it as the hash of the concatenation of IV
and `h0`. The implementation computes `H3 = hash(first_key ++ second_key)` — i.e.
the session key concatenated with the *password*, not with a predefined `h0`. `h0`
is never used as a value anywhere in the code. Document the thesis text against
this, or change both together.

**7.2 Concatenation inside `hash( )`.** Where the paper prints `⊕` between parts
inside a `hash(...)` call, the implementation *concatenates* them
(`hasher.update` per part). XOR between a 32-byte hash and a variable-length block
is not defined, so concatenation is the only workable reading. The one place that
really is XOR is the 32-byte chain combination `h_{k-1} ⊕ h_k`, which is XORed
first and then concatenated with the two message blocks.

**7.3 `h2`.** The paper prints `hash((h1 ⊕ h1) ⊕ M3 ⊕ M4)`. With `h1 ⊕ h1 = 0`
that cannot be right; the implementation computes
`hash((h1 ⊕ h0) ++ M3 ++ M4)`, which is the general recurrence (7) with
`k = 2` and `h0 = H3`. Treat the printed `h1 ⊕ h1` as a typographical error.

**7.4 Block size.** The paper leaves blocks abstract. `BLOCK_SIZE` is a real
format constant: it was 4 bytes, it is now 1024. Changing it changes every
ciphertext and breaks any peer running the other value.

**7.5 Keystream cycling (§5.1).** Blocks are longer than a digest, so each hash
is repeated across the block. This is load-bearing and invisible in the equations.

## 8. Wire format and compatibility

Any change to the following invalidates every existing ciphertext and requires
rebuilding both peers together:

- `BLOCK_SIZE`
- the hash function or its output length
- how `Hy`, `Hxy`, `H3` are derived from the keys
- block ordering / pairing, or the initial chain state `(H3, 0^32)`
- where hashes are concatenated vs XORed (§7.2)

`BLOCK_SIZE` went 4 → 1024 in commit `bb2d99a`; old and new builds cannot talk to
each other. If the algorithm is expected to keep evolving, add a version byte or a
`pub const FORMAT_VERSION` and refuse mismatches, so this is explicit rather than
discovered in the field.

## 9. Known properties (not defects to "fix" during a refactor)

- **No per-packet nonce.** The first two blocks are `M ⊕ Hy ⊕ H3` and
  `M ⊕ Hy ⊕ Hxy`, keystreams that depend only on the keys; `h1` then depends on
  the first two plaintext blocks. Two packets whose first two blocks are equal get
  an identical keystream for the whole packet, and XOR of two ciphertexts reveals
  XOR of the plaintexts for those blocks. Fixing this means changing the format
  (§8), not the refactor.
- **No authentication.** There is no tag; a modified ciphertext decrypts to a
  modified plaintext, and the chain propagates the corruption to later blocks.

## Appendix A — reference implementation (Python, verified)

Written from this document; reproduces every Appendix B vector against
`src/sdex.rs`. Use it to settle disputes.

```python
import blake3
BLOCK, ZERO32 = 1024, bytes(32)

def H(*parts):
    h = blake3.blake3()
    for p in parts: h.update(p)
    return h.digest(length=32)

def xor_block(block, h1, h2):
    return bytes(b ^ h1[i & 31] ^ h2[i & 31] for i, b in enumerate(block))

def xor_hashes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(pt, k1, k2):
    hy, hxy, h3 = H(k1), H(k2), H(k1 + k2)
    B = [pt[i:i+BLOCK] for i in range(0, len(pt), BLOCK)]
    out = bytearray(len(pt))
    if not B: return bytes(out)
    prev, nxt, off = h3, ZERO32, 0
    if len(B) == 1:
        out[0:len(B[0])] = xor_block(B[0], prev, nxt); return bytes(out)
    out[0:len(B[0])] = xor_block(B[0], hy, h3); off += len(B[0])
    out[off:off+len(B[1])] = xor_block(B[1], hy, hxy); off += len(B[1])
    nxt = H(h3, B[0], B[1]); rest, i = B[2:], 0
    while i < len(rest):
        if i + 1 == len(rest):
            a = rest[i]; out[off:off+len(a)] = xor_block(a, prev, nxt); break
        a, b = rest[i], rest[i+1]
        out[off:off+len(a)] = xor_block(a, prev, nxt); off += len(a)
        out[off:off+len(b)] = xor_block(b, nxt, hxy);  off += len(b)
        prev, nxt = nxt, H(xor_hashes(prev, nxt), a, b); i += 2
    return bytes(out)
```

`decrypt` is the same with `ma`/`mb` recovered first and the chain hash taken over
the recovered plaintext blocks (as in §4.2).

## Appendix B — golden vectors

Plaintext pattern: `byte i = i mod 251`. Keys: `k1 = "key1"`, `k2 = "key2"`.

| len | ciphertext |
|---|---|
| 1 | `73` |
| 10 | `73f733e79be3590da99e` |
| 32 | `73f733e79be3590da99e5bb30c46630eaade74db2d69b0e2f0056e5e83c6e33f` |
| 64 | `73f733e79be3590da99e5bb30c46630eaade74db2d69b0e2f0056e5e83c6e33f53d713c7bbc3792d89be7b932c66432e8afe54fb0d4990c2d0254e7ea3e6c31f` |

Longer inputs, compared by digest of the ciphertext (BLAKE3-256 hex):

| len | BLAKE3-256(ciphertext) |
|---|---|
| 1024 | `e824be98fef50ea70371dfcffd473fd49e7eb7ffdf8be1c05a024e09a25ca7f4` |
| 1025 | `ba0518a2e322d2e3e15cbbbc07babb01defb70701316663e58164fbf164e84a5` |
| 1400 | `0e3c2449ca9b937720bdaee4a8e0cc663ba74a6fa134da13a1274a1bf938bab3` |
| 2048 | `0df56659a6e306666c9eb5c58d24d295a19b73612ba7c5106908f45a63c4d48f` |
| 2049 | `030b9ddff38cfcd7a06a3952ec569cf0ccff530412a1afc8c0937a96b9ab7aeb` |

Key sensitivity check, 64-byte input, first 16 bytes of ciphertext:

    k2 = "key2"  -> 73f733e79be3590da99e5bb30c46630e
    k2 = "other" -> e24e8309292cee11d1d28d7a03dc482e

Empty input produces empty output.

Provenance: vectors generated by compiling `src/sdex.rs` at `2711d02` into a
standalone binary, then reproduced independently by Appendix A.
