# Adding an algorithm

The point of the trait layout is that a new algorithm should only have to
supply what is genuinely specific to it. A block cipher implements three
methods and gets all five modes for free — and AES-GCM too, if its blocks
are 128 bits, since GHASH is defined in GF(2^128) and has no counterpart
for a 64 bit cipher.

## A new block cipher

Create `src/block_ciphers/<name>.rs` and implement the three required methods:

```rust,ignore
use crate::block_ciphers::BlockCipher;

pub struct MyCipher { /* round keys, tables */ }

impl MyCipher {
    pub fn new(key: Vec<u8>) -> Result<MyCipher, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. Must be 16.", key.len()));
        }
        Ok(MyCipher { /* ... */ })
    }
}

impl BlockCipher for MyCipher {
    fn blocksize(&self) -> usize { 16 }
    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) { /* ... */ }
    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) { /* ... */ }
}
```

Two rules the mode code relies on: `block_encrypt` and `block_decrypt` must
**append exactly one block** to `result` (the modes check this and error if
not), and the constructor must reject bad key lengths rather than panicking
later.

That is the whole obligation. ECB, CBC, CFB, OFB and CTR, one-shot and
streaming, in place and appending, all work now.

### If the counter is unusual

CTR's only cipher-specific part is how the counter block is built and
advanced. The default is "nonce, zero padded, big-endian increment". A cipher
that does something else overrides two hooks and nothing more — GOST is the
worked example, in `src/block_ciphers/gost.rs`:

```rust,ignore
impl BlockCipher for MyCipher {
    // ... the three required methods ...

    fn ctr_init(&mut self, iv: &[u8], counter: &mut Vec<u8>) -> Result<(), String> {
        counter.clear();
        self.block_encrypt(iv, counter);   // whatever your spec says C_0 is
        self.ctr_next(counter);
        Ok(())
    }

    fn ctr_next(&self, counter: &mut [u8]) {
        // advance in place, however your spec defines it
    }
}
```

A third hook, `ctr_fill`, writes a whole batch of counter blocks; its
default is the loop over `ctr_next`, so a cipher with its own counter
needs nothing more. A *wrapper* that holds a cipher - `AnyBlockCipher` is
the one here - forwards it, or CTR calls `ctr_next` through the wrapper
once per block, which is correct and was most of CTR's time with a
hardware AES.

### If several blocks can go at once

ECB, CTR, GCM, XTS, CBC decryption and CCM's keystream hand the cipher
several independent blocks through `encrypt_blocks` and `decrypt_blocks`,
which default to calling `block_encrypt` once per block. A cipher that can
do better on many blocks than on one overrides them. AES does, with a
bitsliced implementation that runs sixteen blocks side by side and makes
no table lookup; its `block_encrypt` stays the table one, because the
chained modes only ever have one block to give it. Both methods work in
place on a whole number of blocks and return an error for anything else.
Correctness is easy to pin: the two routes are independent
implementations of the same function and must agree on every block, which
is `test_the_routes_agree` in `src/block_ciphers/aes.rs`.

### If one pass beats three

Three more hooks have defaults that do the generic thing and exist for a
cipher with dedicated instructions; a new cipher needs none of them.

- `encrypt_block_in_place` and `decrypt_block_in_place`: one block, no
  output `Vec`. CBC calls them once per block, so their overhead is per
  block too. The default goes through `block_encrypt` with a scratch
  buffer the caller keeps.
- `ctr_xor`: a counter-mode keystream XORed straight into the data, CTR's
  whole-block counter or GCM's 32-bit one. The default returns `false`
  and the mode builds counter blocks with `ctr_fill`, encrypts them with
  `encrypt_blocks` and XORs them in. A cipher that overrides `ctr_next`
  must not override this, which knows only the two standard counters.
- `xts_blocks`: XTS's whole blocks, tweak and all. The default returns
  `false` and `xts.rs` masks, encrypts and masks again.

AES overrides all of them with AES-NI, where the three-pass versions spent
more time moving blocks through memory than encrypting them; without the
feature it overrides only the one-block pair, with its table route. A
*wrapper* must forward every one - `AnyBlockCipher` does, and
`test_the_wrapper_forwards_the_one_block_path` in `tests/test_api.rs` and
the agreement tests in `aes.rs` and `xts.rs` (`test_one_pass_counter_mode_
agrees_with_three_passes`, `test_the_one_pass_path_agrees_with_the_three_
pass_one`) are what notice when it does not.

### Registering it

Three edits, all mechanical:

1. `src/block_ciphers/mod.rs` — add `pub mod <name>;`
2. `src/api.rs` — add a variant to `AnyBlockCipher`, an arm to the
   `dispatch!` macro, a match arm in `AnyBlockCipher::new`, a case in
   `name()`, and the string in the `BLOCK_CIPHERS` constant
3. `docs/status.md` — tick the algorithm in the Block ciphers table

Step 2 is what makes it reachable from Python: the bindings go through
`api.rs`, so a cipher registered there needs no changes in `src/python.rs`.
`tests/test_api.rs` asserts every name in `BLOCK_CIPHERS` actually
constructs, so forgetting part of step 2 fails the suite.

## A new hash

Implement `HashFunction` in `src/hash_functions/<name>.rs`:

```rust,ignore
use crate::hash_functions::HashFunction;

impl HashFunction for MyHash {
    fn name(&self) -> String { "MyHash".to_string() }
    fn digest_len(&self) -> usize { 32 }
    fn update(&mut self, input: &[u8]) { /* buffer and compress */ }
    fn digest(&mut self) -> Vec<u8> { /* finalize a copy, do not consume */ }
}
```

`digest()` must be repeatable and must not end the hash — callers expect to
call it twice, and to keep calling `update` afterwards. Finalize into a local
copy of the state rather than mutating `self`.

Derive `Clone` on the struct so `AnyHash` stays cloneable; that is what backs
`copy()` in Python.

Register it in `src/api.rs` (`AnyHash` variant, `AnyHash::new` arm,
`block_size()` if it is not 64 bytes, and the `HASHES` constant), add it to
`hash_functions::hash_all`, and tick its row in `docs/status.md`.

### Why a hash cannot be registered at run time

`register_oid` can supply a **curve** (`curve_parameters=`) and a **GOST
S-box** (`gost_sbox=`), because both are parameter sets: seven numbers and
eight permutations, distributed separately from any code and checkable as
data. A hash is not like that. It is a compression function, a message
schedule, a padding rule and an endianness convention — there is no data a
caller can hand across the boundary that constitutes one, so `hash=` will
only ever move a *name* onto a hash this library already implements.

That question came up and was deferred until there is a concrete example
to aim at. The options, for whoever meets one:

1. **A parameterised member of a family already here** — the honest cheap
   case, and a registration in the same sense as an S-box: the algorithm
   exists and the parameter names a member of it. SHA-512/t for an
   arbitrary `t` (FIPS 180-4 defines the IV derivation, so it really is
   parameterised), SHAKE at a chosen output length, BLAKE2 with
   key/salt/personalisation. In practice this covers most of what "a
   digest from a standard nobody vendored" turns out to be.
2. **A Python callback.** Possible and argued against: it puts interpreted
   code inside signature verification and certificate parsing, where a
   wrong digest is a forged signature and neither the caller nor this
   library can test it — which gives up the property the rest of the
   library is built on, that every fault here is ours. It also means
   holding the GIL inside the `py.allow_threads` regions that currently
   release it.
3. **Implementing it in Rust**, as above. For anything real that is a day
   plus vectors, and it is what this library is for.

## A new stream cipher

Implement `StreamCipher::crypt`, which must carry keystream position across
calls — feeding the same data in two pieces has to give the same output as
one call. That is exactly the bug that hid in ChaCha for a while, so test it
explicitly. Register in `AnyStreamCipher` and `STREAM_CIPHERS`.

## A new mode

Modes live in `src/block_ciphers/modes.rs` and come in two halves: a
`<Name>State` that owns the mode's state and takes the cipher as an argument,
and a borrowing wrapper that pairs the two for Rust callers. The split is
what lets the Python bindings own a cipher and drive the state directly.

Then: add the one-shot method to the `BlockCipher` trait, a `Driver` variant
and `Mode` variant in `src/api.rs`, the name in `MODES`, and the row in `docs/status.md`.

## Testing checklist

A new algorithm is not done until all of these exist. This is the bar the
current code is held to, and the last two are where the real bugs were found.

- [ ] **Known answer tests** in `tests/test_<name>.rs`, from the spec or RFC.
      Cite the source in a comment.
- [ ] **A range of lengths**, not just the vector lengths. Every padding and
      block boundary: for a 64 byte block hash that means lengths around 55,
      56, 63, 64, and 119, 120, 127, 128.
- [ ] **Streaming equals one shot** — feed the same input in irregular pieces
      and assert byte equality with a single call.
- [ ] **Round trip** — decrypt(encrypt(x)) == x across those same lengths.
- [ ] **Error cases** — wrong key length, wrong IV length, ragged input.
      Assert they return `Err` rather than panicking or producing short output.
- [ ] **Differential against another implementation**, over hundreds of
      inputs. Extend `tools/src/bin/diff_dump.rs` and compare against OpenSSL via
      python-cryptography, or `hashlib` for hashes. See
      [building.md](building.md#differential-testing).

## Where test vectors come from

**Never type a test vector.** A vector typed from memory, or copied by
eye from a PDF, is wrong often enough to matter, and a wrong vector that
the implementation agrees with is worse than none: the private-key
fixtures that were typed parsed, agreed with each other, and were
refused by `openssl pkey`; a BLAKE2s vector was off by one nibble; and
Salsa20's quarter-round had two arguments swapped in all eight call
sites, which every round trip and streaming test accepted.

So, in order of preference:

1. **Parse the document at test time.** `rfcs/` holds the vendored RFCs
   and other specifications, unmodified, and tests `include_str!` them
   and read the vectors out (`src/ec/eddsa.rs` reads RFC 8032 section 7,
   `src/block_ciphers/keywrap.rs` RFC 3394 section 4). Nothing is
   transcribed, so nothing is transcribed wrongly.
2. **Assert the count.** A parser that finds nothing turns every vector
   test into an empty loop that passes, so each one asserts how many
   vectors it expects before using them. Documents print the same label
   several ways - RFC 3394 writes `KEK:  0001`, `KEK:0001`,
   `Ciphertext  031D` and `KEK:` with the value on the next line - and
   each spelling a parser misses costs vectors silently.
3. **Where no document has a vector, generate one** with a reference
   implementation (hashlib, python-cryptography, `openssl`, or a witness
   built from source), and commit the script that did it -
   `scripts/make_xts_vectors.py` is the model - so the claim can be
   re-run.
4. **A published vector can be wrong.** When exactly one row fails and
   every shorter one passes, check the errata and a second
   implementation before the code (RFC 4418's longest UMAC row is
   erratum 3507). Apply a correction to the one line it names, asserting
   that line is still there, never by editing the vendored document.

A vector that came from the implementation being tested is not a test.
The same applies to any text a check parses - an error message, a log
line - which comes from the code that produces it, not from memory.

## Documentation checklist

Documentation that lags the code is worse than none, so treat these as part
of the change, not follow-up work:

- [ ] `docs/status.md` row ticked — Implemented, and Tested only if it
      has been checked against an independent implementation
- [ ] `docs/rust.md` — mention it where the family is listed; add a snippet
      if it is used differently from its siblings
- [ ] `docs/python.md` — same, if it is reachable from Python
- [ ] `python/allcrypt.pyi` — updated if the Python surface changed
- [ ] `python scripts/check_docs.py` passes — every snippet in the docs is
      compiled and run, so a changed signature breaks the check rather than
      quietly making the docs wrong
- [ ] If a bug was fixed, the regression test says in a comment what was
      wrong and why the old tests missed it
