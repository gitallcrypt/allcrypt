use crate::{block_ciphers::BlockCipher, Mac};
use std::collections::HashMap;
use lazy_static::lazy_static;


#[derive(Clone)]
pub struct GostCrypto{
    _key: Vec<u8>,
    sbox: Vec<Vec<u8>>,
    key32: [u32; 8],
    /// The precomputed substitution-and-rotation table, **boxed**.
    ///
    /// Four kilobytes, and held by value it was four kilobytes in
    /// everything that could hold a GOST cipher: `AnyBlockCipher` was
    /// 4224 bytes so an 80 byte AES paid for it, and `Protection` was
    /// 8592 because `CntImit` holds two of these - every TLS
    /// connection, whatever suite it negotiated. On the heap the cost
    /// is one allocation per instance, which the record layer already
    /// pays for the table's contents.
    s_table: Box<[[u32; 256]; 4]>,
    mac_state: Vec<u8>,
    mac_data_unprocessed: Vec<u8>,
    /// Whole blocks the MAC has taken in, for the two-block minimum
    /// in `digest`. Counted rather than derived, because `update` is
    /// the only place that knows and the buffer is emptied as it goes.
    mac_blocks_done: usize,
 }

lazy_static! {
static ref SBOXES: HashMap<String, Vec<Vec<u8>>> = HashMap::from([
    ("id-Gost28147-89-TestParamSet".to_string(),
    vec![vec![4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6],
        vec![12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5],
        vec![13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11],
        vec![14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8],
        vec![3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4],
        vec![8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4],
        vec![9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13],
        vec![12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8]]),
   ("id-Gost28147-89-CryptoPro-A-ParamSet".to_string(),
   vec![vec![9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5],
        vec![3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1],
        vec![14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9],
        vec![14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6],
        vec![11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6],
        vec![3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6],
        vec![1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14],
        vec![11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4]]),

    ("id-Gost28147-89-CryptoPro-B-ParamSet".to_string(),
    vec![vec![8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15],
        vec![0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14],
        vec![14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4],
        vec![7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8],
        vec![2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3],
        vec![8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5],
        vec![5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14],
        vec![0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12]]), 
    ("id-Gost28147-89-CryptoPro-C-ParamSet".to_string(),
    vec![vec![1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3],
        vec![0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3],
        vec![8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11],
        vec![3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4],
        vec![8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7],
        vec![12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13],
        vec![10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7],
        vec![7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8]]),
    ("id-Gost28147-89-CryptoPro-D-ParamSet".to_string(),
    vec![vec![15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3],
        vec![11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1],
        vec![1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2],
        vec![1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8],
        vec![0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1],
        vec![8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6],
        vec![3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7],
        vec![1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14]]),
    ("id-tc26-gost-28147-param-Z".to_string(),
    vec![vec![12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
         vec![6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
         vec![11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
         vec![12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
         vec![7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
         vec![5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
         vec![8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
         vec![1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]]),
    ("id-GostR3411-94-TestParamSet".to_string(),
    vec![vec![4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        vec![14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        vec![5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        vec![7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        vec![6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        vec![4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        vec![13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        vec![1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]]),
    ("id-GostR3411-94-CryptoProParamSet".to_string(),
    vec![vec![10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
         vec![5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
         vec![7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
         vec![4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
         vec![7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
         vec![7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
         vec![13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
         vec![1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12]]),
    ("EACParamSet".to_string(),
    vec![vec![11, 4, 8, 10, 9, 7, 0, 3, 1, 6, 2, 15, 14, 5, 12, 13],
         vec![1, 7, 14, 9, 11, 3, 15, 12, 0, 5, 4, 6, 13, 10, 8, 2],
         vec![7, 3, 1, 9, 2, 4, 13, 15, 8, 10, 12, 6, 5, 0, 11, 14],
         vec![10, 5, 15, 7, 14, 11, 3, 9, 2, 8, 1, 12, 0, 4, 6, 13],
         vec![0, 14, 6, 11, 9, 3, 8, 4, 12, 15, 10, 5, 13, 7, 1, 2],
         vec![9, 2, 11, 12, 0, 4, 5, 6, 3, 15, 13, 8, 1, 7, 14, 10],
         vec![4, 0, 14, 1, 5, 11, 8, 3, 12, 2, 9, 7, 6, 10, 13, 15],
         vec![7, 14, 12, 13, 9, 4, 8, 15, 10, 2, 6, 0, 3, 11, 5, 1]]),
    ]);
 }

 impl GostCrypto {
    pub fn new(key: Vec<u8>, sbox_name: String) -> Result<GostCrypto, String> {
        // **An unknown name used to become CryptoPro-A.** A GOST cipher
        // is its S-box: two parameter sets are two different ciphers
        // that both encrypt and both decrypt, so substituting one for
        // the other produces ciphertext nobody can read and nothing to
        // say so. A misspelt name in a configuration file, or a
        // parameter set this library has not got, came out as a
        // working cipher of the wrong kind.
        GostCrypto::new_with_sbox(key, GostCrypto::sbox_named(&sbox_name)?)
    }

    /// The substitution rows of a named parameter set.
    ///
    /// Public because GOST R 34.11-94 needs them too: the hash is the
    /// block cipher with a key schedule on top, and it is parameterised
    /// by the same tables under different OIDs.
    pub fn sbox_named(name: &str) -> Result<Vec<Vec<u8>>, String> {
        match SBOXES.get(name) {
            Some(sbox) => Ok(sbox.to_vec()),
            // **Then the registry**, so a parameter set this library
            // does not carry can be given to it at run time rather
            // than by editing the table above. A GOST cipher is its
            // S-box, and the tables are distributed separately by
            // design - an organisation's own set is an ordinary thing
            // to meet, not an exotic one. See `src/registry.rs`.
            None if crate::registry::gost_param_set(name).is_some() =>
                Ok(crate::registry::gost_param_set(name).expect("just checked")),
            None => {
                let mut known: Vec<String> = SBOXES.keys().cloned().collect();
                known.extend(crate::registry::registered().into_iter()
                    .filter(|(_, meaning)| matches!(
                        meaning, crate::registry::Meaning::GostParamSet(_)))
                    .map(|(oid, _)| oid));
                known.sort();
                Err(format!("Unknown GOST parameter set {:?}. Known: {}. \
                             Another can be given one with \
                             allcrypt.register_oid(oid, gost_sbox=...).",
                            name, known.join(", ")))
            }
        }
    }

    /// The name every caller that does not care should pass.
    pub const DEFAULT_PARAM_SET: &'static str =
        "id-Gost28147-89-CryptoPro-A-ParamSet";

    /// The substitution rows this instance was built with.
    ///
    /// Exposed so `magma.rs` can pin its own copy of
    /// `id-tc26-gost-28147-param-Z` against this one. Two copies of a
    /// table drift, and a drifted S-box is a cipher that disagrees with
    /// the other half of the same library while passing its own tests.
    pub fn sbox_rows(&self) -> &[Vec<u8>] {
        &self.sbox
    }

    /// **The length is checked here rather than assumed.** GOST
    /// 28147-89 has one key size, 256 bits, and the schedule reads
    /// eight little-endian words straight out of it - so anything
    /// shorter used to index past the end and *panic*. A panic is not
    /// an error: in Rust it unwinds through a function that returns
    /// `Result`, and through the Python bindings it arrives as a
    /// `PanicException` that `except ValueError` does not catch.
    ///
    /// It survived because every test handed it 32 bytes. The catalogue
    /// tests used to carry a table of "which cipher takes which key
    /// length", and GOST's entry in that table was right - so the one
    /// loop that would have found this always passed the one length
    /// that works. They now try every length and require one to
    /// succeed, which is what found it.
    pub fn new_with_sbox(key: Vec<u8>, sbox: Vec<Vec<u8>>)
                         -> Result<GostCrypto, String> {
        if key.len() != 32 {
            return Err(format!("Wrong key length {}. GOST 28147-89 takes \
                                32 bytes.", key.len()));
        }
        let mut key32: [u32; 8]= [0; 8];
        let mut s_table: Box<[[u32; 256]; 4]> = Box::new([[0; 256]; 4]);
        for i in 0..8 {
            key32[i] = u32::from_le_bytes(
                key[(i*4)..(i+1)*4].try_into().expect("32 bytes, checked above"));
        }
        for i in 0..4{
            for j in 0..256 {
                let temp: u32 = (sbox[2*i][j%16] | (sbox[2*i + 1][j/16] << 4)) as u32;
                s_table[i][j] = temp.rotate_left(11+8*i as u32);
            }
        }
        Ok(GostCrypto{
            _key: key,
            sbox,
            key32,
            s_table,
            mac_state: vec![0;8],
            mac_data_unprocessed: vec![],
            mac_blocks_done: 0,
        })
    }

    /// Replace the key and keep everything built from the S-box. GOST
    /// R 34.11-94 encrypts under four fresh keys per block, and rebuilding
    /// the 4 KB substitution table each time was most of its cost.
    pub fn set_key(&mut self, key: &[u8; 32]) {
        for (word, bytes) in self.key32.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        self._key.clear();
        self._key.extend_from_slice(key);
    }

    /// One block, without the `Vec` of `block_encrypt`.
    pub fn encrypt_block(&self, input: [u8; 8]) -> [u8; 8] {
        let mut n1 = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(input[4..8].try_into().unwrap());
        for _i in 0..3 {
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[0]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[1]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[2]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[3]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[4]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[5]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[6]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[7]));
        }
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[7]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[6]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[5]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[4]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[3]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[2]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[1]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[0]));

        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&n2.to_le_bytes());
        out[4..].copy_from_slice(&n1.to_le_bytes());
        out
    }

    fn f(&self, value: u32) -> u32 {
        self.s_table[3][((value>>24)&0xff) as usize] ^ 
        self.s_table[2][((value>>16)&0xff) as usize] ^
        self.s_table[1][((value>>8)&0xff) as usize] ^
        self.s_table[0][((value)&0xff) as usize]
    }

    /// The MAC's chaining state.
    ///
    /// Exposed for CryptoPro key meshing (RFC 4357 section 2.3.2),
    /// which re-derives the IV from the state as it stands after 1024
    /// octets - "the value of the initialization vector after
    /// processing", which for a CBC-MAC is this.
    pub fn mac_state(&self) -> &[u8] {
        &self.mac_state
    }

    /// Bytes taken in and not yet a whole block.
    ///
    /// Meshing builds a new `GostCrypto` and the partial block has to
    /// survive that: the MAC covers one continuous byte stream, and a
    /// section boundary is not a message boundary. Losing these bytes
    /// would be silent - the tag would simply be of a shorter message.
    pub fn mac_buffered(&self) -> &[u8] {
        &self.mac_data_unprocessed
    }

    /// Whole blocks taken in so far. See `restore_buffered`.
    pub fn mac_blocks_done(&self) -> usize {
        self.mac_blocks_done
    }

    /// Put back what `mac_buffered` and `mac_blocks_done` returned,
    /// after a re-key.
    ///
    /// The count has to travel with the bytes. Meshing builds a fresh
    /// `GostCrypto`, and a fresh one has processed nothing - so the
    /// two-block minimum in `digest` would think a message 1024 octets
    /// long was its first block and pad it out. It cannot happen at
    /// the sizes meshing works at, which is exactly why it would have
    /// sat here unnoticed.
    pub fn restore_buffered(&mut self, buffered: &[u8], blocks_done: usize) {
        self.mac_data_unprocessed = buffered.to_vec();
        self.mac_blocks_done = blocks_done;
    }

    pub fn set_mac_iv(&mut self, iv: &[u8]) { 
        self.mac_state = iv.to_vec();
        /*for i in 0..2 {
            for j in 0..4 {
                self.mac_state[i*4+j] = iv[(1-i)*4+j];
            }
        }*/
    }

    fn k(&self, svalue: u32) -> u32 {
        let mut rv: u32 = 0;
        for i in 0..8 {
            rv += (self.sbox[i][((svalue>>(i*4))&0xf) as usize] as u32)<<(i*4);
        }
        rv
    }
    fn mac_block(&self, input: &[u8]) -> Vec<u8> {
        let mut n1 = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(input[4..8].try_into().unwrap());

        for _i in 0..2 {
            for j in 0..8 {
                (n1, n2) = (self.k(u32::wrapping_add(n1, self.key32[j])).rotate_left(11) ^ n2, n1);
            }
        }
        let mut result = vec![];
        result.extend_from_slice(&n1.to_le_bytes());
        result.extend_from_slice(&n2.to_le_bytes());
        result
    }
}

impl BlockCipher for GostCrypto {
    fn blocksize(&self) -> usize {
        8
    }
    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut n1 = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let mut n2 = u32::from_le_bytes(input[4..8].try_into().unwrap());
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[0]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[1]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[2]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[3]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[4]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[5]));
        n2 ^= self.f(u32::wrapping_add(n1, self.key32[6]));
        n1 ^= self.f(u32::wrapping_add(n2, self.key32[7])); 

        for _i in 0..3 {
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[7]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[6]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[5]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[4]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[3]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[2]));
            n2 ^= self.f(u32::wrapping_add(n1, self.key32[1]));
            n1 ^= self.f(u32::wrapping_add(n2, self.key32[0]));
        }
        result.extend_from_slice(&n2.to_le_bytes());
        result.extend_from_slice(&n1.to_le_bytes());
    }
    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.encrypt_block(input[..8].try_into().unwrap()));
    }

    // GOST gamma generation is CTR with an unusual counter: the IV is
    // encrypted once, then each step adds C2 mod 2^32 to the low word and
    // C1 mod 2^32-1 to the high word. Expressing it as these two hooks means
    // the generic `Ctr` driver in `modes` does all the rest.

    fn ctr_init(&mut self, iv: &[u8], counter: &mut Vec<u8>) -> Result<(), String> {
        if iv.len() != self.blocksize() {
            return Err("IV size not same as blocksize.".to_string());
        }
        counter.clear();
        self.block_encrypt(iv, counter);
        if counter.len() != self.blocksize() {
            return Err("block_encrypt did not produce exactly one block.".to_string());
        }
        self.ctr_next(counter);
        Ok(())
    }

    fn ctr_next(&self, counter: &mut [u8]) {
        const C1: u32 = 0x01010104;
        const C2: u32 = 0x01010101;
        let n1 = u32::from_le_bytes(counter[0..4].try_into().unwrap()).wrapping_add(C2);
        // Addition modulo 2^32-1: a carry out of the top folds back into the
        // low bit. `wrapping_add` then `% 0xffffffff` loses that carry and
        // comes out one too low whenever the sum exceeds 2^32.
        let n2_old = u32::from_le_bytes(counter[4..8].try_into().unwrap());
        let (sum, carry) = n2_old.overflowing_add(C1);
        let n2 = if carry { sum.wrapping_add(1) } else { sum };
        counter[0..4].copy_from_slice(&n1.to_le_bytes());
        counter[4..8].copy_from_slice(&n2.to_le_bytes());
    }
}

impl Mac for GostCrypto {
    fn update(&mut self, input: &[u8]) {
        self.mac_data_unprocessed.append(&mut input.to_vec());
        if self.mac_data_unprocessed.len() < self.blocksize() {
            return
        }
        for i in 0..(self.mac_data_unprocessed.len()/self.blocksize()) {
            self.mac_state = self.mac_block(
                &crate::xor(&self.mac_data_unprocessed[i*self.blocksize()..(i+1)*self.blocksize()],
                 &self.mac_state));
        }
        self.mac_blocks_done += self.mac_data_unprocessed.len()/self.blocksize();
        self.mac_data_unprocessed = self.mac_data_unprocessed.split_off(self.blocksize()*(self.mac_data_unprocessed.len()/self.blocksize()));
    }

    /// The tag as the message stands, **zero padded to at least two
    /// blocks**.
    ///
    /// GOST 28147-89 section 4.1 defines the imitovstavka only for a
    /// message of two blocks or more, and says nothing about a shorter
    /// one. So a shorter one is not a matter of reading the standard
    /// again - there is nothing there to read - and what settles it is
    /// what the deployed implementation does: gost-engine's
    /// `gost_imit_final` runs an extra all-zero block through whenever
    /// no full block has been MACed yet, which is the same thing as
    /// padding the message out to two blocks.
    ///
    /// Without this a one-block message got one block, which is
    /// self-consistent, round trips, and is a tag no GOST peer
    /// accepts. `tests/test_gost_engine_vectors.rs` is what found it,
    /// and nothing before it could have: the record layer's MAC input
    /// is a sequence number, a header and a fragment, so it is never
    /// shorter than thirteen bytes, and both ends of every other test
    /// here are ours.
    fn digest(&mut self) -> Vec<u8> {
        let partial = !self.mac_data_unprocessed.is_empty();
        let blocks = self.mac_blocks_done + usize::from(partial);
        if blocks == 0 {
            // An empty message MACs nothing at all; the two-block
            // minimum is about short messages, not about no message.
            return self.mac_state.to_vec();
        }

        let mut state = self.mac_state.to_vec();
        if partial {
            let mut data = self.mac_data_unprocessed.to_owned();
            data.resize(self.blocksize(), 0);
            state = self.mac_block(&crate::xor(&data, &state));
        }
        if blocks == 1 {
            state = self.mac_block(&crate::xor(&vec![0u8; self.blocksize()],
                                               &state));
        }
        state
    }
}
#[cfg(test)]
mod document_tests {
    /*
    The S-box tables, checked against RFC 4357 rather than trusted.

    A GOST cipher *is* its S-box: two parameter sets are two different
    ciphers that both encrypt and both decrypt, and a single wrong
    nibble produces a cipher that round trips against itself and agrees
    with nobody. The tables here were typed, and until this test there
    was nothing behind their thousand numbers but somebody having typed
    them correctly.

    RFC 4357 prints them packed two substitutions to a byte: section
    11.1 has the six encryption parameter sets and section 11.2 the two
    for GOST R 34.11-94. Byte `4i + j` holds `K[2j](i)` in its high
    nibble and `K[2j+1](i)` in its low one, which the document's own
    annotated copy - it prints the columns beside the bytes - is what
    settles.

    `id-tc26-gost-28147-param-Z` and `EACParamSet` are not in RFC 4357
    and are not checked here: the first is RFC 7836's and is pinned
    instead by `magma.rs`, which carries the same table and asserts the
    two agree, and the second is from a document this repository does
    not have.
    */

    use super::*;

    const RFC_4357: &str = include_str!("../../rfcs/rfc4357.txt");

    /// The 64 packed bytes printed under a parameter set's OID.
    fn packed(marker: &str) -> Vec<u8> {
        let lines: Vec<&str> = RFC_4357.lines().collect();
        let start = lines.iter().rposition(|line| {
            let trimmed = line.trim();
            trimmed.starts_with(':') && trimmed.ends_with(marker)
        }).unwrap_or_else(|| panic!("{} is not in RFC 4357's dump", marker));

        let mut bytes = Vec::new();
        for line in &lines[start + 1..] {
            if line.contains("Popov,") || line.contains("RFC 4357") {
                continue;
            }
            let trimmed = line.trim();
            // The annotated sets print their table as comment lines
            // above the bytes.
            if trimmed.starts_with("--") || trimmed.is_empty() {
                continue;
            }
            let rest = match trimmed.strip_prefix(':') {
                Some(rest) => rest.trim(),
                None => continue,
            };
            let words: Vec<&str> = rest.split_whitespace().collect();
            if words.is_empty() || !words.iter().all(
                |word| word.len() == 2 && word.chars().all(
                    |c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())) {
                continue;
            }
            for word in words {
                bytes.push(u8::from_str_radix(word, 16).expect("hex"));
            }
            if bytes.len() >= 64 {
                break;
            }
        }
        assert_eq!(bytes.len(), 64,
                   "{}: the parameters open with a 64 byte OCTET STRING",
                   marker);
        bytes
    }

    fn pack(sbox: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        for value in 0..16usize {
            for pair in 0..4usize {
                out[4 * value + pair] =
                    (sbox[2 * pair][value] << 4) | sbox[2 * pair + 1][value];
            }
        }
        out
    }

    #[test]
    fn test_the_parameter_sets_are_rfc_4357s() {
        let named = ["id-Gost28147-89-TestParamSet",
                     "id-Gost28147-89-CryptoPro-A-ParamSet",
                     "id-Gost28147-89-CryptoPro-B-ParamSet",
                     "id-Gost28147-89-CryptoPro-C-ParamSet",
                     "id-Gost28147-89-CryptoPro-D-ParamSet",
                     "id-GostR3411-94-TestParamSet",
                     "id-GostR3411-94-CryptoProParamSet"];
        for name in named {
            let carried = GostCrypto::sbox_named(name).unwrap();
            assert_eq!(pack(&carried), packed(name),
                       "{} disagrees with RFC 4357", name);
        }

        // Seven different tables, so a parser that returned the same
        // bytes every time would not pass.
        let mut seen: Vec<Vec<u8>> = named.iter()
            .map(|name| packed(name)).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), named.len(), "two parameter sets are identical");

        // And each substitution is a permutation of 0..16, which is
        // what makes a nibble swap survivable and therefore worth
        // checking separately.
        for name in named {
            for (index, row) in GostCrypto::sbox_named(name).unwrap()
                                    .iter().enumerate() {
                let mut sorted = row.clone();
                sorted.sort();
                assert_eq!(sorted, (0..16u8).collect::<Vec<u8>>(),
                           "{} K{} is not a permutation", name, index + 1);
            }
        }
    }
}
