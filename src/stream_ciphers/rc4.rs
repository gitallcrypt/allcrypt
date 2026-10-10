use crate::stream_ciphers::StreamCipher;

pub struct RC4 {
    key: Vec<u8>,
    key_mapping: Vec<u8>,
    i: usize,
    j: usize,
}

impl RC4 {
    pub fn new(key: &[u8]) -> Result<RC4, String> {
        // An empty key divides by zero in the KSA; past 256 bytes the extra
        // key material is never read, so reject rather than silently ignore it.
        if key.is_empty() || key.len() > 256 {
            return Err(format!("Wrong key length {}. Must be 1..=256.", key.len()));
        }
        let key_mapping: Vec<u8> = vec![0; 256];
        let mut rc4 = RC4{
            key: key.to_vec(),
            key_mapping,
            i: 0,
            j: 0,
        };
        rc4.setup_key();
        Ok(rc4)
    }
    /// The key-scheduling algorithm alone. Private, because it leaves
    /// `i` and `j` where they were: run after some output it re-keys
    /// the permutation without restarting the generator, which is no
    /// stream RC4 defines. `reset` does both.
    fn setup_key(&mut self) {
        for i in 0..256 {
            self.key_mapping[i] = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(u8::wrapping_add(self.key[i % self.key.len()], self.key_mapping[i]));
            (self.key_mapping[i], self.key_mapping[j as usize]) = (self.key_mapping[j as usize], self.key_mapping[i]);
        } 
    }
    pub fn reset(&mut self) {
        self.setup_key();
        self.i = 0;
        self.j = 0;
    }
}

impl StreamCipher for RC4 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        for item in input {
            self.i = (self.i+1) & 0xff;
            self.j = (self.j + self.key_mapping[self.i] as usize) & 0xff;
            (self.key_mapping[self.i], self.key_mapping[self.j]) = 
                (self.key_mapping[self.j], self.key_mapping[self.i]);
            result.push(item ^ 
                self.key_mapping[u8::wrapping_add(self.key_mapping[self.i], 
                    self.key_mapping[self.j]) as usize & 0xff]);
        }
    }
}