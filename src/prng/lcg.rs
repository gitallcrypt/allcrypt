use super::Prng;



pub struct LCG {
    state: u128,
    a: u128,
    c: u128,
    m: u128,
    mask: u128,
    mask_shift: u32,
}


impl LCG {
    pub fn new(state: u128, a: u128, c: u128, m: u128, mask: u128) -> LCG {
        LCG{
            state,
            a,
            c,
            m,
            mask,
            mask_shift: mask.trailing_zeros(),
        } 
    }
    pub fn get_byte(&mut self) -> u8 {
        self.state = self.state.wrapping_mul(self.a).wrapping_add(self.c) % self.m;
        ((self.state & self.mask) >> self.mask_shift) as u8
    }
}

impl Prng for LCG {
    fn get_bytes(&mut self, output: &mut Vec<u8>, count: usize) {
        for _i in 0..count {
            output.push(self.get_byte());
        }
    }
    fn name(&self) -> String {
        format!("LCG {}*x + {} % {}", self.a, self.c, self.m).to_string()
    }
    fn get_raw_output(&mut self, _output: &mut Vec<u64>) {
        unimplemented!("LCG::get_raw_output is not implemented yet");
    }
    fn set_seed(&mut self, seed: u64) {
        self.state = seed as u128;
    }
}