/*
Pseudo random number generator functions.

**Not for keys.** Everything in this module is a statistical generator,
predictable from a handful of outputs. It is here for simulation, test data,
and for studying the generators themselves - which is squarely in the spirit
of the project, since an LCG is exactly the kind of thing you need when
talking to old systems that used one.

For anything keyed - key generation, nonces, IVs, TLS randoms - use
`crate::random`, which reads the operating system's generator. The two are in
separate modules on purpose.
*/

pub mod lcg;

pub trait Prng {
    fn name(&self) -> String;
    fn get_bytes(&mut self, output: &mut Vec<u8>, count: usize);
    fn get_raw_output(&mut self, output: &mut Vec<u64>);
    fn set_seed(&mut self, _seed: u64) {

    }
}