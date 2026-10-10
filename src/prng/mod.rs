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

pub mod dual_ec;
pub mod lcg;

/// A statistical generator: a name, bytes, raw words, and reseeding.
///
/// Every method is required. `set_seed` once had an empty default
/// body, so an implementation that forgot it compiled and ignored
/// every reseed while still producing output - a generator that
/// "works" and cannot be made to repeat a run. The one implementation,
/// `lcg::LCG`, had always overridden it; the default existed only to be
/// wrong. An implementation without it does not compile:
///
/// ```compile_fail
/// use allcrypt::prng::Prng;
/// struct Constant;
/// impl Prng for Constant {
///     fn name(&self) -> String { "constant".to_string() }
///     fn get_bytes(&mut self, output: &mut Vec<u8>, count: usize) {
///         output.extend(std::iter::repeat_n(4u8, count));
///     }
///     fn get_raw_output(&mut self, output: &mut Vec<u64>) { output.push(4); }
/// }
/// ```
pub trait Prng {
    fn name(&self) -> String;
    fn get_bytes(&mut self, output: &mut Vec<u8>, count: usize);
    fn get_raw_output(&mut self, output: &mut Vec<u64>);
    /// Restart the generator from `seed`, by the generator's own rule.
    fn set_seed(&mut self, seed: u64);
}