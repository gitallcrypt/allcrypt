//! The modes and MACs allocate their scratch once per stream, not once
//! per block.
//!
//! That is a design invariant, and nothing in the ordinary tests can
//! see it: a loop that allocates a fresh vector per block produces the
//! same bytes as one that does not. This file counts heap allocations
//! through the global allocator while a message of a thousand blocks
//! goes through, and refuses a count that grows with the block count.
//! PCBC cloned its chain per block, LRW collected a masked block per
//! block, MGM built a vector per keystream block and per field product,
//! CTR-ACPKM cloned its counter per block, the GOST MAC copied its
//! input, XORed into a fresh vector and split the buffer per block, and
//! Rijndael copied its state once per round - all of which passed
//! every vector.
//!
//! The counter is global, so each test holds a lock for its whole
//! body; the test binary holds nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use allcrypt::api::AnyBlockCipher;
use allcrypt::block_ciphers::acpkm::CtrAcpkm;
use allcrypt::block_ciphers::gost::GostCrypto;
use allcrypt::block_ciphers::lrw;
use allcrypt::block_ciphers::mgm::Mgm;
use allcrypt::block_ciphers::rijndael::Rijndael;
use allcrypt::block_ciphers::{BlockCipher, CtsState, CtsVariant, PcbcState};
use allcrypt::Mac;

/// The system allocator with a count of the allocations made through
/// it. Every call is forwarded unchanged, so the only invariant this
/// adds to the allocator's own is that `COUNT` moves once per `alloc`;
/// `realloc` goes through the default, which counts as an `alloc`.
struct Counting;

static COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT.fetch_add(1, Ordering::Relaxed);
        // The layout is the caller's, handed on as received.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // The pointer and layout are the pair `alloc` handed out.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

static LOCK: Mutex<()> = Mutex::new(());

/// The lock every test holds from its first line: the allocation count
/// is process-wide, and the harness runs tests on several threads.
fn serialised() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Allocations made while `work` runs.
fn allocations<R>(work: impl FnOnce() -> R) -> (usize, R) {
    let before = COUNT.load(Ordering::Relaxed);
    let result = work();
    (COUNT.load(Ordering::Relaxed) - before, result)
}

/// A thousand blocks is enough that a per-block allocation dwarfs the
/// handful a call needs for its output and scratch; the output vector's
/// growth alone is logarithmic in the length. A cipher without its own
/// `encrypt_blocks` goes through the trait's default, which takes one
/// scratch vector per batch of sixteen blocks, so a mode that batches
/// through such a cipher is allowed that many on top.
const BLOCKS: usize = 1000;
const LIMIT: usize = 64;
const PER_BATCH: usize = BLOCKS / 16 + 1;

fn message(block: usize) -> Vec<u8> {
    (0..BLOCKS * block).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn test_pcbc_allocates_per_stream() {
    let _held = serialised();
    let mut cipher = AnyBlockCipher::new("aes", &[1; 16], None).unwrap();
    let input = message(16);
    for decrypting in [false, true] {
        let mut state = PcbcState::new(&mut cipher, &[2; 16], decrypting).unwrap();
        let mut out = Vec::with_capacity(input.len());
        let (count, result) = allocations(|| state.update(&mut cipher, &input, &mut out));
        result.unwrap();
        assert!(count < LIMIT, "PCBC made {count} allocations for {BLOCKS} blocks");
    }
}

#[test]
fn test_ciphertext_stealing_allocates_per_stream() {
    let _held = serialised();
    let mut cipher = AnyBlockCipher::new("aes", &[1; 16], None).unwrap();
    let input = message(16);
    let mut state = CtsState::new(&mut cipher, &[2; 16], CtsVariant::Cs3, false).unwrap();
    let mut out = Vec::with_capacity(input.len());
    let (count, result) = allocations(|| {
        // In pieces, since the held-back blocks are what used to be
        // drained into a fresh vector on every call.
        for piece in input.chunks(40) {
            state.update(&mut cipher, piece, &mut out)?;
        }
        state.finish(&mut cipher, &mut out)
    });
    result.unwrap();
    assert!(count < LIMIT, "CTS made {count} allocations for {BLOCKS} blocks");
}

#[test]
fn test_lrw_allocates_per_call() {
    let _held = serialised();
    let mut cipher = AnyBlockCipher::new("aes", &[1; 16], None).unwrap();
    let input = message(16);
    let (count, result) = allocations(|| lrw::encrypt(&mut cipher, &[3; 16], &[0; 16], &input));
    result.unwrap();
    assert!(count < LIMIT, "LRW made {count} allocations for {BLOCKS} blocks");
}

#[test]
fn test_mgm_allocates_per_message() {
    let _held = serialised();
    for (name, key_len, block) in [("kuznyechik", 32, 16), ("magma", 32, 8)] {
        let mut mgm = Mgm::new(name, &vec![4u8; key_len]).unwrap();
        let input = message(block);
        let aad = message(block);
        let (count, result) = allocations(|| mgm.encrypt(&vec![0u8; block], &aad, &input));
        let (ciphertext, tag) = result.unwrap();
        // Two batched passes, over the data and over the data with the
        // associated data.
        let limit = LIMIT + 3 * PER_BATCH;
        assert!(count < limit, "{name}-MGM made {count} allocations for {BLOCKS} blocks");
        let (count, result) = allocations(|| mgm.decrypt(&vec![0u8; block], &aad, &ciphertext, &tag));
        assert_eq!(result.unwrap(), input);
        assert!(count < limit, "{name}-MGM decryption made {count} allocations");
    }
}

#[test]
fn test_ctr_acpkm_allocates_per_section() {
    let _held = serialised();
    let input = message(16);
    let mut state = CtrAcpkm::new("kuznyechik", &[5; 32], &[6; 8], 16 * 64).unwrap();
    let mut buffer = input.clone();
    let (count, result) = allocations(|| state.apply(&mut buffer));
    result.unwrap();
    // A key change builds a cipher, which may allocate: the section is
    // 64 blocks, so sixteen of those over the message.
    assert!(count < LIMIT + PER_BATCH + 16 * 8,
            "CTR-ACPKM made {count} allocations for {BLOCKS} blocks");
}

#[test]
fn test_the_gost_mac_allocates_per_stream() {
    let _held = serialised();
    let mut mac = GostCrypto::new(vec![7; 32], GostCrypto::DEFAULT_PARAM_SET.to_string()).unwrap();
    let input = message(8);
    let (count, ()) = allocations(|| {
        // Ragged pieces, so the partial-block path runs as well.
        for piece in input.chunks(13) {
            mac.update(piece);
        }
    });
    assert!(count < LIMIT, "the GOST MAC made {count} allocations for {BLOCKS} blocks");
    assert_eq!(mac.digest().len(), 8);
}

#[test]
fn test_rijndael_allocates_nothing_per_block() {
    let _held = serialised();
    for block in [16usize, 24, 32] {
        let mut cipher = Rijndael::new(block, vec![8; 32]).unwrap();
        let input = message(block);
        let mut out = Vec::with_capacity(input.len());
        let (count, ()) = allocations(|| {
            for chunk in input.chunks(block) {
                cipher.block_encrypt(chunk, &mut out);
            }
        });
        assert!(count < LIMIT, "Rijndael-{} made {count} allocations for {BLOCKS} blocks",
                block * 8);
        let mut back = Vec::with_capacity(input.len());
        let (count, ()) = allocations(|| {
            for chunk in out.chunks(block) {
                cipher.block_decrypt(chunk, &mut back);
            }
        });
        assert!(count < LIMIT, "Rijndael-{} decryption made {count} allocations", block * 8);
        assert_eq!(back, input);
    }
}
