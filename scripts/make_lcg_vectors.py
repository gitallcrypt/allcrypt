#!/usr/bin/env python3
"""Write vectors/lcg.vec: the named linear congruential generators'
outputs, as the software that shipped them produces them.

    scripts/witness/lcgwitness/build.sh /opt/lcgwitness
    python3 scripts/make_lcg_vectors.py

**A development tool, not a test.** It needs the witness built (which
fetches its sources once), the system's glibc and a JDK;
`tests/test_lcg.rs` reads `vectors/lcg.vec` offline. Where each answer
comes from:

- `minstd_rand0`, `minstd_rand`: libstdc++'s `std::minstd_rand0` and
  `std::minstd_rand`.
- `musl`, `newlib`, `msvc`: each library's own `srand`/`rand`, compiled
  from its source - musl 1.2.5, newlib 4.4.0, and for MSVC the
  reimplementation in Wine 9.0's msvcrt.
- `mmix`: PCG's `pcg_oneseq_64_step_r`, whose state update is Knuth's
  MMIX generator.
- `glibc_type0`, `lrand48`, `mrand48` and every `rand48` row: the
  system's glibc through ctypes.
- `java` and every `java` row: the JDK's `java.util.Random`.

RANDU has no implementation left to ask, so it is not here;
`tests/test_lcg.rs` checks it by the relation that made it notorious.

Row formats, one generator run per row:

    lcg name=<name> seed=<n> skip=<k> outputs=<v,...>
        LCG::named(name, seed), k outputs discarded, then these.
    java method=<m> seed=<n> arg=<a> outputs=<v,...>
        new Random(seed), then m(a) once per value.
    rand48 setup=<how> calls=<l|m|d...> outputs=<v,...>
        how is srand48:<n>, seed48:<w0,w1,w2>, lcong48:<7 words> or none,
        or several of them joined by ';' and applied in order; the calls
        are lrand48, mrand48 and drand48.
"""

import ctypes
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "lcg.vec")
WITNESS = os.environ.get("LCG_WITNESS", "/opt/lcgwitness")

libc = ctypes.CDLL("libc.so.6")
libc.random.restype = ctypes.c_long
libc.initstate.restype = ctypes.c_char_p
libc.initstate.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.c_size_t]
libc.srand48.argtypes = [ctypes.c_long]
libc.lrand48.restype = ctypes.c_long
libc.mrand48.restype = ctypes.c_long
libc.drand48.restype = ctypes.c_double
libc.seed48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]
libc.seed48.restype = ctypes.POINTER(ctypes.c_ushort)
libc.lcong48.argtypes = [ctypes.POINTER(ctypes.c_ushort)]

SEEDS = [0, 1, 2, 42, 12345, 2**31 - 2, 2**31 - 1, 2**31, 2**32 - 1, 2**32,
         2**32 + 5, 2**48 + 3, 2**63 - 1, 2**64 - 1]
COUNT = 12
LONG_RUNS = [(1, 9999), (42, 9999), (2**31 - 1, 100000)]

_type0_buffer = ctypes.create_string_buffer(8)


def witness(name, seed, skip, count):
    out = subprocess.run([os.path.join(WITNESS, "lcgwitness"), name, str(seed),
                          str(skip), str(count)], check=True, capture_output=True,
                         text=True).stdout.split()
    assert len(out) == count, (name, seed, out)
    return out


def glibc_type0(seed, skip, count):
    # initstate with eight bytes selects TYPE_0, the bare LCG. The seed
    # argument is an unsigned int; masking is the conversion C applies.
    libc.initstate(seed & 0xFFFFFFFF, _type0_buffer, 8)
    values = [libc.random() for _ in range(skip + count)]
    return [str(v) for v in values[skip:]]


def rand48(fn_name, seed, skip, count):
    libc.srand48(ctypes.c_long(to_signed(seed, 64)))
    fn = getattr(libc, fn_name)
    values = [fn() for _ in range(skip + count)]
    return [str(v) for v in values[skip:]]


def java(seed, method, arg, count):
    out = subprocess.run(["java", "-cp", WITNESS, "JavaRandomWitness", str(seed),
                          method, str(arg), str(count)], check=True,
                         capture_output=True, text=True).stdout.split("\n")[:count]
    assert len(out) == count, (seed, method, out)
    return [v if v else "-" for v in out]


def to_signed(n, bits):
    n &= (1 << bits) - 1
    return n - (1 << bits) if n >> (bits - 1) else n


def named_rows():
    rows = []
    sources = {
        "minstd_rand0": lambda s, k, n: witness("minstd_rand0", s, k, n),
        "minstd_rand": lambda s, k, n: witness("minstd_rand", s, k, n),
        "glibc_type0": glibc_type0,
        "lrand48": lambda s, k, n: rand48("lrand48", s, k, n),
        "mrand48": lambda s, k, n: rand48("mrand48", s, k, n),
        "java": lambda s, k, n: java(to_signed(s, 64), "nextInt", 0, k + n)[k:],
        "msvc": lambda s, k, n: witness("msvc", s, k, n),
        "musl": lambda s, k, n: witness("musl", s, k, n),
        "newlib": lambda s, k, n: witness("newlib", s, k, n),
        "mmix": lambda s, k, n: witness("mmix", s, k, n),
    }
    for name, source in sources.items():
        for seed in SEEDS:
            rows.append(f"lcg name={name} seed={seed} skip=0 "
                        f"outputs={','.join(source(seed, 0, COUNT))}")
        for seed, skip in LONG_RUNS:
            rows.append(f"lcg name={name} seed={seed} skip={skip} "
                        f"outputs={','.join(source(seed, skip, 3))}")
    return rows


def java_rows():
    rows = []
    seeds = [0, 1, 42, -1, 12345, -9223372036854775808, 9223372036854775807,
             0x5DEECE66D]
    plain = ["nextInt", "nextLong", "nextBoolean", "nextFloat", "nextDouble"]
    # Bounds: tiny, a power of two at each end, and just over a power of
    # two, where nearly half of next(31)'s values are rejected.
    bounds = [1, 2, 3, 6, 7, 10, 16, 100, 1000, 2**30, 2**30 + 1, 2**31 - 1]
    for seed in seeds:
        for method in plain:
            rows.append(f"java method={method} seed={seed} arg=0 "
                        f"outputs={','.join(java(seed, method, 0, 16))}")
        for bound in bounds:
            rows.append(f"java method=nextIntBounded seed={seed} arg={bound} "
                        f"outputs={','.join(java(seed, 'nextIntBounded', bound, 16))}")
        for n in range(0, 10):
            rows.append(f"java method=nextBytes seed={seed} arg={n} "
                        f"outputs={','.join(java(seed, 'nextBytes', n, 3))}")
    return rows


def run_rand48(setup, calls):
    """One sequence in a fresh process, so 'none' sees glibc's initial
    state rather than whatever an earlier row left."""
    program = f"""
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.lrand48.restype = ctypes.c_long
libc.mrand48.restype = ctypes.c_long
libc.drand48.restype = ctypes.c_double
libc.srand48.argtypes = [ctypes.c_long]
for step in {setup!r}.split(";"):
    kind, _, arg = step.partition(":")
    if kind == "srand48":
        libc.srand48(int(arg))
    elif kind == "seed48":
        libc.seed48((ctypes.c_ushort * 3)(*map(int, arg.split(","))))
    elif kind == "lcong48":
        libc.lcong48((ctypes.c_ushort * 7)(*map(int, arg.split(","))))
out = []
for c in {calls!r}:
    v = {{"l": libc.lrand48, "m": libc.mrand48, "d": libc.drand48}}[c]()
    out.append(repr(v))
print(",".join(out))
"""
    return subprocess.run([sys.executable, "-I", "-c", program], check=True,
                          capture_output=True, text=True).stdout.strip()


def rand48_rows():
    rows = []
    calls = "lmdlmdllmmddldmldm"
    setups = ["none"]
    setups += [f"srand48:{s}" for s in (0, 1, 42, -1, 2**31, -(2**63), 2**40 + 7)]
    setups += ["seed48:0,0,0", "seed48:13070,1,0", "seed48:65535,65535,65535",
               "seed48:1,2,3"]
    # lcong48 changes the multiplier and addend too, which srand48 and
    # seed48 reset; the last one is RANDU's multiplier in 48 bits.
    setups += ["lcong48:1,2,3,58989,57068,5,11", "lcong48:5,0,0,3,1,0,0",
               "lcong48:65535,65535,65535,65535,65535,65535,65535",
               "lcong48:1,0,0,3,1,0,0"]
    # srand48 and seed48 after lcong48 must put the multiplier and addend
    # back, which a fresh state cannot show.
    setups += ["lcong48:1,2,3,3,1,0,0;seed48:1,2,3", "lcong48:1,2,3,3,1,0,7;srand48:5"]
    for setup in setups:
        rows.append(f"rand48 setup={setup} calls={calls} "
                    f"outputs={run_rand48(setup, calls)}")
    return rows


def main():
    if not os.path.exists(os.path.join(WITNESS, "lcgwitness")):
        sys.exit(f"no witness in {WITNESS}: run scripts/witness/lcgwitness/build.sh")
    rows = named_rows() + java_rows() + rand48_rows()
    header = ("# Named linear congruential generators. Written by\n"
              "# scripts/make_lcg_vectors.py; do not edit. Every value is the\n"
              "# output of the shipped software: libstdc++, musl 1.2.5, newlib\n"
              "# 4.4.0 and Wine 9.0 compiled from source, PCG's LCG step, glibc\n"
              "# through ctypes, and JDK 21. See the script for the formats.\n")
    with open(OUTPUT, "w") as f:
        f.write(header)
        for r in rows:
            f.write(r + "\n")
    print(f"{len(rows)} rows")


if __name__ == "__main__":
    main()
