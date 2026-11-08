#!/usr/bin/env python3
"""Check the SNOW 3G and ZUC witnesses before anything uses them.

    python3 scripts/witness/snow3g_zuc/selftest.py /opt/gppwitness

  * Every published test set - Doc3's SNOW 3G, UEA2 and UIA2 sets, the
    EEA3/EIA3 test data's ZUC, 128-EEA3 and 128-EIA3 sets, and Intel's
    ZUC-256 keystreams and MACs - reproduced by every witness that
    implements it, and by at least two.
  * The witnesses agreeing over random inputs of every kind.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import published  # noqa: E402


def check_published(out):
    sets = published.published()
    ks, macs = published.zuc256_published()
    cases = published.requests_for_published(sets) + published.requests_for_zuc256(ks, macs)
    counts = {}
    answers = published.ask_all(out, [r for r, _, _ in cases])
    for (request, want, label), given in zip(cases, answers):
        if len(given) < 2:
            sys.exit(f"{label}: only {sorted(given)} answer")
        for program, got in given.items():
            if not published.answer_matches(want, got):
                sys.exit(f"{program} does not reproduce {label}")
            counts[program] = counts.get(program, 0) + 1
    return counts


def random_requests(rng, scale=1):
    """Requests of every kind over random inputs: lengths either side of
    the word and byte steps, every bearer and both directions."""
    reqs = []
    lengths = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000]
    for n in lengths + [4096 * scale]:
        reqs.append(published.stream("snow3g", rng.randbytes(16), rng.randbytes(16), n))
        reqs.append(published.stream("zuc128", rng.randbytes(16), rng.randbytes(16), n))
        reqs.append(published.stream("zuc256", rng.randbytes(32), zuc256_iv(rng), n))
    bit_lengths = [1, 2, 7, 8, 9, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 255,
                   256, 257, 511, 512, 513, 1000, 4095, 4096, 4097, 20000 * scale]
    for bits in bit_lengths:
        data = rng.randbytes((bits + 7) // 8)
        key = rng.randbytes(16)
        count, bearer, direction = rng.getrandbits(32), rng.randrange(32), rng.randrange(2)
        for alg in ("uea2", "eea3"):
            reqs.append(published.f8(alg, key, count, bearer, direction, bits, data))
        reqs.append(published.f9("uia2", key, count, rng.getrandbits(32), direction, bits, data))
        for alg in ("eia1", "eia3"):
            reqs.append(published.f9(alg, key, count, bearer, direction, bits, data))
        reqs.append(published.zucmac(32, key, rng.randbytes(16), bits, data))
        for tag in (32, 64, 128):
            reqs.append(published.zucmac(tag, rng.randbytes(32), zuc256_iv(rng), bits, data))
    # Empty messages, which some implementations refuse. Both witnesses
    # with UIA2's free FRESH refuse one, so an empty UIA2 is not asked;
    # 128-EIA1 is the same function with FRESH = BEARER || 0^27.
    key = rng.randbytes(16)
    reqs += [published.f8(a, key, 1, 2, 1, 0, b"") for a in ("uea2", "eea3")]
    reqs += [published.f9(a, key, 1, 2, 1, 0, b"") for a in ("eia1", "eia3")]
    reqs += [published.zucmac(32, key, rng.randbytes(16), 0, b"")]
    reqs += [published.zucmac(t, rng.randbytes(32), zuc256_iv(rng), 0, b"") for t in (32, 64, 128)]
    return reqs


def zuc256_iv(rng):
    return rng.randbytes(17) + bytes(rng.randrange(64) for _ in range(8))


def check_agreement(out, requests):
    """{request: answer}, every request answered by at least two programs
    that agree; dies naming the first disagreement."""
    agreed = {}
    for request, given in zip(requests, published.ask_all(out, requests)):
        if len(given) < published.witnesses_needed(request):
            sys.exit(f"only {sorted(given)} answer {request[:120]}")
        if len(set(given.values())) != 1:
            groups = {}
            for program, got in given.items():
                groups.setdefault(got, []).append(program)
            sys.exit(f"the witnesses disagree on {request[:160]}: "
                     + "; ".join(f"{sorted(p)} {a[:32]}" for a, p in groups.items()))
        agreed[request] = (next(iter(given.values())), sorted(given))
    return agreed


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/gppwitness"
    counts = check_published(out)
    check_agreement(out, random_requests(random.Random(1)))
    print("snow3g_zuc witnesses: " + ", ".join(f"{p} {n}" for p, n in counts.items())
          + " published sets reproduced; they agree over random inputs")


if __name__ == "__main__":
    main()
