"""Donaldduck8/FEAL-NX-Python-Implementation's FEAL-NX as a witness,
speaking ../nessie/driver.h's request format on stdin:

    enc <key hex> <block hex>          one block
    dec <key hex> <block hex>
    enc-n <key hex> <block hex> <n>    the block encrypted n times over
    dec-n <key hex> <block hex> <n>

    python3 -I feal_driver.py <directory of FEAL_NX.py>

The round count N is the environment's ROUNDS, 32 when it is not set. A
key is FEAL-NX's 16 bytes, or FEAL-N's 8, which the FEAL-NX
specification defines as the same with the right key half zero.
"""

import importlib.util
import os
import sys


def main():
    spec = importlib.util.spec_from_file_location("FEAL_NX", os.path.join(sys.argv[1], "FEAL_NX.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rounds = int(os.environ.get("ROUNDS") or 32)
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 3 or fields[0] not in ("enc", "dec", "enc-n", "dec-n"):
            print("error op", flush=True)
            continue
        op = fields[0]
        try:
            key, block = list(bytes.fromhex(fields[1])), list(bytes.fromhex(fields[2]))
            count = int(fields[3]) if op.endswith("-n") and len(fields) == 4 else 1
            if len(key) == 8:
                key += [0] * 8
            if (len(key) != 16 or len(block) != 8 or count < 1
                    or op.endswith("-n") != (len(fields) == 4)):
                raise ValueError
        except ValueError:
            print("error lengths", flush=True)
            continue
        step = module.DecryptFEALNX if op.startswith("dec") else module.EncryptFEALNX
        # The module prints its complaints; they go to stderr here.
        stdout, sys.stdout = sys.stdout, sys.stderr
        try:
            for _ in range(count):
                block = step(block, key, rounds)
        finally:
            sys.stdout = stdout
        print(bytes(block).hex(), flush=True)


if __name__ == "__main__":
    main()
