"""OpenTitan's Python PRESENT (lowRISC/opentitan, util/design/lib/Present.py,
the pypresent of Oosterlynck and Teuwen ported to Python 3) as a witness,
speaking ../nessie/driver.h's request format on stdin:

    enc <key hex> <block hex>          one block
    dec <key hex> <block hex>
    enc-n <key hex> <block hex> <n>    the block encrypted n times over
    dec-n <key hex> <block hex> <n>

    python3 -I opentitan_driver.py <directory of Present.py>

The module works on integers; a key of 10 or 16 bytes and a block are
read as big-endian byte strings of them, the specification's order, and
an answer is written the same way.
"""

import importlib.util
import os
import sys


def main():
    path = os.path.join(sys.argv[1], "Present.py")
    spec = importlib.util.spec_from_file_location("Present", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 3 or fields[0] not in ("enc", "dec", "enc-n", "dec-n"):
            print("error op", flush=True)
            continue
        op = fields[0]
        try:
            key, block = bytes.fromhex(fields[1]), bytes.fromhex(fields[2])
            count = int(fields[3]) if op.endswith("-n") and len(fields) == 4 else 1
            if (len(block) != 8 or len(key) not in (10, 16) or count < 1
                    or op.endswith("-n") != (len(fields) == 4)):
                raise ValueError
            cipher = module.Present(int.from_bytes(key, "big"), keylen=8 * len(key))
        except Exception:
            print("error lengths", flush=True)
            continue
        value = int.from_bytes(block, "big")
        step = cipher.decrypt if op.startswith("dec") else cipher.encrypt
        for _ in range(count):
            value = step(value)
        print(value.to_bytes(8, "big").hex(), flush=True)


if __name__ == "__main__":
    main()
