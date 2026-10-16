"""inmcm's Python Simon and Speck (inmcm/Simon_Speck_Ciphers) as a
witness, speaking ../nessie/driver.h's request format on stdin:

    enc <key hex> <block hex>          one block
    dec <key hex> <block hex>
    enc-n <key hex> <block hex> <n>    the block encrypted n times over
    dec-n <key hex> <block hex> <n>

    python3 -I inmcm_driver.py <directory of simon.py and speck.py> simon|speck <block bits>

The reference works on the paper's integers. A key and a block are read
as little-endian byte strings of them, and an answer written the same
way: the encoding the designers gave, the Linux kernel's and Crypto++'s.
"""

import importlib.util
import os
import sys


def load(directory, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    directory, family, block_bits = sys.argv[1], sys.argv[2], int(sys.argv[3])
    cipher_class = getattr(load(directory, family), family.capitalize() + "Cipher")
    block_bytes = block_bits // 8
    for line in sys.stdin:
        fields = line.split()
        if len(fields) < 3 or fields[0] not in ("enc", "dec", "enc-n", "dec-n"):
            print("error op", flush=True)
            continue
        op = fields[0]
        try:
            key, block = bytes.fromhex(fields[1]), bytes.fromhex(fields[2])
            count = int(fields[3]) if op.endswith("-n") and len(fields) == 4 else 1
            if len(block) != block_bytes or count < 1 or (op.endswith("-n") != (len(fields) == 4)):
                raise ValueError
            # The reference prints a message and re-raises on a size it
            # does not know; its message goes to stderr here.
            stdout, sys.stdout = sys.stdout, sys.stderr
            try:
                cipher = cipher_class(int.from_bytes(key, "little"), key_size=8 * len(key),
                                      block_size=block_bits)
            finally:
                sys.stdout = stdout
        except Exception:
            print("error lengths", flush=True)
            continue
        value = int.from_bytes(block, "little")
        step = cipher.decrypt if op.startswith("dec") else cipher.encrypt
        for _ in range(count):
            value = step(value)
        print(value.to_bytes(block_bytes, "little").hex(), flush=True)


if __name__ == "__main__":
    main()
