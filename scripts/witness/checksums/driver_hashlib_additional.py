"""hashlib-additional's fletcher16, fletcher32 and fletcher64, and its
FNV-0, FNV-1 and FNV-1a at every size as fnvVARIANT_BITS, from its one
module, whose path is the first argument. One request per line on
stdin, "NAME PATH", answered with the checksum of the file's bytes as
lowercase big endian hex, or "error". The data goes in in pieces of 1,
2, 3 ... bytes."""

import importlib.util
import sys

spec = importlib.util.spec_from_file_location("hashlib_additional", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NAMES = {"fletcher16": module.fletcher16, "fletcher32": module.fletcher32,
         "fletcher64": module.fletcher64}
for variant in ("0", "1", "1a"):
    for bits in (32, 64, 128, 256, 512, 1024):
        NAMES[f"fnv{variant}_{bits}"] = (
            lambda make, size: lambda: make(digest_size=size)
        )(getattr(module, f"fnv{variant}"), bits // 8)

for line in sys.stdin:
    parts = line.split()
    try:
        make = NAMES[parts[0]]
        with open(parts[1], "rb") as f:
            data = f.read()
    except (IndexError, KeyError, OSError):
        print("error", flush=True)
        continue
    h = make()
    at, step = 0, 1
    while at < len(data):
        h.update(data[at:at + step])
        at, step = at + step, step + 1
    print(h.hexdigest(), flush=True)
