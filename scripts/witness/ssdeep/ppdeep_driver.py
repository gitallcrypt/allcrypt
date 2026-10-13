"""ppdeep-witness: ppdeep (elceef/ppdeep), a pure-Python ssdeep that goes
over the input once per block size, as spamsum did.

One request per line on stdin, and one line out:

    hash PATH          the digest of the file's bytes
    compare SIG SIG    ppdeep's score, or "error" where it raises

Run as `python3 -I ppdeep_driver.py DIR` with ppdeep.py in DIR.
"""
import sys

sys.path.insert(0, sys.argv[1])
import ppdeep  # noqa: E402

for line in sys.stdin:
    op, *args = line.split()
    try:
        if op == "hash":
            print(ppdeep.hash_from_file(args[0]), flush=True)
        elif op == "compare":
            print(ppdeep.compare(args[0], args[1]), flush=True)
        else:
            print("error", flush=True)
    except Exception:  # noqa: BLE001 - a refusal is an answer here
        print("error", flush=True)
