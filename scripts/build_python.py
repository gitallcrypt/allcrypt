#!/usr/bin/env python3
"""Build the Python extension module with cargo. No maturin needed.

    python3 scripts/build_python.py            # release build into python/
    python3 scripts/build_python.py --debug    # faster to build, slow to run
    python3 scripts/build_python.py --install  # also into site-packages

    # Faster, for this machine or ones like it (docs/building.md,
    # "Building for speed"):
    python3 scripts/build_python.py --target-cpu x86-64-v3 --features aes-ni,sha-ni

Then either run from the repository root, where `python/` is already on
the path for the scripts here, or set it yourself:

    # Linux and macOS
    export PYTHONPATH=$PWD/python
    # Windows, cmd
    set PYTHONPATH=%CD%\\python
    # Windows, PowerShell
    $env:PYTHONPATH = "$PWD\\python"

## Why this exists

maturin is the usual way to build a PyO3 extension, and it is a perfectly
good tool - it builds wheels, handles metadata, uploads to PyPI. None of
that is needed to import a module locally, and it is one more thing to
install before anybody can run anything.

The crate is already `crate-type = ["cdylib"]`, so **cargo builds a
loadable Python module by itself**. The only thing maturin adds for local
use is renaming the file and putting it somewhere importable, which is
what this does:

    Linux    target/release/liballcrypt.so     -> python/allcrypt.so
    macOS    target/release/liballcrypt.dylib  -> python/allcrypt.so
    Windows  target/release/allcrypt.dll       -> python/allcrypt.pyd

That is the whole of it. Python imports a module by file name, and cargo's
name is not the one it looks for - on Windows it is not even the right
extension.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import sysconfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESTINATION = os.path.join(ROOT, "python")


def artifact_names():
    """(what cargo writes, what Python wants to import) for this platform."""
    if sys.platform == "win32":
        # No "lib" prefix on Windows, and the extension has to be .pyd -
        # Python will not import a .dll by that name.
        return "allcrypt.dll", "allcrypt.pyd"
    if sys.platform == "darwin":
        # cargo writes a .dylib; Python wants .so even on macOS.
        return "liballcrypt.dylib", "allcrypt.so"
    return "liballcrypt.so", "allcrypt.so"


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--debug", action="store_true",
                        help="debug build: quick to compile, much slower to "
                             "run (the bignum code especially)")
    parser.add_argument("--install", action="store_true",
                        help="also copy into site-packages, so `import "
                             "allcrypt` works from anywhere")
    parser.add_argument("--offline", action="store_true",
                        help="pass --offline to cargo, for a vendored build")
    parser.add_argument("--features", default="",
                        help="extra cargo features of the allcrypt crate, "
                             "comma separated - `aes-ni` and `sha-ni` for "
                             "the hardware AES and SHA paths")
    parser.add_argument("--target-cpu", default="",
                        help="compile for this CPU level or model, e.g. "
                             "x86-64-v3 (AVX2) - the result does not run on "
                             "older processors")
    args = parser.parse_args()

    profile = "debug" if args.debug else "release"
    if args.target_cpu:
        # Appended to whatever RUSTFLAGS already holds. Changing RUSTFLAGS
        # rebuilds everything, once.
        flags = os.environ.get("RUSTFLAGS", "")
        os.environ["RUSTFLAGS"] = f"{flags} -C target-cpu={args.target_cpu}".strip()
        print(f"RUSTFLAGS={os.environ['RUSTFLAGS']}")
    extra = [f for f in args.features.split(",") if f]
    shared = []
    if not args.debug:
        shared.append("--release")
    if args.offline or os.environ.get("CARGO_NET_OFFLINE") == "true":
        shared.append("--offline")

    # **Two invocations, and they cannot be one.**
    #
    # This is a workspace, and `cargo build --features python` applies
    # the feature to everything in it. The shim depends on `allcrypt`,
    # so it would be linked against the pyo3-enabled build and come out
    # with undefined Python symbols - at which point `LD_PRELOAD`ing it
    # fails with
    #
    #     symbol lookup error: libssl.so: undefined symbol: PyBaseObject_Type
    #
    # and the shimmed program carries on against the real OpenSSL,
    # working perfectly. `pytests/test_shim.py` catches that only
    # because every test there asserts the shim was in the path.
    #
    # Separate invocations because feature unification is per build:
    # naming the package in the same command would not help.
    command = ["cargo", "build", "-p", "allcrypt", "--features",
               ",".join(["python", *extra]), *shared]
    print(f"$ {' '.join(command)}")
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        # The one failure worth explaining, because the message cargo gives
        # is about a missing symbol rather than about Python.
        if sys.platform == "win32":
            print("\nIf that failed to link against Python, point PyO3 at "
                  "your interpreter and try again:\n"
                  "    set PYO3_PYTHON=C:\\path\\to\\python.exe", file=sys.stderr)
        return result.returncode

    # The shim gets the same library features, through its dependency.
    shim = ["cargo", "build", "-p", "allcrypt-shim", *shared]
    if extra:
        shim[4:4] = ["--features", ",".join(f"allcrypt/{f}" for f in extra)]
    print(f"$ {' '.join(shim)}")
    result = subprocess.run(shim, cwd=ROOT)
    if result.returncode != 0:
        return result.returncode

    built, wanted = artifact_names()
    source = os.path.join(ROOT, "target", profile, built)
    if not os.path.exists(source):
        print(f"cargo reported success but {source} is not there.",
              file=sys.stderr)
        # Worth listing what it did write: a crate-type change would land
        # here and the message above would be baffling on its own.
        directory = os.path.dirname(source)
        if os.path.isdir(directory):
            found = [name for name in os.listdir(directory)
                     if "allcrypt" in name and not name.endswith(".d")]
            print(f"  {directory} holds: {found}", file=sys.stderr)
        return 1

    os.makedirs(DESTINATION, exist_ok=True)
    target = os.path.join(DESTINATION, wanted)
    shutil.copy2(source, target)
    print(f"\n{os.path.relpath(source, ROOT)} -> {os.path.relpath(target, ROOT)}")

    if args.install:
        packages = sysconfig.get_paths()["purelib"]
        installed = os.path.join(packages, wanted)
        try:
            shutil.copy2(source, installed)
            # The stubs and the ssl shim are plain Python and belong beside
            # it, or `import allcrypt_ssl` works from the repo and nowhere
            # else - which is a confusing way to find out.
            for extra in ("allcrypt.pyi", "allcrypt_ssl.py"):
                beside = os.path.join(DESTINATION, extra)
                if os.path.exists(beside):
                    shutil.copy2(beside, os.path.join(packages, extra))
            print(f"installed into {packages}")
        except OSError as reason:
            print(f"could not install into {packages}: {reason}\n"
                  f"(a virtualenv, or --user, would avoid needing "
                  f"permission)", file=sys.stderr)
            return 1

    # Import it, because a file in the right place is not the same as a
    # module that loads - an ABI mismatch shows up exactly here.
    sys.path.insert(0, DESTINATION)
    try:
        import allcrypt
    except ImportError as reason:
        print(f"\nbuilt, but it does not import: {reason}", file=sys.stderr)
        return 1

    print(f"imported: {len(allcrypt.algorithms_available)} hashes, "
          f"{len(allcrypt.block_ciphers_available)} block ciphers, "
          f"{len(allcrypt.aeads_available)} AEADs")
    if args.debug:
        print("\nthis is a debug build; the key generation and bignum paths "
              "are several times slower than release")
    if not args.install:
        variable = ("set PYTHONPATH=%CD%\\python" if sys.platform == "win32"
                    else "export PYTHONPATH=$PWD/python")
        print(f"\nto use it from elsewhere:  {variable}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
