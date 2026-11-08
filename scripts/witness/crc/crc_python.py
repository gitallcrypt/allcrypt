#!/usr/bin/env python3
"""The Python CRC witnesses, one per run, chosen by the first argument:

    pycrc-bbb   pycrc 0.10.0, its bit-by-bit algorithm
    pycrc-bbf   pycrc 0.10.0, its bit-by-bit-fast algorithm
    pycrc-tbl   pycrc 0.10.0, its table-driven algorithm
    crccheck    crccheck 1.3.0's CrcBase, subclassed with the parameters
    crcmod      crcmod 1.7 through its C extension, which this refuses to
                run without: widths 8, 16, 24, 32 and 64 with
                the input and output reflected alike only; its initCrc is
                the register's starting value XOR xorout, and a reflected
                CRC's register is reflected, so the catalogue's init is
                reflected first

The second is the directory the packages were installed into. One request
per line:

    crc <width> <poly> <init> <refin> <refout> <xorout> <data>

poly, init and xorout in hex, refin and refout 0 or 1, data hex or "-".
The answer is the CRC in hex, ceil(width / 8) bytes, or "error ...".
"""

import sys

IMPLEMENTATION = sys.argv[1]
sys.path.insert(0, sys.argv[2])


def pycrc(algorithm):
    from pycrc.algorithms import Crc

    def run(width, poly, init, refin, refout, xorout, data):
        crc = Crc(width=width, poly=poly, reflect_in=refin, xor_in=init,
                  reflect_out=refout, xor_out=xorout)
        if algorithm == "tbl" and width < 8:
            raise ValueError("unsupported")
        return getattr(crc, {"bbb": "bit_by_bit", "bbf": "bit_by_bit_fast",
                             "tbl": "table_driven"}[algorithm])(data)
    return run


def crccheck(width, poly, init, refin, refout, xorout, data):
    from crccheck.crc import CrcBase

    class Custom(CrcBase):
        _width = width
        _poly = poly
        _initvalue = init
        _reflect_input = refin
        _reflect_output = refout
        _xor_output = xorout
    return Custom.calc(data)


def crcmod(width, poly, init, refin, refout, xorout, data):
    import crcmod as module
    if not sys.modules["crcmod.crcmod"]._usingExtension:
        sys.exit("crcmod's C extension did not load")
    if width not in (8, 16, 24, 32, 64) or refin != refout:
        raise ValueError("unsupported")
    if refin:
        init = int(f"{init:0{width}b}"[::-1], 2)
    fun = module.mkCrcFun((1 << width) | poly, initCrc=init ^ xorout, rev=refin,
                          xorOut=xorout)
    return fun(data)


RUN = {"pycrc-bbb": pycrc("bbb"), "pycrc-bbf": pycrc("bbf"), "pycrc-tbl": pycrc("tbl"),
       "crccheck": crccheck, "crcmod": crcmod}[IMPLEMENTATION]


def main():
    for line in sys.stdin:
        f = line.split()
        try:
            if len(f) != 8 or f[0] != "crc":
                raise ValueError("request")
            width = int(f[1])
            args = (width, int(f[2], 16), int(f[3], 16), f[4] == "1", f[5] == "1",
                    int(f[6], 16), b"" if f[7] == "-" else bytes.fromhex(f[7]))
            value = RUN(*args)
            print(value.to_bytes((width + 7) // 8, "big").hex(), flush=True)
        except ValueError as e:
            print(f"error {e}", flush=True)


if __name__ == "__main__":
    main()
