#!/usr/bin/env python3
"""
A virtual smart card on a TCP port, for checking
`examples/products/smartcard` without hardware.

The card is CanoKey's `apdu-replay` (canokey-core built with
-DENABLE_APDU_REPLAY=ON): PIV, OpenPGP card and OATH in one process, with
state kept across commands the way a card keeps it. This script holds one
such process and serves its line protocol to consecutive TCP clients:

    -> 00A4040007A0000005272101          one APDU, hex
    <- RESP 9000790300...                status word, then the data

When a client disconnects, or sends `!POWEROFF`, the card is powered off,
which forgets PIN verification and the selected application.

CanoKey has no YubiKey OTP application (`A0 00 00 05 27 20 01`), so this
script answers for one: SELECT returns a status block, slots 1 and 2 take
a 52-byte HMAC-SHA1 configuration, and a challenge is answered with the
HMAC the configuration asks for. That half is written here from yubikit's
reading of the format and checks nothing by itself; what checks the
example's OTP code is that yubikit and the example send it the same
bytes, which `scripts/check_smartcard.py` compares.

    python3 cardsim.py --card /opt/canokey/apdu-replay --port 35963 [--log FILE]
"""

import argparse
import hashlib
import hmac
import socket
import subprocess
import sys

OTP_AID = bytes.fromhex("A0000005272001")


def crc16(data):
    """ISO/IEC 13239: reflected 0x8408 from 0xFFFF; a block with its
    complemented CRC appended leaves 0xF0B8."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


def command_data(apdu):
    """The data field of a short or an extended-length APDU (yubikit sends
    the latter to a card it believes is a recent YubiKey)."""
    if len(apdu) <= 5:
        return b""
    if apdu[4] == 0 and len(apdu) >= 7:
        length = int.from_bytes(apdu[5:7], "big")
        return apdu[7:7 + length]
    return apdu[5:5 + apdu[4]]


class OtpApplication:
    """The YubiKey OTP application's challenge-response half."""

    VERSION = bytes([5, 4, 3])
    SERIAL = 0x00C0FFEE

    def __init__(self):
        self.sequence = 0
        self.slots = {}

    def status(self):
        touch_level = 0x0003 if self.slots else 0
        return self.VERSION + bytes([self.sequence]) + touch_level.to_bytes(2, "little")

    def process(self, apdu):
        """The answer to one command as (sw, data)."""
        cla, ins, p1, p2 = apdu[:4]
        data = command_data(apdu)
        if ins == 0x03:
            return 0x9000, self.status()
        if ins != 0x01:
            return 0x6D00, b""
        if p1 == 0x10:
            return 0x9000, self.SERIAL.to_bytes(4, "big")
        if p1 in (0x01, 0x03):
            config = data[:52]
            if len(config) != 52 or crc16(config) != 0xF0B8:
                return 0x6A80, b""
            # fixed(16) uid(6) key(16) acc_code(6) fixed_size ext tkt cfg rfu(2) crc(2)
            uid, key, ticket, cfg = config[16:22], config[22:38], config[46], config[47]
            self.slots[1 if p1 == 0x01 else 2] = {
                "key": key + uid[:4],
                "lt64": bool(cfg & 0x04),
                "hmac": (cfg & 0x22) == 0x22 and bool(ticket & 0x40),
            }
            self.sequence += 1
            return 0x9000, self.status()
        if p1 in (0x30, 0x38):
            slot = self.slots.get(1 if p1 == 0x30 else 2)
            if not slot or not slot["hmac"] or len(data) != 64:
                return 0x6A80, b""
            challenge = data
            if slot["lt64"]:
                challenge = challenge.rstrip(challenge[-1:])
            return 0x9000, hmac.new(slot["key"], challenge, hashlib.sha1).digest()
        return 0x6A86, b""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--card", required=True)
    parser.add_argument("--port", type=int, default=35963)
    parser.add_argument("--log", help="append every exchange to this file")
    args = parser.parse_args()

    card = subprocess.Popen([args.card], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1)
    if card.stdout.readline().strip() != "READY":
        sys.exit("the card did not start")
    log = open(args.log, "a") if args.log else None
    otp = OtpApplication()

    def power_off():
        card.stdin.write("!POWEROFF\n")
        card.stdin.flush()
        return card.stdout.readline()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    print(f"listening on 127.0.0.1:{args.port}", flush=True)
    while True:
        connection, _ = server.accept()
        stream = connection.makefile("rw", newline="\n")
        otp_selected = False
        for line in stream:
            line = line.strip()
            if not line:
                continue
            if line == "!POWEROFF":
                otp_selected = False
                answer = power_off()
            else:
                apdu = bytes.fromhex(line)
                if apdu[1:3] == b"\xA4\x04":
                    otp_selected = command_data(apdu) == OTP_AID
                if otp_selected:
                    sw, data = (0x9000, otp.status()) if apdu[1] == 0xA4 else otp.process(apdu)
                    answer = f"RESP {sw:04X}{data.hex().upper()}\n"
                else:
                    card.stdin.write(line + "\n")
                    card.stdin.flush()
                    answer = card.stdout.readline()
            if log:
                log.write(f"> {line}\n< {answer}")
                log.flush()
            stream.write(answer)
            stream.flush()
        power_off()
        connection.close()


if __name__ == "__main__":
    main()
