// Crypto++ 8.9.0's eSTREAM software-profile ciphers as a witness:
// `stream <cipher> <key hex> <iv hex> <length>` per line, "-" for an
// empty IV; the first <length> bytes of keystream in hex, or "error ...".
// Ciphers: rabbit (no IV), rabbit-iv (8 byte IV), hc128, hc256, sosemanuk.
// The key, IV and keystream are in exact-size heap buffers at an offset of
// OFFSET bytes (0 unless -DOFFSET=1).
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "cryptlib.h"
#include "hc128.h"
#include "hc256.h"
#include "hex.h"
#include "rabbit.h"
#include "sosemanuk.h"

using namespace CryptoPP;

#ifndef OFFSET
#define OFFSET 0
#endif

static std::vector<byte> unhex(const std::string &s) {
    std::vector<byte> out;
    if (s == "-") return out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) out.push_back((byte)std::stoi(s.substr(i, 2), nullptr, 16));
    return out;
}

template <class C>
static std::string run(const std::vector<byte> &key, const std::vector<byte> &iv, size_t n, bool with_iv) {
    typename C::Encryption e;
    byte *k = new byte[key.size() + OFFSET + 1], *v = new byte[iv.size() + OFFSET + 1];
    std::copy(key.begin(), key.end(), k + OFFSET);
    std::copy(iv.begin(), iv.end(), v + OFFSET);
    if (with_iv) e.SetKeyWithIV(k + OFFSET, key.size(), v + OFFSET, iv.size());
    else e.SetKey(k + OFFSET, key.size());
    /* Written in pieces of 1, 2, 3 .. bytes. */
    byte *out = new byte[n + OFFSET + 1];
    for (size_t at = 0, piece = 1; at < n; piece++) {
        size_t take = std::min(piece, n - at);
        e.GenerateBlock(out + OFFSET + at, take);
        at += take;
    }
    std::string text;
    char b[3];
    for (size_t i = 0; i < n; i++) { snprintf(b, sizeof b, "%02x", out[OFFSET + i]); text += b; }
    delete[] out;
    delete[] k;
    delete[] v;
    return text;
}

int main() {
    std::ios::sync_with_stdio(false);
    for (std::string line; std::getline(std::cin, line);) {
        std::istringstream in(line);
        std::string op, cipher, k, v;
        size_t n;
        std::string answer;
        if (!(in >> op >> cipher >> k >> v >> n) || op != "stream") {
            answer = "error request";
        } else {
            auto key = unhex(k), iv = unhex(v);
            try {
                if (cipher == "rabbit" && iv.empty()) answer = run<Rabbit>(key, iv, n, false);
                else if (cipher == "rabbit-iv") answer = run<RabbitWithIV>(key, iv, n, true);
                else if (cipher == "hc128") answer = run<HC128>(key, iv, n, true);
                else if (cipher == "hc256") answer = run<HC256>(key, iv, n, true);
                else if (cipher == "sosemanuk") answer = run<Sosemanuk>(key, iv, n, true);
                else answer = "error unsupported";
            } catch (const Exception &e) {
                answer = std::string("error ") + e.what();
            }
        }
        std::cout << answer << "\n" << std::flush;
    }
}
