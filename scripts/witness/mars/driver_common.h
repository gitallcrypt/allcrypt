// The request loop both MARS witnesses share. Each driver defines
//
//     struct Witness { void set_key(const byte *, size_t);
//                      void encrypt(byte *); void decrypt(byte *); };
//
// over its implementation and includes this. One request per line on
// stdin, answered with one line of hex or `error ...`:
//
//     enc <key hex> <block hex>    one block
//     dec <key hex> <block hex>
//     mct-enc <key hex> <block hex> [<outer> <inner>]
//     mct-dec <key hex> <block hex> [<outer> <inner>]
//
// mct-* is the Monte Carlo test of Crypto++'s datatest.cpp
// (EncryptionMCT, DecryptionMCT): 400 times, process the block 10,000
// times in place under one key, then XOR the key with the last key-length
// bytes of those outputs and set it again. The answer is the final block.
// The two counts can be given, for a shorter test of the same shape;
// the inner one is at least 4, so the key always takes whole outputs of
// that pass.
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::vector<byte> unhex(const std::string &s) {
    std::vector<byte> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((byte)std::stoul(s.substr(i, 2), nullptr, 16));
    return out;
}

static std::string hex(const byte *p, size_t n) {
    static const char *d = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; i++) {
        out += d[p[i] >> 4];
        out += d[p[i] & 15];
    }
    return out;
}

static void monte_carlo(bool decrypt, std::vector<byte> key, byte block[16],
                        int outer, int inner) {
    Witness w;
    w.set_key(key.data(), key.size());
    std::vector<byte> tail(key.size());
    for (int i = 0; i < outer; i++) {
        for (int j = 0; j < inner; j++) {
            if (decrypt) w.decrypt(block); else w.encrypt(block);
            // The last key.size() bytes of everything output so far: the
            // final block, preceded by the end of the one before it.
            if (j >= inner - (int)((key.size() + 15) / 16)) {
                size_t before = (size_t)(inner - 1 - j) * 16;
                for (size_t b = 0; b < 16; b++) {
                    size_t from_end = before + 16 - b;
                    if (from_end <= key.size()) tail[key.size() - from_end] = block[b];
                }
            }
        }
        for (size_t b = 0; b < key.size(); b++) key[b] ^= tail[b];
        w.set_key(key.data(), key.size());
    }
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string op, k, b;
        int outer = 400, inner = 10000;
        in >> op >> k >> b;
        if (!(in >> outer >> inner)) {
            outer = 400;
            inner = 10000;
        }
        std::vector<byte> key = unhex(k), block = unhex(b);
        if (key.size() < 16 || key.size() > 56 || key.size() % 4 || block.size() != 16
            || outer < 1 || inner < 4) {
            std::cout << "error lengths" << std::endl;
            continue;
        }
        if (op == "enc" || op == "dec") {
            Witness w;
            w.set_key(key.data(), key.size());
            if (op == "enc") w.encrypt(block.data()); else w.decrypt(block.data());
        } else if (op == "mct-enc" || op == "mct-dec") {
            monte_carlo(op == "mct-dec", key, block.data(), outer, inner);
        } else {
            std::cout << "error op" << std::endl;
            continue;
        }
        std::cout << hex(block.data(), 16) << std::endl;
    }
    return 0;
}
