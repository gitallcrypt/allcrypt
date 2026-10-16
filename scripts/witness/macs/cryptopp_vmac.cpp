// Crypto++ 8.9.0's VMAC as a witness: `vmac <cipher> <key> <nonce> <msg>
// <tag bytes>` per line, hex, "-" for empty; the tag in hex, or "error
// ...". The nonce is passed as the IV, at its own length.
#include <iostream>
#include <sstream>
#include <string>

#include "cryptlib.h"
#include "vmac.h"
#include "aes.h"
#include "twofish.h"
#include "serpent.h"
#include "camellia.h"
#include "aria.h"
#include "seed.h"
#include "sm4.h"
#include "hex.h"
#include "filters.h"

using namespace CryptoPP;

static std::string unhex(const std::string &text) {
    if (text == "-") return std::string();
    std::string out;
    StringSource(text, true, new HexDecoder(new StringSink(out)));
    return out;
}

template <class C, int Bits>
static std::string tag(const std::string &key, const std::string &nonce, const std::string &msg) {
    VMAC<C, Bits> mac;
    mac.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                     reinterpret_cast<const byte *>(nonce.data()), nonce.size());
    mac.Update(reinterpret_cast<const byte *>(msg.data()), msg.size());
    std::string out(mac.DigestSize(), '\0');
    mac.Final(reinterpret_cast<byte *>(&out[0]));
    std::string hex;
    StringSource(out, true, new HexEncoder(new StringSink(hex), false));
    return hex;
}

template <class C>
static std::string either(int bytes, const std::string &k, const std::string &n, const std::string &m) {
    if (bytes == 8) return tag<C, 64>(k, n, m);
    if (bytes == 16) return tag<C, 128>(k, n, m);
    return "error tag length";
}

static std::string answer(const std::string &line) {
    std::istringstream in(line);
    std::string op, cipher, k, n, m;
    int bytes = 0;
    if (!(in >> op >> cipher >> k >> n >> m >> bytes) || op != "vmac") return "error request";
    try {
        std::string key = unhex(k), nonce = unhex(n), msg = unhex(m);
        if (cipher == "aes") return either<AES>(bytes, key, nonce, msg);
        if (cipher == "twofish") return either<Twofish>(bytes, key, nonce, msg);
        if (cipher == "serpent") return either<Serpent>(bytes, key, nonce, msg);
        if (cipher == "camellia") return either<Camellia>(bytes, key, nonce, msg);
        if (cipher == "aria") return either<ARIA>(bytes, key, nonce, msg);
        if (cipher == "seed") return either<SEED>(bytes, key, nonce, msg);
        if (cipher == "sm4") return either<SM4>(bytes, key, nonce, msg);
        return "error unsupported";
    } catch (const Exception &e) {
        std::string what = e.what();
        for (auto &c : what) if (c == '\n') c = ' ';
        return "error " + what;
    }
}

int main() {
    std::ios::sync_with_stdio(false);
    for (std::string line; std::getline(std::cin, line);) {
        std::cout << answer(line) << "\n" << std::flush;
    }
    return 0;
}
