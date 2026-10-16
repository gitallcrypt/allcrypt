// Crypto++'s CMAC and EAX over the wide-block ciphers, as a witness.
//
// One request per line on stdin, one answer per line on stdout:
//
//     cmac <cipher> <key hex> <message hex>                 -> tag
//     eax  <cipher> <key hex> <nonce hex> <ad hex> <pt hex> -> ciphertext tag
//
// An empty field is "-". The answer is hex, or "error unsupported" for a
// cipher this library lacks, or "error <what>" for anything it refused.
// The cipher is named as allcrypt names it.
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "cryptlib.h"
#include "cmac.h"
#include "eax.h"
#include "hex.h"
#include "filters.h"
#include "kalyna.h"
#include "shacal2.h"
#include "threefish.h"

using namespace CryptoPP;

static std::string unhex(const std::string &text) {
    if (text == "-") return std::string();
    std::string out;
    StringSource(text, true, new HexDecoder(new StringSink(out)));
    return out;
}

static std::string hex(const std::string &bytes) {
    if (bytes.empty()) return "-";
    std::string out;
    StringSource(bytes, true, new HexEncoder(new StringSink(out), false));
    return out;
}

template <class C>
static std::string cmac(const std::string &key, const std::string &msg) {
    CMAC<C> mac(reinterpret_cast<const byte *>(key.data()), key.size());
    mac.Update(reinterpret_cast<const byte *>(msg.data()), msg.size());
    std::string tag(mac.DigestSize(), '\0');
    mac.Final(reinterpret_cast<byte *>(&tag[0]));
    return hex(tag);
}

template <class C>
static std::string eax(const std::string &key, const std::string &nonce,
                       const std::string &ad, const std::string &pt) {
    // Keyed with the nonce and then fed, not through EncryptAndAuthenticate:
    // that resynchronises a second time, and EAX_Base::Resync does not
    // restart the CMAC it feeds, so after SetKeyWithIV it gives the wrong
    // ciphertext and tag for every block cipher. Over AES with a key of
    // sixteen 0x11 bytes, nonce 00 and plaintext 61 it gives ciphertext 1d;
    // this path, Botan and Bouncy Castle give 23.
    typename EAX<C>::Encryption enc;
    enc.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                     reinterpret_cast<const byte *>(nonce.data()), nonce.size());
    enc.Update(reinterpret_cast<const byte *>(ad.data()), ad.size());
    std::string ct(pt.size(), '\0');
    enc.ProcessData(reinterpret_cast<byte *>(&ct[0]),
                    reinterpret_cast<const byte *>(pt.data()), pt.size());
    std::string tag(enc.DigestSize(), '\0');
    enc.TruncatedFinal(reinterpret_cast<byte *>(&tag[0]), tag.size());
    return hex(ct) + " " + hex(tag);
}

#define DISPATCH(FN, ...)                                                   \
    if (cipher == "threefish256") return FN<Threefish256>(__VA_ARGS__);     \
    if (cipher == "threefish512") return FN<Threefish512>(__VA_ARGS__);     \
    if (cipher == "threefish1024") return FN<Threefish1024>(__VA_ARGS__);   \
    if (cipher == "shacal2") return FN<SHACAL2>(__VA_ARGS__);               \
    if (cipher == "kalyna-256") return FN<Kalyna256>(__VA_ARGS__);          \
    if (cipher == "kalyna-512") return FN<Kalyna512>(__VA_ARGS__);          \
    return "error unsupported";

static std::string answer(const std::string &line) {
    std::istringstream in(line);
    std::string op, cipher;
    in >> op >> cipher;
    std::vector<std::string> fields;
    for (std::string f; in >> f;) fields.push_back(unhex(f));
    try {
        if (op == "cmac" && fields.size() == 2) {
            DISPATCH(cmac, fields[0], fields[1])
        }
        if (op == "eax" && fields.size() == 4) {
            DISPATCH(eax, fields[0], fields[1], fields[2], fields[3])
        }
        return "error op";
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
