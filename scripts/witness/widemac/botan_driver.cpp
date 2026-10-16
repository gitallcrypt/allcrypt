// Botan 3's CMAC and EAX over the wide-block ciphers it has, as a witness.
// The same request format as cryptopp_driver.cpp.
#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::vector<uint8_t> unhex(const std::string &text) {
    if (text == "-") return {};
    return Botan::hex_decode(text);
}

static std::string hex(const std::vector<uint8_t> &bytes) {
    if (bytes.empty()) return "-";
    return Botan::hex_encode(bytes, false);
}

static std::string botan_name(const std::string &cipher) {
    if (cipher == "threefish512") return "Threefish-512";
    if (cipher == "shacal2") return "SHACAL2";
    return "";
}

static std::string answer(const std::string &line) {
    std::istringstream in(line);
    std::string op, cipher;
    in >> op >> cipher;
    std::vector<std::vector<uint8_t>> f;
    for (std::string t; in >> t;) f.push_back(unhex(t));
    const std::string name = botan_name(cipher);
    if (name.empty()) return "error unsupported";
    try {
        if (op == "cmac" && f.size() == 2) {
            auto mac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(" + name + ")");
            mac->set_key(f[0]);
            mac->update(f[1]);
            auto tag = mac->final();
            return hex(std::vector<uint8_t>(tag.begin(), tag.end()));
        }
        if (op == "eax" && f.size() == 4) {
            auto mode = Botan::AEAD_Mode::create_or_throw(name + "/EAX", Botan::Cipher_Dir::Encryption);
            mode->set_key(f[0]);
            mode->set_associated_data(f[2]);
            mode->start(f[1]);
            Botan::secure_vector<uint8_t> buf(f[3].begin(), f[3].end());
            mode->finish(buf);
            const size_t tag = mode->tag_size();
            std::vector<uint8_t> ct(buf.begin(), buf.end() - tag), t(buf.end() - tag, buf.end());
            return hex(ct) + " " + hex(t);
        }
        return "error op";
    } catch (const std::exception &e) {
        std::string what = e.what();
        for (auto &c : what) if (c == '\n') c = ' ';
        return "error " + what;
    }
}

int main() {
    for (std::string line; std::getline(std::cin, line);) {
        std::cout << answer(line) << "\n" << std::flush;
    }
    return 0;
}
