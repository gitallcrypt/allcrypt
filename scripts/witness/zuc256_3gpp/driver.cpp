// Drives TS 35.246 Annex A's NEA6_256, NIA6_256 and NCA6_256 from stdin,
// one case a line, every byte string in hex and "-" for none:
//
//   nea KEY COUNT BEARER DIRECTION EXTRA_IV BITS DATA          -> OBS
//   nia KEY COUNT BEARER DIRECTION EXTRA_IV MAC_BYTES BITS DATA -> MAC
//   nca KEY COUNT BEARER DIRECTION EXTRA_IV MAC_BYTES AAD_BITS AAD BITS DATA
//                                                              -> OBS MAC
//   ncad KEY COUNT BEARER DIRECTION EXTRA_IV AAD_BITS AAD BITS DATA MAC
//                                                    -> OBS, or "refused"
//
// COUNT, BEARER, DIRECTION and the lengths are decimal. A key of 16
// bytes is passed as KEY_BYTES 16. Every buffer is copied to a heap
// block at the offset argv[1] gives (default 0), so 1 misaligns them all.
#include "annex_a.cpp"
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

static size_t offset = 0;

struct Buffer {
    std::vector<u8> bytes;
    u8 * base = nullptr;
    u8 * at = nullptr;
    size_t size = 0;
    explicit Buffer(const std::vector<u8> & from, size_t extra = 0) : bytes(from) {
        size = from.size();
        base = (u8 *)malloc(size + extra + offset + 1);
        at = base + offset;
        if (size) memcpy(at, from.data(), size);
    }
    ~Buffer() { free(base); }
    u8 * ptr() { return size ? at : nullptr; }
};

static std::vector<u8> unhex(const char * s) {
    std::vector<u8> out;
    if (!strcmp(s, "-")) return out;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
        unsigned v;
        sscanf(s + i, "%2x", &v);
        out.push_back((u8)v);
    }
    return out;
}

static void hex(const u8 * p, size_t n) {
    if (!n) { printf("-"); return; }
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(int argc, char ** argv) {
    if (argc > 1) offset = (size_t)atoi(argv[1]);
    char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        std::vector<std::string> f;
        for (char * t = strtok(line, " \n"); t; t = strtok(nullptr, " \n")) f.push_back(t);
        if (f.empty()) continue;
        Buffer key(unhex(f[1].c_str()));
        u32 count = (u32)strtoul(f[2].c_str(), nullptr, 10);
        u8 bearer = (u8)atoi(f[3].c_str()), direction = (u8)atoi(f[4].c_str());
        Buffer extra(unhex(f[5].c_str()));
        if (f[0] == "nea") {
            u32 bits = (u32)strtoul(f[6].c_str(), nullptr, 10);
            Buffer in(unhex(f[7].c_str())), out{std::vector<u8>(in.size)};
            NEA6_256(count, extra.ptr(), direction, bearer, key.ptr(), (u8)key.size,
                     in.ptr(), out.ptr(), bits);
            hex(out.ptr(), out.size);
        } else if (f[0] == "nia") {
            u8 mac_bytes = (u8)atoi(f[6].c_str());
            u32 bits = (u32)strtoul(f[7].c_str(), nullptr, 10);
            Buffer in(unhex(f[8].c_str())), mac{std::vector<u8>(mac_bytes)};
            NIA6_256(count, extra.ptr(), direction, bearer, key.ptr(), (u8)key.size,
                     in.ptr(), bits, mac.ptr(), mac_bytes);
            hex(mac.ptr(), mac.size);
        } else if (f[0] == "nca") {
            u8 mac_bytes = (u8)atoi(f[6].c_str());
            u32 aad_bits = (u32)strtoul(f[7].c_str(), nullptr, 10);
            Buffer aad(unhex(f[8].c_str()));
            u32 bits = (u32)strtoul(f[9].c_str(), nullptr, 10);
            Buffer in(unhex(f[10].c_str())), out{std::vector<u8>(in.size)};
            Buffer mac{std::vector<u8>(mac_bytes)};
            NCA6_256(0, count, extra.ptr(), direction, bearer, key.ptr(), (u8)key.size,
                     mac.ptr(), mac_bytes, aad.ptr(), aad_bits, in.ptr(), out.ptr(), bits);
            hex(out.ptr(), out.size);
            printf(" ");
            hex(mac.ptr(), mac.size);
        } else if (f[0] == "ncad") {
            u32 aad_bits = (u32)strtoul(f[6].c_str(), nullptr, 10);
            Buffer aad(unhex(f[7].c_str()));
            u32 bits = (u32)strtoul(f[8].c_str(), nullptr, 10);
            Buffer in(unhex(f[9].c_str())), out{std::vector<u8>(in.size)};
            Buffer mac(unhex(f[10].c_str()));
            int r = NCA6_256(1, count, extra.ptr(), direction, bearer, key.ptr(), (u8)key.size,
                             mac.ptr(), (u8)mac.size, aad.ptr(), aad_bits, in.ptr(), out.ptr(),
                             bits);
            if (r < 0) printf("refused");
            else hex(out.ptr(), out.size);
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
