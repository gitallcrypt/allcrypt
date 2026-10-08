// lcgwitness NAME SEED SKIP COUNT
//
// Seeds the named generator the way its own library does, discards SKIP
// outputs and prints the next COUNT, one per line in decimal. Each
// generator is the library's code, not a re-implementation: libstdc++'s
// engines, and the C sources build.sh fetched and compiled.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>

#include "pcg_variants.h"

extern "C" {
void musl_srand(unsigned);
int musl_rand(void);
void newlib_srand(unsigned);
int newlib_rand(void);
void wine_srand(unsigned);
int wine_rand(void);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        std::fprintf(stderr, "usage: lcgwitness NAME SEED SKIP COUNT\n");
        return 2;
    }
    const char *name = argv[1];
    unsigned long long seed = std::strtoull(argv[2], nullptr, 10);
    unsigned long long skip = std::strtoull(argv[3], nullptr, 10);
    unsigned long long count = std::strtoull(argv[4], nullptr, 10);

    std::minstd_rand0 minstd0;
    std::minstd_rand minstd;
    pcg_state_64 pcg;
    std::function<unsigned long long()> next;

    // The C functions take an unsigned int, and the conversion here is the
    // one a C caller's argument would undergo.
    if (!std::strcmp(name, "minstd_rand0")) {
        minstd0.seed(seed);
        next = [&] { return (unsigned long long)minstd0(); };
    } else if (!std::strcmp(name, "minstd_rand")) {
        minstd.seed(seed);
        next = [&] { return (unsigned long long)minstd(); };
    } else if (!std::strcmp(name, "musl")) {
        musl_srand((unsigned)seed);
        next = [] { return (unsigned long long)musl_rand(); };
    } else if (!std::strcmp(name, "newlib")) {
        newlib_srand((unsigned)seed);
        next = [] { return (unsigned long long)newlib_rand(); };
    } else if (!std::strcmp(name, "msvc")) {
        wine_srand((unsigned)seed);
        next = [] { return (unsigned long long)wine_rand(); };
    } else if (!std::strcmp(name, "mmix")) {
        // The state itself is the output: PCG permutes it afterwards, and
        // that permutation is PCG, not the LCG underneath.
        pcg.state = seed;
        next = [&] { pcg_oneseq_64_step_r(&pcg); return (unsigned long long)pcg.state; };
    } else {
        std::fprintf(stderr, "unknown generator %s\n", name);
        return 2;
    }
    for (unsigned long long i = 0; i < skip; i++) next();
    for (unsigned long long i = 0; i < count; i++) std::printf("%llu\n", next());
    return 0;
}
