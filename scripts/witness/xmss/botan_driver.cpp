// Botan 3.6.1's XMSS as a witness, under the request lines selftest.py
// describes; it has no XMSS^MT. A key is made by Botan's own key
// generation from an RNG that gives the seeds in the order it draws them -
// SEED, then SK_PRF, then SK_SEED - with SP 800-208's WOTS+ derivation, so
// Botan computes the root itself; a second key from those seeds and that
// root is set to the index asked for. Botan keeps each key's index in a
// process-wide registry that never goes back, so every signing runs in a
// child process of its own.
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/xmss.h>

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

class Given_RNG final : public Botan::RandomNumberGenerator {
   public:
      explicit Given_RNG(std::vector<uint8_t> bytes) : m_bytes(std::move(bytes)) {}
      bool accepts_input() const override { return false; }
      std::string name() const override { return "given"; }
      bool is_seeded() const override { return true; }
      void clear() override {}

   private:
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t>) override {
         if(out.size() > m_bytes.size() - m_at) {
            throw std::runtime_error("the given bytes ran out");
         }
         std::copy_n(m_bytes.begin() + m_at, out.size(), out.begin());
         m_at += out.size();
      }
      std::vector<uint8_t> m_bytes;
      size_t m_at = 0;
};

std::vector<uint8_t> unhex(const std::string& s) {
   std::vector<uint8_t> out;
   if(s == "-") {
      return out;
   }
   for(size_t i = 0; i + 1 < s.size(); i += 2) {
      out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
   }
   return out;
}

std::string hex(std::span<const uint8_t> b) {
   std::string out;
   char buf[3];
   for(uint8_t x : b) {
      std::snprintf(buf, sizeof buf, "%02x", x);
      out += buf;
   }
   return out;
}

std::string sign(const std::vector<std::string>& f) {
   if(f.size() != 6) {
      return "error request";
   }
   if(f[1] != "xmss") {
      return "error unsupported";
   }
   auto oid = static_cast<Botan::XMSS_Parameters::xmss_algorithm_t>(std::stoul(f[2]));
   Botan::XMSS_Parameters params(oid);
   const size_t n = params.element_size();
   auto seeds = unhex(f[3]);
   if(seeds.size() != 3 * n) {
      return "error request";
   }
   std::vector<uint8_t> sk_seed(seeds.begin(), seeds.begin() + n);
   std::vector<uint8_t> sk_prf(seeds.begin() + n, seeds.begin() + 2 * n);
   std::vector<uint8_t> seed(seeds.begin() + 2 * n, seeds.end());
   std::vector<uint8_t> order = seed;
   order.insert(order.end(), sk_prf.begin(), sk_prf.end());
   order.insert(order.end(), sk_seed.begin(), sk_seed.end());
   Given_RNG given(order);
   Botan::XMSS_PrivateKey first(oid, given, Botan::WOTS_Derivation_Method::NIST_SP800_208);
   auto public_key = first.raw_public_key_bits();
   // OID || root || SEED: the root is after the four byte OID.
   Botan::secure_vector<uint8_t> root(public_key.begin() + 4, public_key.begin() + 4 + n);
   Botan::XMSS_PrivateKey key(oid, std::stoull(f[4]),
                              Botan::secure_vector<uint8_t>(sk_seed.begin(), sk_seed.end()),
                              Botan::secure_vector<uint8_t>(sk_prf.begin(), sk_prf.end()), root,
                              Botan::secure_vector<uint8_t>(seed.begin(), seed.end()),
                              Botan::WOTS_Derivation_Method::NIST_SP800_208);
   Given_RNG unused({});
   Botan::PK_Signer signer(key, unused, "");
   auto sig = signer.sign_message(unhex(f[5]), unused);
   return hex(public_key) + " " + hex(sig);
}

std::string verify(const std::vector<std::string>& f) {
   if(f.size() != 5) {
      return "error request";
   }
   if(f[1] != "xmss") {
      return "error unsupported";
   }
   try {
      Botan::XMSS_PublicKey key(unhex(f[2]));
      Botan::PK_Verifier verifier(key, "");
      return verifier.verify_message(unhex(f[3]), unhex(f[4])) ? "ok" : "bad";
   } catch(const std::exception&) {
      return "bad";
   }
}

}  // namespace

int main() {
   std::string line;
   while(std::getline(std::cin, line)) {
      std::istringstream in(line);
      std::vector<std::string> f;
      for(std::string w; in >> w;) {
         f.push_back(w);
      }
      std::string out;
      if(!f.empty() && f[0] == "sign") {
         int pipes[2];
         if(pipe(pipes) != 0) {
            return 1;
         }
         std::cout.flush();
         pid_t child = fork();
         if(child == 0) {
            close(pipes[0]);
            std::string answer;
            try {
               answer = sign(f);
            } catch(const std::exception& e) {
               answer = std::string("error ") + e.what();
            }
            (void)!write(pipes[1], answer.data(), answer.size());
            _exit(0);
         }
         close(pipes[1]);
         char buf[65536];
         for(ssize_t got; (got = read(pipes[0], buf, sizeof buf)) > 0;) {
            out.append(buf, static_cast<size_t>(got));
         }
         close(pipes[0]);
         waitpid(child, nullptr, 0);
      } else if(!f.empty() && f[0] == "verify") {
         out = verify(f);
      } else {
         out = "error request";
      }
      std::cout << out << "\n" << std::flush;
   }
   return 0;
}
