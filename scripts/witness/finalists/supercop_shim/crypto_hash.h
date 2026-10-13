/* What SUPERCOP's build would generate for one crypto_hash
 * implementation; the driver renames crypto_hash itself. */
#include "api.h"
#define crypto_hash_BYTES CRYPTO_BYTES
int crypto_hash(unsigned char *, const unsigned char *, unsigned long long);
