/* The designers' NESSIE reference code fixes its key size at compile
 * time, with an unguarded `#define KEYSIZEB` that only the key setup
 * reads. That file includes <stdio.h> after the definition and before
 * the key setup, so this header, found first on the include path, turns
 * KEYSIZEB into a variable the driver sets: every key size from one
 * build, and the source compiled as fetched. */
#include_next <stdio.h>
#undef KEYSIZEB
extern int nessie_key_bytes;
#define KEYSIZEB nessie_key_bytes
