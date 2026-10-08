/* What Wine's srand and rand need from msvcrt.h: the calling convention
   (empty off Windows), MSVC's RAND_MAX, and a thread-data record whose
   random_seed is the 32 bit unsigned int msvcrt.h declares. */
#include <stdlib.h>
#undef RAND_MAX
#define RAND_MAX 0x7fff
#define CDECL
typedef struct { unsigned int random_seed; } thread_data_t;
static thread_data_t witness_thread_data;
#define msvcrt_get_thread_data() (&witness_thread_data)
