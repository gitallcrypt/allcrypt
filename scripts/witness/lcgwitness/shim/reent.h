/* Stand-in for newlib's <reent.h>: one static state for rand() to reach
   through the same macros newlib's own header defines. */
struct _reent { unsigned long long rand_next; };
static struct _reent witness_reent;
#define _REENT (&witness_reent)
#define _REENT_CHECK_RAND48(r) ((void)0)
#define _REENT_RAND_NEXT(r) ((r)->rand_next)
