/* Stands in for cryptonite's pthread_internal.h, which its repository
 * keeps outside src/cryptonite/c: the POSIX mutex, and pthread_id as the
 * calling thread's id. */
#ifndef PTHREAD_INTERNAL_H
#define PTHREAD_INTERNAL_H
#include <pthread.h>
#define pthread_id() ((unsigned long)pthread_self())
#endif
