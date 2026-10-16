/* What libmcrypt 2.5.8's algorithm modules take from its lib/libdefs.h
 * and win32_comp.h, for a 64-bit Unix build: the standard headers, the
 * fixed-width word types its configure script would have chosen, and
 * the export marker, empty. lib/mcrypt_modules.h, with the rotations and
 * the byte swap, is libmcrypt's own, fetched with the modules. */
#ifndef OLDCIPHERS_MCRYPT_LIBDEFS_H
#define OLDCIPHERS_MCRYPT_LIBDEFS_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t word32;
typedef int32_t sword32;
typedef uint16_t word16;
typedef uint8_t byte;

#define WIN32DLL_DEFINE
#endif
