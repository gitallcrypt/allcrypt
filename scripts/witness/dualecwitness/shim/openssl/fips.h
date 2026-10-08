/* Stand-in for the FIPS module's <openssl/fips.h>: the Dual EC code in
 * fips_drbg_ec.c calls the module's digest wrappers, which are the
 * ordinary EVP calls of the same library underneath. */
#ifndef DUALEC_SHIM_FIPS_H
#define DUALEC_SHIM_FIPS_H
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#define FIPS_digestinit(ctx, md) EVP_DigestInit_ex((ctx), (md), NULL)
#define FIPS_digestupdate(ctx, d, n) EVP_DigestUpdate((ctx), (d), (n))
#define FIPS_digestfinal(ctx, out, n) EVP_DigestFinal_ex((ctx), (out), (n))
#define FIPS_get_digestbynid(nid) EVP_get_digestbynid(nid)
#define M_EVP_MD_size(md) EVP_MD_size(md)
#define __fips_constseg
#endif
