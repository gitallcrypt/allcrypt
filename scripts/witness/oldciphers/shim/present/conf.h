/* conf.h for kurtfu/present, the configuration file its README says to
 * edit: PRESENT's 31 rounds, and the key size the build chooses - 128
 * bits with KEY128 defined, otherwise 80. Included instead of the
 * project's own, which fixes 80 bits. */
#ifndef CONF_H
#define CONF_H
#define CONF_PRESENT (1u)
#ifdef KEY128
#   define PRESENT_USE_KEY80  (0u)
#   define PRESENT_USE_KEY128 (1u)
#else
#   define PRESENT_USE_KEY80  (1u)
#   define PRESENT_USE_KEY128 (0u)
#endif
#define PRESENT_ROUND_COUNT (31u)
#endif
