#!/bin/sh
# Builds the two 802.11 key derivation witnesses into PREFIX: hostapd's
# (wpa_supplicant 2.11's) src/common/wpa_common.c with its internal
# crypto, and Wireshark 4.6's epan/crypt/dot11decrypt_util.c against
# libgcrypt and the built tree's libwsutil - each plain and under
# ASan and UBSan.
#
#   sh scripts/witness/ft80211/build.sh WPA_SRC WIRESHARK_SRC WIRESHARK_BUILD PREFIX
#
# WPA_SRC is wpa-2.11 unpacked (Ubuntu's wpa_2.11.orig.tar.xz, sha256
# 9f1109e2aef8e591004bec8e9d8dd363be61c2edaf99f4cc14e35b74316d5a45);
# WIRESHARK_BUILD is where cmake built WIRESHARK_SRC (it holds config.h
# and run/libwsutil.so).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
WPA=$1/src; WS=$2; WSB=$3; PREFIX=$4
mkdir -p "$PREFIX"
STUB="$PREFIX/hostapd_stub.c"
cat > "$STUB" <<'C'
/* Element parsing is on no path the driver takes. */
#include "includes.h"
#include "common.h"
#include "common/ieee802_11_common.h"
ParseRes ieee802_11_parse_elems(const u8 *start, size_t len, struct ieee802_11_elems *elems,
                                int show_errors) { abort(); }
struct wpabuf * ieee802_11_defrag(const u8 *data, size_t len, bool ext_elem) { abort(); }
C
HOSTAPD_SRCS="$WPA/common/wpa_common.c"
for f in sha1 sha1-internal sha1-prf sha256 sha256-internal sha256-prf sha384 sha384-internal \
         sha384-prf sha512 sha512-internal sha512-prf md5 md5-internal aes-omac1 aes-internal \
         aes-internal-enc aes-internal-dec aes-unwrap aes-wrap; do
    HOSTAPD_SRCS="$HOSTAPD_SRCS $WPA/crypto/$f.c"
done
for f in common wpa_debug os_unix wpabuf; do HOSTAPD_SRCS="$HOSTAPD_SRCS $WPA/utils/$f.c"; done
HOSTAPD_FLAGS="-I$WPA -I$WPA/utils -I$HERE -DCONFIG_IEEE80211R -DCONFIG_SHA384 -DCONFIG_SHA512 \
    -DCONFIG_CRYPTO_INTERNAL -DCONFIG_NO_STDOUT_DEBUG"
WS_FLAGS="-I$WSB -I$WS -I$WS/include -I$WS/epan/crypt -I$HERE $(pkg-config --cflags glib-2.0)"
WS_LIBS="-L$WSB/run -Wl,-rpath,$WSB/run -lwsutil -lgcrypt $(pkg-config --libs glib-2.0)"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
for variant in plain san; do
    if [ $variant = san ]; then extra="-O1 -g $SAN"; suffix=-san; else extra="-O2"; suffix=; fi
    # shellcheck disable=SC2086
    cc $extra $HOSTAPD_FLAGS -o "$PREFIX/hostapd-ft$suffix" "$HERE/hostapd_driver.c" "$STUB" \
        $HOSTAPD_SRCS
    # shellcheck disable=SC2086
    cc $extra $WS_FLAGS -o "$PREFIX/wireshark-ft$suffix" "$HERE/wireshark_driver.c" \
        "$WS/epan/crypt/dot11decrypt_util.c" $WS_LIBS
done
echo "built $PREFIX/hostapd-ft{,-san} and $PREFIX/wireshark-ft{,-san}"
