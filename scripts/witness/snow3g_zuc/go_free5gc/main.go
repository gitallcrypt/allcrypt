// free5gc's SNOW 3G, ZUC, NEA1, NEA3, NIA1 and NIA3 (free5gc/nas,
// internal/algo) as a witness, under the request lines driver.h
// describes. build.sh copies the package beside this file as gppwitness/algo,
// its imports pointed there; nothing in it is changed.
//
// snow3g takes K0..K3 and IV0..IV3 as big-endian words of the key and IV
// bytes, as GetKeyStream does. NEA1 is 128-EEA1, the same function as UEA2;
// NIA1 is 128-EIA1, and is handed its message with the bits past LENGTH
// cleared. There is no UIA2 with a free FRESH, and no ZUC-256.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gppwitness/algo"
	"gppwitness/algo/snow3g"
	"gppwitness/algo/zuc"
)

func unhex(s string) ([]byte, error) {
	if s == "-" {
		return []byte{}, nil
	}
	return hex.DecodeString(s)
}

func words(b []byte) [4]uint32 {
	var w [4]uint32
	for i := range w {
		w[i] = binary.BigEndian.Uint32(b[4*i:])
	}
	return w
}

func zeroTail(data []byte, bits uint32) {
	if bits%8 != 0 {
		data[bits/8] &= byte(0xff << (8 - bits%8))
	}
}

func stream(f []string) string {
	key, err1 := unhex(f[2])
	iv, err2 := unhex(f[3])
	n, err3 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil || err3 != nil {
		return "error request"
	}
	var ks []uint32
	switch f[1] {
	case "snow3g":
		if len(key) != 16 || len(iv) != 16 {
			return "error key or iv length"
		}
		ks = snow3g.GetKeyStream(words(key), words(iv), (n+3)/4)
	case "zuc128":
		if len(key) != 16 || len(iv) != 16 {
			return "error key or iv length"
		}
		ks = zuc.Zuc(key, iv, uint32((n+3)/4))
	default:
		return "error unsupported"
	}
	out := make([]byte, 4*len(ks))
	for i, w := range ks {
		binary.BigEndian.PutUint32(out[4*i:], w)
	}
	return hex.EncodeToString(out[:n])
}

func modes(f []string) string {
	key, err1 := unhex(f[2])
	count, err2 := strconv.ParseUint(f[3], 16, 32)
	bearer, err3 := strconv.ParseUint(f[4], 10, 32)
	dir, err4 := strconv.ParseUint(f[5], 10, 32)
	bits, err5 := strconv.ParseUint(f[6], 10, 32)
	data, err6 := unhex(f[7])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		return "error request"
	}
	if len(key) != 16 || uint64(len(data)) != (bits+7)/8 {
		return "error key or data length"
	}
	var k [16]byte
	copy(k[:], key)
	var out []byte
	var err error
	switch f[0] + " " + f[1] {
	case "f8 uea2":
		out, err = algo.NEA1(k, uint32(count), uint32(bearer), uint32(dir), data, uint32(bits))
		if err == nil {
			zeroTail(out, uint32(bits))
		}
	case "f8 eea3":
		out, err = algo.NEA3(k, uint32(count), uint8(bearer), uint8(dir), data, uint32(bits))
		if err == nil {
			zeroTail(out, uint32(bits))
		}
	case "f9 eia1":
		// NIA1 takes the bits past LENGTH in its last block into the MAC,
		// where TS 33.401 pads with zeros, so they are cleared here first.
		zeroTail(data, uint32(bits))
		out, err = algo.NIA1(k, uint32(count), byte(bearer), uint32(dir), data, bits)
	case "f9 eia3":
		out, err = algo.NIA3(k, uint32(count), uint8(bearer), uint8(dir), data, uint32(bits))
	default:
		return "error unsupported"
	}
	if err != nil {
		return "error " + err.Error()
	}
	return hex.EncodeToString(out)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		f := strings.Fields(in.Text())
		answer := "error request"
		func() {
			defer func() {
				if r := recover(); r != nil {
					answer = fmt.Sprintf("error panic: %v", r)
				}
			}()
			switch {
			case len(f) == 5 && f[0] == "stream":
				answer = stream(f)
			case len(f) == 8 && (f[0] == "f8" || f[0] == "f9"):
				answer = modes(f)
			case len(f) == 6 && f[0] == "zucmac":
				answer = "error unsupported"
			}
		}()
		fmt.Fprintln(out, answer)
		out.Flush()
	}
}
