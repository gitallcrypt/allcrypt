// hpke-witness: filippo.io/hpke (the HPKE behind Go's crypto/hpke) as a
// witness, one request per line, hex fields, "-" for empty, one line
// out per request or "error: ...".
//
//	derive KEM IKM                       -> SK PK
//	seal KEM KDF AEAD PK INFO AAD PT     -> ENC CT
//	open KEM KDF AEAD SK ENC INFO AAD CT -> PT
//	export KEM KDF AEAD SK ENC INFO CTX L -> VALUE   (the recipient's export)
//
// KEM, KDF and AEAD are ids in hex without a prefix. Base mode only:
// filippo.io/hpke has no other.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"filippo.io/hpke"
)

func field(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func out(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func id(s string) uint16 {
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		panic(err)
	}
	return uint16(v)
}

func suite(f []string) (hpke.KEM, hpke.KDF, hpke.AEAD, error) {
	kem, err := hpke.NewKEM(id(f[0]))
	if err != nil {
		return nil, nil, nil, err
	}
	kdf, err := hpke.NewKDF(id(f[1]))
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := hpke.NewAEAD(id(f[2]))
	if err != nil {
		return nil, nil, nil, err
	}
	return kem, kdf, aead, nil
}

func handle(f []string) (string, error) {
	switch {
	case f[0] == "derive" && len(f) == 3:
		kem, err := hpke.NewKEM(id(f[1]))
		if err != nil {
			return "", err
		}
		k, err := kem.DeriveKeyPair(field(f[2]))
		if err != nil {
			return "", err
		}
		sk, err := k.Bytes()
		if err != nil {
			return "", err
		}
		return out(sk) + " " + out(k.PublicKey().Bytes()), nil
	case f[0] == "seal" && len(f) == 8:
		kem, kdf, aead, err := suite(f[1:4])
		if err != nil {
			return "", err
		}
		pk, err := kem.NewPublicKey(field(f[4]))
		if err != nil {
			return "", err
		}
		enc, s, err := hpke.NewSender(pk, kdf, aead, field(f[5]))
		if err != nil {
			return "", err
		}
		ct, err := s.Seal(field(f[6]), field(f[7]))
		if err != nil {
			return "", err
		}
		return out(enc) + " " + out(ct), nil
	case (f[0] == "open" && len(f) == 9) || (f[0] == "export" && len(f) == 9):
		kem, kdf, aead, err := suite(f[1:4])
		if err != nil {
			return "", err
		}
		sk, err := kem.NewPrivateKey(field(f[4]))
		if err != nil {
			return "", err
		}
		r, err := hpke.NewRecipient(field(f[5]), sk, kdf, aead, field(f[6]))
		if err != nil {
			return "", err
		}
		if f[0] == "export" {
			length, err := strconv.Atoi(f[8])
			if err != nil {
				return "", err
			}
			v, err := r.Export(string(field(f[7])), length)
			if err != nil {
				return "", err
			}
			return out(v), nil
		}
		pt, err := r.Open(field(f[7]), field(f[8]))
		if err != nil {
			return "", err
		}
		return out(pt), nil
	}
	return "", fmt.Errorf("unknown request")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		answer, err := handle(strings.Fields(in.Text()))
		if err != nil {
			answer = "error: " + err.Error()
		}
		fmt.Fprintln(w, answer)
		w.Flush()
	}
}
