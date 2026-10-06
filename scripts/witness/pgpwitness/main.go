// A witness for the OpenPGP example: ProtonMail's go-crypto, which
// implements RFC 9580 (version 6 keys, SEIPD v2, Argon2) as well as RFC
// 4880. Development tool only; see docs/building.md.
//
//	pgpwitness sym-encrypt -pass P [-aead none|ocb|eax|gcm] [-cipher aes128|aes192|aes256]
//	           [-argon2] [-compress none|zip|zlib] IN OUT
//	pgpwitness decrypt -pass P IN OUT
//	pgpwitness decrypt -key SECRET [-keypass P] IN OUT
//	pgpwitness gen-key -algo rsa|ed25519|ed448|eddsa|p256|p384|p521|secp256k1|brainpool256 [-v6]
//	           [-keypass P] SECRET PUBLIC
//	pgpwitness encrypt -to PUBLIC [-signkey SECRET -keypass P] [-aead ...] [-cipher ...] IN OUT
//	pgpwitness sign -key SECRET [-keypass P] [-mode inline|detached|clear] IN OUT
//	pgpwitness verify -key PUBLIC [-mode inline|detached|clear] [-sig SIG] IN
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "pgpwitness:", err)
	os.Exit(1)
}

func dearmor(data []byte) []byte {
	if block, err := armor.Decode(bytes.NewReader(data)); err == nil {
		out, err := io.ReadAll(block.Body)
		if err == nil {
			return out
		}
	}
	return data
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: pgpwitness sym-encrypt|decrypt ..."))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	pass := fs.String("pass", "", "passphrase")
	aead := fs.String("aead", "none", "none, ocb, eax or gcm")
	cipher := fs.String("cipher", "aes256", "aes128, aes192 or aes256")
	argon2 := fs.Bool("argon2", false, "Argon2 S2K")
	compress := fs.String("compress", "none", "none, zip or zlib")
	keyFile := fs.String("key", "", "secret key file")
	keyPass := fs.String("keypass", "", "secret key passphrase")
	to := fs.String("to", "", "public key file")
	algo := fs.String("algo", "ed25519", "key algorithm")
	v6 := fs.Bool("v6", false, "version 6 key")
	mode := fs.String("mode", "inline", "inline, detached or clear")
	sigFile := fs.String("sig", "", "detached signature file")
	signKey := fs.String("signkey", "", "secret key to sign with while encrypting")
	fs.Parse(os.Args[2:])
	if (os.Args[1] == "verify" && fs.NArg() != 1) || (os.Args[1] != "verify" && fs.NArg() != 2) {
		fail(fmt.Errorf("IN and OUT are needed (IN alone for verify)"))
	}
	var in []byte
	readKeys := func(path string) openpgp.EntityList {
		data, err := os.ReadFile(path)
		if err != nil {
			fail(err)
		}
		keys, err := openpgp.ReadKeyRing(bytes.NewReader(dearmor(data)))
		if err != nil {
			fail(err)
		}
		return keys
	}

	unlocked := func(path string) openpgp.EntityList {
		keys := readKeys(path)
		for _, e := range keys {
			if e.PrivateKey != nil && e.PrivateKey.Encrypted {
				if err := e.DecryptPrivateKeys([]byte(*keyPass)); err != nil {
					fail(err)
				}
			}
		}
		return keys
	}
	_ = unlocked
	if os.Args[1] != "gen-key" {
		var err error
		in, err = os.ReadFile(fs.Arg(0))
		if err != nil {
			fail(err)
		}
	}
	config := &packet.Config{}
	switch *cipher {
	case "aes128":
		config.DefaultCipher = packet.CipherAES128
	case "aes192":
		config.DefaultCipher = packet.CipherAES192
	default:
		config.DefaultCipher = packet.CipherAES256
	}
	switch *aead {
	case "ocb":
		config.AEADConfig = &packet.AEADConfig{DefaultMode: packet.AEADModeOCB}
	case "eax":
		config.AEADConfig = &packet.AEADConfig{DefaultMode: packet.AEADModeEAX}
	case "gcm":
		config.AEADConfig = &packet.AEADConfig{DefaultMode: packet.AEADModeGCM}
	}
	if *argon2 {
		config.S2KConfig = &s2k.Config{S2KMode: s2k.Argon2S2K}
	}
	switch *compress {
	case "zip":
		config.DefaultCompressionAlgo = packet.CompressionZIP
	case "zlib":
		config.DefaultCompressionAlgo = packet.CompressionZLIB
	}

	switch os.Args[1] {
	case "gen-key":
		config.V6Keys = *v6
		switch *algo {
		case "rsa":
			config.Algorithm = packet.PubKeyAlgoRSA
			config.RSABits = 3072
		case "ed25519":
			config.Algorithm = packet.PubKeyAlgoEd25519
		case "ed448":
			config.Algorithm = packet.PubKeyAlgoEd448
		case "eddsa":
			config.Algorithm = packet.PubKeyAlgoEdDSA
			config.Curve = packet.Curve25519
		case "p256", "p384", "p521", "secp256k1", "brainpool256":
			config.Algorithm = packet.PubKeyAlgoECDSA
			config.Curve = map[string]packet.Curve{"p256": packet.CurveNistP256,
				"p384": packet.CurveNistP384, "p521": packet.CurveNistP521,
				"secp256k1": packet.CurveSecP256k1,
				"brainpool256": packet.CurveBrainpoolP256}[*algo]
		default:
			fail(fmt.Errorf("unknown algorithm %s", *algo))
		}
		var e *openpgp.Entity
		var err error
		if *v6 {
			e, err = openpgp.NewEntityWithoutId(config)
		} else {
			e, err = openpgp.NewEntity("witness", "", "witness@example.org", config)
		}
		if err != nil {
			fail(err)
		}
		var pub bytes.Buffer
		if err := e.Serialize(&pub); err != nil {
			fail(err)
		}
		if *keyPass != "" {
			if err := e.EncryptPrivateKeys([]byte(*keyPass), config); err != nil {
				fail(err)
			}
		}
		var sec bytes.Buffer
		if err := e.SerializePrivateWithoutSigning(&sec, config); err != nil {
			fail(err)
		}
		if err := os.WriteFile(fs.Arg(0), sec.Bytes(), 0o600); err != nil {
			fail(err)
		}
		if err := os.WriteFile(fs.Arg(1), pub.Bytes(), 0o600); err != nil {
			fail(err)
		}
		fmt.Printf("%X\n", e.PrimaryKey.Fingerprint)
		return
	case "sign":
		signers := unlocked(*keyFile)
		var out bytes.Buffer
		switch *mode {
		case "detached":
			if err := openpgp.DetachSign(&out, signers[:1], bytes.NewReader(in), config); err != nil {
				fail(err)
			}
		case "clear":
			w, err := clearsign.Encode(&out, signers[0].PrivateKey, config)
			if err != nil {
				fail(err)
			}
			w.Write(in)
			if err := w.Close(); err != nil {
				fail(err)
			}
		default:
			w, err := openpgp.Sign(&out, signers[:1], &openpgp.FileHints{FileName: "data"}, config)
			if err != nil {
				fail(err)
			}
			w.Write(in)
			if err := w.Close(); err != nil {
				fail(err)
			}
		}
		if err := os.WriteFile(fs.Arg(1), out.Bytes(), 0o600); err != nil {
			fail(err)
		}
		return
	case "verify":
		keyring := readKeys(*keyFile)
		switch *mode {
		case "detached":
			sig, err := os.ReadFile(*sigFile)
			if err != nil {
				fail(err)
			}
			if _, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(in), bytes.NewReader(dearmor(sig)), config); err != nil {
				fail(err)
			}
		case "clear":
			block, _ := clearsign.Decode(in)
			if block == nil {
				fail(fmt.Errorf("not a cleartext signed message"))
			}
			if _, _, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, config); err != nil {
				fail(err)
			}
		default:
			md, err := openpgp.ReadMessage(bytes.NewReader(dearmor(in)), keyring, nil, config)
			if err != nil {
				fail(err)
			}
			if _, err := io.ReadAll(md.UnverifiedBody); err != nil {
				fail(err)
			}
			if !md.IsSigned || md.SignatureError != nil {
				fail(fmt.Errorf("signature: signed %v, %v", md.IsSigned, md.SignatureError))
			}
		}
		fmt.Println("good signature")
		return
	case "encrypt":
		var signers []*openpgp.Entity
		if *signKey != "" {
			signers = unlocked(*signKey)[:1]
		}
		var out bytes.Buffer
		w, err := openpgp.Encrypt(&out, readKeys(*to), nil, signers, &openpgp.FileHints{FileName: "data"}, config)
		if err != nil {
			fail(err)
		}
		if _, err := w.Write(in); err != nil {
			fail(err)
		}
		if err := w.Close(); err != nil {
			fail(err)
		}
		if err := os.WriteFile(fs.Arg(1), out.Bytes(), 0o600); err != nil {
			fail(err)
		}
		return
	case "sym-encrypt":
		var out bytes.Buffer
		w, err := openpgp.SymmetricallyEncrypt(&out, []byte(*pass), &openpgp.FileHints{FileName: "data"}, config)
		if err != nil {
			fail(err)
		}
		if _, err := w.Write(in); err != nil {
			fail(err)
		}
		if err := w.Close(); err != nil {
			fail(err)
		}
		if err := os.WriteFile(fs.Arg(1), out.Bytes(), 0o600); err != nil {
			fail(err)
		}
	case "decrypt":
		config.InsecureAllowUnauthenticatedMessages = true
		prompted := false
		prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if prompted {
				return nil, fmt.Errorf("the passphrase did not decrypt the message")
			}
			prompted = true
			return []byte(*pass), nil
		}
		var keyring openpgp.EntityList
		if *to != "" {
			keyring = append(keyring, readKeys(*to)...)
		}
		if *keyFile != "" {
			secret := readKeys(*keyFile)
			keyring = append(keyring, secret...)
			for _, e := range secret {
				if e.PrivateKey != nil && e.PrivateKey.Encrypted {
					if err := e.DecryptPrivateKeys([]byte(*keyPass)); err != nil {
						fail(err)
					}
				}
			}
		}
		md, err := openpgp.ReadMessage(bytes.NewReader(dearmor(in)), keyring, prompt, config)
		if err != nil {
			fail(err)
		}
		body, err := io.ReadAll(md.UnverifiedBody)
		if err != nil {
			fail(err)
		}
		if md.IsSigned && (md.SignatureError != nil || md.SignedBy == nil) {
			fail(fmt.Errorf("signature: %v", md.SignatureError))
		}
		fmt.Printf("cipher %d, %d bytes\n", md.DecryptedWithAlgorithm, len(body))
		if err := os.WriteFile(fs.Arg(1), body, 0o600); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown command %s", os.Args[1]))
	}
}
