// age-tag-witness: the identity side of age's tagged recipients, from
// age's own test identities (tag/internal/tagtest), whose keys are HPKE's
// DeriveKeyPair of a seed - so a file age encrypts to a tag recipient,
// and one anything else does, can be opened without hardware.
//
//	age-tag-witness recipient classic|pq SEED       -> age1tag1... / age1tagpq1...
//	age-tag-witness decrypt classic|pq SEED IN OUT  -> OUT is the plaintext
package main

import (
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/tag/internal/tagtest"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: age-tag-witness recipient|decrypt classic|pq SEED [IN OUT]")
		os.Exit(2)
	}
	var identity age.Identity
	var recipient fmt.Stringer
	switch os.Args[2] {
	case "classic":
		i := tagtest.NewClassicIdentity(os.Args[3])
		identity, recipient = i, i.Recipient()
	case "pq":
		i := tagtest.NewHybridIdentity(os.Args[3])
		identity, recipient = i, i.Recipient()
	default:
		fmt.Fprintln(os.Stderr, "classic or pq")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "recipient":
		fmt.Println(recipient.String())
	case "decrypt":
		in, err := os.Open(os.Args[4])
		if err != nil {
			fail(err)
		}
		r, err := age.Decrypt(in, identity)
		if err != nil {
			fail(err)
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(os.Args[5], plain, 0o600); err != nil {
			fail(err)
		}
	default:
		fmt.Fprintln(os.Stderr, "recipient or decrypt")
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
