// A witness for the KeePass example: tobischo/gokeepasslib, which reads
// and writes KDBX 3.1, 4.0 and 4.1. Development tool only; see
// docs/building.md.
//
//	kdbxwitness dump -pass P [-key FILE] DATABASE
//	kdbxwitness create -pass P [-key FILE] -version 3|40|41 -cipher aes|chacha20|twofish
//	            -kdf aes|argon2d [-rounds N] [-iterations N] [-memory KIB]
//	            [-compress=false] OUT
//
// `dump` prints the database in the canonical listing the example's
// `dump --canonical` also prints, so the two can be compared as text:
// the format, cipher and KDF, then every group and entry in document
// order with each string field and attachment as hex.
//
// `create` writes the fixed sample database every check uses - groups,
// protected and plain fields, characters XML must escape, a multi-line
// note, a custom protected field and an attachment - under the
// parameters given.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "kdbxwitness:", err)
	os.Exit(1)
}

func credentials(pass, key string) *gokeepasslib.DBCredentials {
	if key == "" {
		return gokeepasslib.NewPasswordCredentials(pass)
	}
	c, err := gokeepasslib.NewPasswordAndKeyCredentials(pass, key)
	if err != nil {
		fail(err)
	}
	return c
}

func hexOf(b []byte) string {
	return fmt.Sprintf("%x", b)
}

func cipherName(id []byte) string {
	switch string(id) {
	case string(gokeepasslib.CipherAES):
		return "aes"
	case string(gokeepasslib.CipherChaCha20):
		return "chacha20"
	case string(gokeepasslib.CipherTwoFish):
		return "twofish"
	}
	return "unknown"
}

func dumpEntry(db *gokeepasslib.Database, path string, e *gokeepasslib.Entry) {
	fmt.Printf("entry %s\n", path)
	values := append([]gokeepasslib.ValueData(nil), e.Values...)
	sort.SliceStable(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	for _, v := range values {
		fmt.Printf("  string %s %s\n", hexOf([]byte(v.Key)), hexOf([]byte(v.Value.Content)))
	}
	for _, ref := range e.Binaries {
		b := ref.Find(db)
		if b == nil {
			fail(fmt.Errorf("attachment %q refers to nothing", ref.Name))
		}
		content, err := b.GetContentBytes()
		if err != nil {
			fail(err)
		}
		fmt.Printf("  attachment %s %x\n", hexOf([]byte(ref.Name)), sha256.Sum256(content))
	}
	history := 0
	for _, h := range e.Histories {
		history += len(h.Entries)
	}
	fmt.Printf("  history %d\n", history)
}

func dumpGroup(db *gokeepasslib.Database, path string, g *gokeepasslib.Group) {
	path = path + "/" + g.Name
	fmt.Printf("group %s\n", path)
	for i := range g.Entries {
		dumpEntry(db, path, &g.Entries[i])
	}
	for i := range g.Groups {
		dumpGroup(db, path, &g.Groups[i])
	}
}

func dump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	pass := fs.String("pass", "", "")
	key := fs.String("key", "", "")
	fs.Parse(args)
	file, err := os.Open(fs.Arg(0))
	if err != nil {
		fail(err)
	}
	defer file.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials(*pass, *key)
	if err := gokeepasslib.NewDecoder(file).Decode(db); err != nil {
		fail(err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		fail(err)
	}
	h := db.Header
	fmt.Printf("version %d.%d\n", h.Signature.MajorVersion, h.Signature.MinorVersion)
	fmt.Printf("cipher %s\n", cipherName(h.FileHeaders.CipherID))
	if h.IsKdbx4() {
		kdf := "aes"
		if string(h.FileHeaders.KdfParameters.UUID) == string(gokeepasslib.KdfArgon2) {
			kdf = "argon2d"
		}
		fmt.Printf("kdf %s\n", kdf)
	} else {
		fmt.Printf("kdf aes\n")
	}
	fmt.Printf("compression %d\n", h.FileHeaders.CompressionFlags)
	fmt.Printf("name %s\n", hexOf([]byte(db.Content.Meta.DatabaseName)))
	for i := range db.Content.Root.Groups {
		dumpGroup(db, "", &db.Content.Root.Groups[i])
	}
}

func value(key, content string, protected bool) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key,
		Value: gokeepasslib.V{Content: content, Protected: w.NewBoolWrapper(protected)}}
}

func create(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	pass := fs.String("pass", "", "")
	key := fs.String("key", "", "")
	version := fs.String("version", "41", "")
	cipher := fs.String("cipher", "aes", "")
	kdf := fs.String("kdf", "aes", "")
	rounds := fs.Uint64("rounds", 1000, "")
	iterations := fs.Uint64("iterations", 2, "")
	memory := fs.Uint64("memory", 1024, "KiB")
	compress := fs.Bool("compress", true, "")
	fs.Parse(args)

	var db *gokeepasslib.Database
	switch *version {
	case "3":
		db = gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	case "40":
		db = gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion40())
	default:
		db = gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion41())
	}
	fh := db.Header.FileHeaders
	switch *cipher {
	case "chacha20":
		fh.CipherID = gokeepasslib.CipherChaCha20
	case "twofish":
		fh.CipherID = gokeepasslib.CipherTwoFish
	default:
		fh.CipherID = gokeepasslib.CipherAES
	}
	// ChaCha20's IV is 12 bytes and the CBC ciphers' 16.
	iv := make([]byte, 16)
	if *cipher == "chacha20" {
		iv = make([]byte, 12)
	}
	for i := range iv {
		iv[i] = byte(i * 7)
	}
	fh.EncryptionIV = iv
	if *compress {
		fh.CompressionFlags = gokeepasslib.GzipCompressionFlag
	} else {
		fh.CompressionFlags = gokeepasslib.NoCompressionFlag
	}
	if *version == "3" {
		fh.TransformRounds = *rounds
	} else if *kdf == "argon2d" {
		fh.KdfParameters.UUID = gokeepasslib.KdfArgon2
		fh.KdfParameters.Iterations = *iterations
		fh.KdfParameters.Memory = *memory * 1024
		fh.KdfParameters.Parallelism = 2
		fh.KdfParameters.Rounds = 0
	} else {
		fh.KdfParameters.UUID = gokeepasslib.KdfAES4
		fh.KdfParameters.Rounds = *rounds
		fh.KdfParameters.Iterations = 0
		fh.KdfParameters.Memory = 0
		fh.KdfParameters.Parallelism = 0
		fh.KdfParameters.Version = 0
	}
	db.Credentials = credentials(*pass, *key)
	db.Content.Meta.DatabaseName = "Sample <&> \"database\""

	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	email := gokeepasslib.NewGroup()
	email.Name = "Email"
	bank := gokeepasslib.NewGroup()
	bank.Name = "Banking & Finance"

	mail := gokeepasslib.NewEntry()
	mail.Values = []gokeepasslib.ValueData{
		value("Title", "Mail account", false),
		value("UserName", "alice@example.org", false),
		value("Password", "correct horse battery staple", true),
		value("URL", "https://mail.example.org/?a=1&b=<2>", false),
		value("Notes", "line one\nline two\n\ttabbed 'quoted' \"double\"", false),
	}
	attachment := db.AddBinary([]byte("attachment contents\x00\x01\x02 binary"))
	mail.Binaries = append(mail.Binaries, attachment.CreateReference("notes.bin"))

	card := gokeepasslib.NewEntry()
	card.Values = []gokeepasslib.ValueData{
		value("Title", "Bank card", false),
		value("UserName", "", false),
		value("Password", "1234", true),
		value("PIN (custom)", "0000 éè ☃", true),
		value("Notes", "", false),
	}
	other := gokeepasslib.NewEntry()
	other.Values = []gokeepasslib.ValueData{
		value("Title", "Plain entry", false),
		value("Password", "not protected", false),
	}

	email.Entries = append(email.Entries, mail)
	bank.Entries = append(bank.Entries, card)
	root.Entries = append(root.Entries, other)
	root.Groups = append(root.Groups, email, bank)
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}

	if err := db.LockProtectedEntries(); err != nil {
		fail(err)
	}
	out, err := os.Create(fs.Arg(0))
	if err != nil {
		fail(err)
	}
	if err := gokeepasslib.NewEncoder(out).Encode(db); err != nil {
		fail(err)
	}
	out.Close()
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: kdbxwitness dump|create ..."))
	}
	switch os.Args[1] {
	case "dump":
		dump(os.Args[2:])
	case "create":
		create(os.Args[2:])
	default:
		fail(fmt.Errorf("unknown command %s", os.Args[1]))
	}
}
