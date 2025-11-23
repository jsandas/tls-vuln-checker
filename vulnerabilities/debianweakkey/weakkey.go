package debianweakkey

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

var commonKeySizes = []int{512, 1024, 2048, 4096}

/*
	Debian Weak Key checking is an old vulnerability.
	This check compares the sha1 hash of the certificate modulus
	a list of known weak keys based on keysize

	Note: because this require referencing binary files a hack
	was added to detect if running locally which overrides the
	value of blpath
*/

const (
	notVulnerable = "no"
	vulnerable    = "yes"
	uncommonKey   = "uncommonKey"
	testFailed    = "error"
)

type DebianWeakKey struct {
	Vulnerable string `json:"vulnerable"`
}

// WeakKey detects if key was generated with weak Debian openssl
func (w *DebianWeakKey) Check(keysize int, modulus string) error {
	w.Vulnerable = notVulnerable

	// only test if common keysize
	var found bool
	for _, ks := range commonKeySizes {
		if keysize == ks {
			found = true
		}
	}
	if !found {
		w.Vulnerable = uncommonKey
		return nil
	}

	// blpath is the location of weakkeys blacklist files
	blpath := "resources/weakkeys"

	// override blpath if running go test
	if testing.Testing() {
		blpath = "../../resources/weakkeys"
	}

	mod := fmt.Sprintf("Modulus=%s\n", strings.ToUpper(modulus))
	ks := strconv.Itoa(keysize)
	h := sha1.New()
	h.Write([]byte(mod))
	bs := h.Sum(nil)

	sh := hex.EncodeToString(bs)

	// Test overrides
	// ks = "2048"
	// sh = "24a319be7f63b8b46e9cd10d992069d592fe1766"

	// load weak key file
	file, err := os.Open(blpath + "/blacklist.RSA-" + ks)
	if err != nil {
		w.Vulnerable = testFailed
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if sh[20:] == scanner.Text() {
			w.Vulnerable = vulnerable
		}
	}

	return nil
}
