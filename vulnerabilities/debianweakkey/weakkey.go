package debianweakkey

import (
	"bufio"
	"crypto/sha1" /* #nosec */
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
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

// WeakKey detects if key was generated with weak Debian openssl.
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

	// blpath is the location of weakkeys blacklist files. Override with
	// environment variable `WEAKKEY_PATH` when running tests or in CI.
	blpath := "resources/weakkeys"
	if v, ok := os.LookupEnv("WEAKKEY_PATH"); ok && v != "" {
		blpath = v
	}

	mod := fmt.Sprintf("Modulus=%s\n", strings.ToUpper(modulus))
	ks := strconv.Itoa(keysize)

	// Compute SHA-1 of the modulus string. Use sha1.Sum to avoid extra
	// allocations from streaming writer.
	hsum := sha1.Sum([]byte(mod)) /* #nosec */
	sh := hex.EncodeToString(hsum[:])

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
	// Compare against the last 20 hex characters of the SHA-1 (same
	// format used by the blacklist files). Stop early when found.
	target := sh[20:]

	for scanner.Scan() {
		if scanner.Text() == target {
			w.Vulnerable = vulnerable
			return nil
		}
	}

	err = scanner.Err()
	if err != nil {
		w.Vulnerable = testFailed
		return err
	}

	return nil
}
