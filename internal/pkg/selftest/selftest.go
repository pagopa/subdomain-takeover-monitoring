// Package selftest creates and verifies disposable "canary" dangling DNS
// records. A canary is a DNS record that intentionally points to a deleted
// resource; a healthy takeover scanner must always detect it. Running the
// self-test on every invocation proves the scanner is still functioning.
package selftest

import (
	"crypto/rand"
	"encoding/hex"
)

// randomHex returns a hex-encoded string of n random bytes.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
