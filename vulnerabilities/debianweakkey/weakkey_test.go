package debianweakkey

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

const weak1024 = `
-----BEGIN CERTIFICATE-----
MIICDzCCAXgCCQCusmyauLBA4jANBgkqhkiG9w0BAQUFADBMMQswCQYDVQQGEwJH
QjESMBAGA1UECBMJQmVya3NoaXJlMRAwDgYDVQQHEwdOZXdidXJ5MRcwFQYDVQQK
Ew5NeSBDb21wYW55IEx0ZDAeFw0wODA1MTYxODE0MDJaFw0wOTA1MTYxODE0MDJa
MEwxCzAJBgNVBAYTAkdCMRIwEAYDVQQIEwlCZXJrc2hpcmUxEDAOBgNVBAcTB05l
d2J1cnkxFzAVBgNVBAoTDk15IENvbXBhbnkgTHRkMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQDl/LnqaBR7lirE3HDMt1GuJyN9XCBz2lEZthyxX65KBFGkZUiY
PwAPjlq9PDTB0gIYNMCIEDFJAJl+xl92njZhK47L8t4+PaxMpCRrM6kz1KY5/gTs
49Z33g70m/zT13sTNmHjK7720QNWCIM2GpmtodiXecDAEI7DaW0KTFSfBQIDAQAB
MA0GCSqGSIb3DQEBBQUAA4GBANNXoSJuOlQqT5JIBJs8ba+2TA9hrxXQrXUWvySy
2NyF9l4CEwPdwYf+xKde6Ga5yEY/fejLG2WEZJBa8aas7nkKqkiNBnjmqbph2gP6
7LldvthZqKkUl6BkkTr3bZEXPXa6JLHtcpRKT5ybTWIHfh0waSVmpD6o/7KictNA
Bq3R
-----END CERTIFICATE-----`

const weak2048 = `
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIJAJs7Mrs4MdflMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNV
BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRAwDgYDVQQKEwdUZXN0bGliMQ0wCwYD
VQQLEwRUZXN0MQswCQYDVQQDEwJDQTAeFw0wODA1MTIxNzM2NTZaFw0wODA2MTEx
NzM2NTZaME0xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRAwDgYDVQQK
EwdUZXN0bGliMQ0wCwYDVQQLEwRUZXN0MQswCQYDVQQDEwJDQTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANM8XW6YsOpOq3amDWoKe5xZg8WMCqHTw3lp
WBafJwJ7rIElP6V5xILohKLhzvDKgT7INZ6WENKUc8o21jwegaAQGkgaPP9YYQ6O
pyoqFYJn1m9NooZpKKI9RuAhxUQv355K3WvFNn0/dyJhCSlRExCDbnp31gi38ZH4
JBm+EYfsoYTwZlHESOqQR4gT623JvlP8ZmnTHKtjij8wY9E8ytpbSvojHc75VIbt
XS1xjDDgzkraL/3hgWAD8J0YOiXMsodKVwOVAOS2UAurfNQ13DAdGfLCVq5Pg33S
3mMOiKZSqHwfKkRCJFA9qX3D7rvHk+blvuxjHB7SeI/LHaEOCvcCAwEAAaOBrzCB
rDAdBgNVHQ4EFgQUC//QSRcOIUe7DnKguOpX+kBmqVcwfQYDVR0jBHYwdIAUC//Q
SRcOIUe7DnKguOpX+kBmqVehUaRPME0xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdB
cml6b25hMRAwDgYDVQQKEwdUZXN0bGliMQ0wCwYDVQQLEwRUZXN0MQswCQYDVQQD
EwJDQYIJAJs7Mrs4MdflMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEB
ALRkK4uZ60YHeL6LYLJyhz1p/FJXNWb2TqO7kZQl3ZfkmFJF1524N/K8KrZLwIGJ
KJXUPcGTkBm/3tmvIuAMxn/MRvlEPW1nwQG81QXltObHRF5123Tl1px30Y8B00/V
VBqeKw7sMLF0b4PmnegPz77UhsGikffPJwLt6VUO0j52RW/XvpletgqcxWMHqVLK
z0V73UyaJT3wEm6zEjJINPfPwcw46IeOXcnEekon3JbDxtvm8Q706YOziPStGcel
hh+5myPwDwMgc/mH+jDBK8vyaYGb+xViHK9Fa70jkcSX/AOmYYRKfKZbaR8ba/Ee
xosT4eW/v04AyK9nfcPNbhg=
-----END CERTIFICATE-----`

const oddSize1784 = `
-----BEGIN CERTIFICATE-----
MIIC8DCCAfoCCQC/HRHmKuAz7jANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTlkxFjAUBgNVBAcMDU5ldyBZb3JrIENpdHkxEDAOBgNVBAoM
B0Zha2VPcmcxGDAWBgNVBAMMD29kZC5rZXlzaXplLmNvbTAeFw0yMjA4MjEwMjMw
NTlaFw0yMzA4MjEwMjMwNTlaMF4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOWTEW
MBQGA1UEBwwNTmV3IFlvcmsgQ2l0eTEQMA4GA1UECgwHRmFrZU9yZzEYMBYGA1UE
AwwPb2RkLmtleXNpemUuY29tMIH9MA0GCSqGSIb3DQEBAQUAA4HrADCB5wKB3zfP
RDCqxw7BH7cXm1vMEmH4EAJuVpWYJGTGr8krhJUyRiW0RwYyA7uBVMQi5+zCl+/P
oCBwPNwe8LmDhjmT6O0OLhOTeEGITlggSZOskppfpxEOM450S9i9RhYHnGxim8uO
tUoHJfaUy8IeKYHA/RGS2OaE704F3HsQzvTplmYiXiD0cc9O55y/CMno/KPU0Fw0
/CdWsU2vbxQlmvnB4gS/7bou/XvFhsaa7fQZrh2RewA3FnJkJhKsIMOeOu7Svj6Z
w6zDW+CV2us16I+kmim2Qe4b+VXlTp1qSvVmd2UCAwEAATANBgkqhkiG9w0BAQsF
AAOB4AAUW8wOhOQRJGghghlM5e+zWMno15D2keoUBVvOyapJjgnrJkFpWLBt+Pr6
R9Oo1BFMpmSp4VNQcKQ84ddVNoSpgzKk6M4C4g8IEyzh8OWu7YEg81J2n90g8xMA
6iYZenPB9FDgylPGOfE4pz/G06aMW24BT64cX+p9+Skiw1lqkD3Copj3tSlNmkKS
rNJFWh3NMI1M1r+WiG4AhGPSwWyL6Z2eni9ggpLNeAF0hHtcK6lBF6NLxt3NjHi/
UrUNQTca4I10vp16gVCdU3AsMmaYXLn7vqoiexdgzQmQqsJW
-----END CERTIFICATE-----`

const good2048 = `
-----BEGIN CERTIFICATE-----
MIIDVDCCAjwCAQEwDQYJKoZIhvcNAQELBQAwbTEZMBcGA1UEAwwQU2VsZi1TaWdu
ZWQgUm9vdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlVUMQ0wCwYDVQQHDARMZWhp
MRkwFwYDVQQKDBBTZWxmLVNpZ25lZCBJbmMuMQwwCgYDVQQLDANTUkUwHhcNMjAw
MTEzMDU1MTE4WhcNMjAwMTIwMDU1MTE4WjBzMQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCVVQxDTALBgNVBAcMBExlaGkxGTAXBgNVBAoMEFNlbGYtU2lnbmVkIEluYy4x
DDAKBgNVBAsMA1NSRTEfMB0GA1UEAwwWdmFsaWQuZGlnaWNlcnR0ZXN0LmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/1VPx0IrEnQcPQZ6sElobO
CsO8C7oTqZFpJttujRMCWpvKAizlx+tEocZTBnUcTupC0NA2FCg7CakS+JZ9phHC
mnnC5Fq2Eeehgg4vhVtU/hi2BRUW+QUV8SnIBoid6KZckaHg1qBCxT0KPH5iGpAG
S3dRpmNAgQ9x3lrHrRj+qmQxTUQ8eeUzQZhifBm+y/NmZVZq+r4MXh8imK44d1SD
BoQTSS7+jLU3SnFKu+R/y4IUU53JakJBrD1Vst6+FMgDIXD1pj+cDVlCHlNw9ccB
XSJG3VpBXdNvlxodOO7gBVIbW8zzg2WLcNJRzSKHFR9WdFhKMJzpe3dXTf9b7MkC
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEABdU8Bb8EqrRlErbeKbjQen2kN7UpFHL5
TpyxQL3tlvW4W2ougiTWy6j5FX4EMCjTPg4/tBcR97Kqe4uU01JSRoCBd6zKAmrD
VZaUBWc1ly8iskOO+vZjuFa1wxhX/ugjqWHnfREqm3QHX4nuQEwjvHgZLQmuq21/
Zx3gd64aD7xL5pXt+/DILPNUD3OYKBpQ8DGW3CxKXEQZvN/D4opk7FFMnSWPCiFo
6wAwChXZBzX+v8hoFHt83QsnpFOrVD1H/RBuNBp0VBuySRlVwPYVDcutTrqMEz3z
d7+0ksvbDUmlMMZRIppmHit25taSAGPxmprKhIs2U/39qbfsrXwp4Q==
-----END CERTIFICATE-----`

func TestWeakKeyBad1024(t *testing.T) {
	var r DebianWeakKey

	os.Setenv("WEAKKEY_PATH", "../../resources/weakkeys")

	block, _ := pem.Decode([]byte(weak1024))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("error parsing certificate for test: %v", err)
	}

	pk := crt.PublicKey.(*rsa.PublicKey)
	ks := pk.Size() * 8
	mod := fmt.Sprintf("%x", pk.N)
	r.Check(ks, mod)

	if r.Vulnerable != vulnerable {
		t.Errorf("Did not detect weak key, got: %v, want: %v.", r.Vulnerable, vulnerable)
	}
}

func TestWeakKeyBad2048(t *testing.T) {
	var r DebianWeakKey

	os.Setenv("WEAKKEY_PATH", "../../resources/weakkeys")

	fmt.Printf("path: %s\n", os.Getenv("WEAKKEY_PATH"))

	block, _ := pem.Decode([]byte(weak2048))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("error parsing certificate for test: %v", err)
	}

	pk := crt.PublicKey.(*rsa.PublicKey)
	ks := pk.Size() * 8
	mod := fmt.Sprintf("%x", pk.N)
	r.Check(ks, mod)

	if r.Vulnerable != vulnerable {
		t.Errorf("Did not detect weak key, got: %v, want: %v.", r.Vulnerable, vulnerable)
	}
}

func TestWeakKeyGood2048(t *testing.T) {
	var r DebianWeakKey

	os.Setenv("WEAKKEY_PATH", "../../resources/weakkeys")

	block, _ := pem.Decode([]byte(good2048))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("error parsing certificate for test: %v", err)
	}

	pk := crt.PublicKey.(*rsa.PublicKey)
	ks := pk.Size() * 8
	mod := fmt.Sprintf("%x", pk.N)
	r.Check(ks, mod)

	if r.Vulnerable == vulnerable {
		t.Errorf("Did not detect weak key, got: %v, want: %v.", r.Vulnerable, notVulnerable)
	}
}

func TestWeakKeyUncommonKeySize(t *testing.T) {
	var r DebianWeakKey

	os.Setenv("WEAKKEY_PATH", "../../resources/weakkeys")

	block, _ := pem.Decode([]byte(oddSize1784))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("error parsing certificate for test: %v", err)
	}

	pk := crt.PublicKey.(*rsa.PublicKey)
	ks := pk.Size() * 8
	mod := fmt.Sprintf("%x", pk.N)
	r.Check(ks, mod)

	if r.Vulnerable != uncommonKey {
		t.Errorf("wrong return, got: %v, want: %v.", r.Vulnerable, uncommonKey)
	}
}

func TestWeakKeyMissingKeyFile(t *testing.T) {
	var r DebianWeakKey

	commonKeySizes = []int{512, 1024, 1784, 2048, 4096}

	os.Setenv("WEAKKEY_PATH", "../../resources/weakkeys")

	block, _ := pem.Decode([]byte(oddSize1784))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("error parsing certificate for test: %v", err)
	}

	pk := crt.PublicKey.(*rsa.PublicKey)
	ks := pk.Size() * 8
	mod := fmt.Sprintf("%x", pk.N)

	err = r.Check(ks, mod)
	if err == nil {
		t.Errorf("Expected error for odd key size")
	}
}
