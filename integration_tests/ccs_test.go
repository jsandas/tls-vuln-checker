//go:build integration

package integrationtests

import (
	"testing"

	"github.com/jsandas/tls-vuln-checker/vulnerabilities/ccs"
)

// ccsCase describes a single CCS injection integration test scenario.
type ccsCase struct {
	name     string
	host     string
	port     string
	expected string
	// reason documents why this (OpenSSL, TLS config) combination produces this result.
	reason string
}

func TestCCSInjection(t *testing.T) {
	cases := []ccsCase{
		{
			name:     "patched_openssl_tls12_tls13",
			host:     "127.0.0.1",
			port:     "443",
			expected: "no",
			reason:   "OpenSSL 3.5.7 is patched; TLS 1.0 disabled so probe receives a fatal alert during handshake",
		},
		{
			name:     "patched_openssl_tls12_only",
			host:     "127.0.0.1",
			port:     "1443",
			expected: "no",
			reason:   "OpenSSL 3.5.7 is patched; TLS 1.2-only server rejects the TLS 1.0 ClientHello with a fatal alert",
		},
		{
			name:     "patched_openssl_tls10_plus",
			host:     "127.0.0.1",
			port:     "2443",
			expected: "no",
			reason:   "OpenSSL 3.5.7 is patched; TLS 1.0 accepted but server correctly rejects the premature CCS with a fatal alert",
		},
		{
			name:     "vulnerable_openssl_tls12_only",
			host:     "127.0.0.1",
			port:     "3443",
			expected: "no",
			reason:   "OpenSSL 1.0.1f is vulnerable but TLS 1.0 is disabled; CVE-2014-0224 requires TLS ≤ 1.1 so the server cannot be exploited via this path",
		},
		{
			name:     "vulnerable_openssl_tls10_plus",
			host:     "127.0.0.1",
			port:     "4443",
			expected: "yes",
			reason:   "OpenSSL 1.0.1f with TLS 1.0 enabled silently accepts the premature CCS and switches cipher state",
		},
		{
			name:     "vulnerable_openssl_sslv2_tls12",
			host:     "127.0.0.1",
			port:     "5443",
			expected: "yes",
			reason:   "OpenSSL 1.0.1f with broad protocol range including TLS 1.0 is exploitable",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("scenario: %s", tc.reason)

			host := envDefault("CCS_"+tc.name+"_HOST", tc.host)
			port := envDefault("CCS_"+tc.name+"_PORT", tc.port)

			waitForTCP(t, host, port)

			var result ccs.CCSInjection

			if err := result.Check(host, port); err != nil {
				t.Fatalf("CCS check returned unexpected error: %v", err)
			}

			if result.Vulnerable != tc.expected {
				t.Errorf("expected vulnerable=%s, got vulnerable=%s\n  scenario: %s",
					tc.expected, result.Vulnerable, tc.reason)
			}
		})
	}
}
