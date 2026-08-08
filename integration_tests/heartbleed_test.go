//go:build integration

package integrationtests

import (
	"crypto/tls"
	"testing"

	"github.com/jsandas/tls-vuln-checker/vulnerabilities/heartbleed"
)

// heartbleedCase describes a single Heartbleed integration test scenario.
type heartbleedCase struct {
	name               string
	host               string
	port               string
	tlsVersion         int
	expectedVulnerable string
	expectedExtension  bool
	// reason documents why this (OpenSSL, TLS config) combination produces this result.
	reason string
}

func TestHeartbleed(t *testing.T) {
	cases := []heartbleedCase{
		{
			name:               "patched_openssl_tls12_tls13",
			host:               "127.0.0.1",
			port:               "443",
			tlsVersion:         tls.VersionTLS12,
			expectedVulnerable: "n/a",
			expectedExtension:  false,
			reason:             "OpenSSL 3.5.7 does not advertise the heartbeat extension",
		},
		{
			name:               "patched_openssl_tls12_only",
			host:               "127.0.0.1",
			port:               "1443",
			tlsVersion:         tls.VersionTLS12,
			expectedVulnerable: "n/a",
			expectedExtension:  false,
			reason:             "OpenSSL 3.5.7 does not advertise the heartbeat extension regardless of TLS version range",
		},
		{
			name:               "patched_openssl_tls10_plus",
			host:               "127.0.0.1",
			port:               "2443",
			tlsVersion:         tls.VersionTLS12,
			expectedVulnerable: "n/a",
			expectedExtension:  false,
			reason:             "OpenSSL 3.5.7 does not advertise the heartbeat extension regardless of TLS version range",
		},
		{
			// OpenSSL 1.0.1f is Heartbleed-vulnerable; with TLS 1.2 enabled this scenario should
			// advertise the heartbeat extension and be reported as vulnerable.
			name:               "vulnerable_openssl_tls12_only",
			host:               "127.0.0.1",
			port:               "3443",
			tlsVersion:         tls.VersionTLS12,
			expectedVulnerable: "yes",
			expectedExtension:  true,
			reason:             "OpenSSL 1.0.1f advertises the heartbeat extension and is exploitable",
		},
		{
			name:               "vulnerable_openssl_tls10_plus",
			host:               "127.0.0.1",
			port:               "4443",
			tlsVersion:         tls.VersionTLS10,
			expectedVulnerable: "yes",
			expectedExtension:  true,
			reason:             "OpenSSL 1.0.1f advertises the heartbeat extension and is exploitable",
		},
		{
			name:               "vulnerable_openssl_sslv2_tls12",
			host:               "127.0.0.1",
			port:               "5443",
			tlsVersion:         tls.VersionTLS10,
			expectedVulnerable: "yes",
			expectedExtension:  true,
			reason:             "OpenSSL 1.0.1f advertises the heartbeat extension and is exploitable across all configured protocol versions",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("scenario: %s", tc.reason)

			host := envDefault("HEARTBLEED_"+tc.name+"_HOST", tc.host)
			port := envDefault("HEARTBLEED_"+tc.name+"_PORT", tc.port)

			waitForTCP(t, host, port)

			var result heartbleed.Heartbleed

			if err := result.Check(host, port, tc.tlsVersion); err != nil {
				t.Fatalf("heartbleed check returned unexpected error: %v", err)
			}

			if result.ExtensionEnabled != tc.expectedExtension {
				t.Errorf("expected heartbeat extension enabled=%v, got=%v\n  scenario: %s",
					tc.expectedExtension, result.ExtensionEnabled, tc.reason)
			}

			if result.Vulnerable != tc.expectedVulnerable {
				t.Errorf("expected vulnerable=%s, got vulnerable=%s\n  scenario: %s",
					tc.expectedVulnerable, result.Vulnerable, tc.reason)
			}
		})
	}
}
