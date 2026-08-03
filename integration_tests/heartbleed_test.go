//go:build integration

package integrationtests

import (
	"crypto/tls"
	"testing"

	"github.com/jsandas/tls-vuln-checker/vulnerabilities/heartbleed"
)

func TestHeartbleedNginxGood(t *testing.T) {
	host := envDefault("NGINX_GOOD_HOST", "127.0.0.1")
	port := envDefault("NGINX_GOOD_PORT", "443")

	waitForTCP(t, host, port)

	var result heartbleed.Heartbleed

	err := result.Check(host, port, tls.VersionTLS12)
	if err != nil {
		t.Fatalf("heartbleed check failed for good container: %v", err)
	}

	if result.Vulnerable != "n/a" {
		t.Fatalf("expected nginx_good heartbleed status n/a, got vulnerable=%s", result.Vulnerable)
	}

	if result.ExtensionEnabled {
		t.Fatalf("expected nginx_good heartbeat extension to be disabled")
	}
}

func TestHeartbleedNginxBad(t *testing.T) {
	host := envDefault("NGINX_BAD_HOST", "127.0.0.1")
	port := envDefault("NGINX_BAD_PORT", "8443")

	waitForTCP(t, host, port)

	var result heartbleed.Heartbleed

	err := result.Check(host, port, tls.VersionTLS12)
	if err != nil {
		t.Fatalf("heartbleed check failed for bad container: %v", err)
	}

	if result.Vulnerable != "n/a" {
		t.Fatalf("expected nginx_bad heartbleed status n/a, got vulnerable=%s", result.Vulnerable)
	}

	if result.ExtensionEnabled {
		t.Fatalf("expected nginx_bad heartbeat extension to be disabled")
	}
}
