//go:build integration

package integrationtests

import (
	"testing"

	"github.com/jsandas/tls-vuln-checker/vulnerabilities/ccs"
)

func TestCCSInjectionNginxGood(t *testing.T) {
	host := envDefault("NGINX_GOOD_HOST", "127.0.0.1")
	port := envDefault("NGINX_GOOD_PORT", "443")
	expected := envDefault("NGINX_GOOD_EXPECTED_CCS", "no")

	waitForTCP(t, host, port)

	var result ccs.CCSInjection

	err := result.Check(host, port)
	if err != nil {
		t.Fatalf("CCS check failed for good container: %v", err)
	}

	if result.Vulnerable != expected {
		t.Fatalf("expected nginx_good CCS result %s, got vulnerable=%s", expected, result.Vulnerable)
	}
}

	host := envDefault("NGINX_BAD_HOST", "127.0.0.1")
	port := envDefault("NGINX_BAD_PORT", "8443")
	expected := envDefault("NGINX_BAD_EXPECTED_CCS", "yes")
	waitForTCP(t, host, port)

	var result ccs.CCSInjection

	err := result.Check(host, port)
	if err != nil {
		t.Fatalf("CCS check failed for bad container: %v", err)
	}

	if result.Vulnerable != expected {
		t.Fatalf("expected nginx_bad CCS result %s, got vulnerable=%s", expected, result.Vulnerable)
	}
}
