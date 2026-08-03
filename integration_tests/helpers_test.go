//go:build integration

package integrationtests

import (
	"net"
	"os"
	"testing"
	"time"
)

func envDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}

	return v
}

func waitForTCP(t *testing.T, host, port string) {
	t.Helper()

	addr := net.JoinHostPort(host, port)
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()

			return
		}

		time.Sleep(300 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for service on %s", addr)
}
