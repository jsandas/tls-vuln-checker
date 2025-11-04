package heartbleed

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeartbleedExtensionDisabled(t *testing.T) {
	// Start a local HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Header().Set("Server", "Apache")
			rw.Write([]byte("Hello"))
		}
	}))
	// Close the server when test finishes d
	defer server.Close()

	s := strings.ReplaceAll(server.URL, "https://", "")
	host, port, _ := net.SplitHostPort(s)

	var r Heartbleed

	r.Check(host, port, 771)

	if r.Vulnerable == vulnerable || r.ExtensionEnabled {
		t.Errorf("Wrong return, got: %s/%v, want: %s/%v.", r.Vulnerable, r.ExtensionEnabled, notApplicable, false)
	}

	var rTLS13 Heartbleed
	rTLS13.Check(host, port, 772)

	if rTLS13.Vulnerable == vulnerable || rTLS13.ExtensionEnabled {
		t.Errorf("Wrong return, got: %v/%v, want: %s/%v.", rTLS13.Vulnerable, rTLS13.ExtensionEnabled, notVulnerable, false)
	}
}

func TestHeartBleedConnectFail(t *testing.T) {
	var r Heartbleed

	err := r.Check("127.0.0.1", "4242", 771)
	if err == nil {
		t.Errorf("Wrong return, got: %s, want: error message", err)
	}
}
