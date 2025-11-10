package heartbleed

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestHeartbleedExtensionEnabled starts a minimal TCP server that
// responds with a ServerHello-like byte sequence containing the
// heartbeat extension (0x000f) and verifies that the Heartbleed
// check detects that the extension is enabled.
func TestCheckExtensionDetectsHeartbeat(t *testing.T) {
	// Build a ServerHello-like byte sequence that contains the
	// heartbeat extension bytes (00 0f 00 01 01) and the
	// serverHello finished marker (0e000000). The checkExtension
	// function only looks for those substrings in the read stream,
	// so we can test detection without performing a full TLS
	// handshake.
	data := []byte{
		0x16, 0x03, 0x03, 0x00, 0x11,
		0x02, 0x00, 0x00, 0x0d,
		0x03, 0x03,
	}
	data = append(data, make([]byte, 8)...)
	// heartbeat extension: type(0x000f) length(0x0001) value(0x01)
	data = append(data, 0x00, 0x0f, 0x00, 0x01, 0x01)
	// serverHello finished marker
	data = append(data, 0x0e, 0x00, 0x00, 0x00)

	r := bufio.NewReader(bytes.NewReader(data))

	enabled, err := checkExtension(r)
	if err != nil {
		t.Fatalf("checkExtension returned error: %v", err)
	}

	if !enabled {
		t.Fatalf("expected heartbeat extension to be detected, got false")
	}
}

// TestHeartbleedOnPort443 attempts to bind a TCP server on 127.0.0.1:443 and
// exercise the full Check path. The test is skipped if binding to port 443
// fails (insufficient privileges or port in use).
func TestHeartbleedWithMockStartTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Start a server goroutine that responds with a ServerHello-like
	// byte sequence containing the heartbeat extension so the
	// check path will detect it.
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the ClientHello sent by the check
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		tmp := make([]byte, 8192)
		_, _ = conn.Read(tmp)

		// Build ServerHello-like response containing heartbeat extension
		resp := []byte{
			0x16, 0x03, 0x03, 0x00, 0x11,
			0x02, 0x00, 0x00, 0x0d,
			0x03, 0x03,
		}
		resp = append(resp, make([]byte, 8)...)
		// heartbeat extension: type(0x000f) length(0x0001) value(0x01)
		resp = append(resp, 0x00, 0x0f, 0x00, 0x01, 0x01)
		// serverHello finished marker
		resp = append(resp, 0x0e, 0x00, 0x00, 0x00)

		_, _ = conn.Write(resp)

		// Read the heartbeat payload that the client sends
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(tmp)

		// Send a large heartbeat response (>1600 bytes) to trigger vulnerability detection
		// Format: record type (0x18) | TLS version (0x0303) | length (2 bytes) | payload
		largePayload := make([]byte, 2000) // Well over the 1600 byte threshold
		for i := range largePayload {
			largePayload[i] = byte(i & 0xff) // Fill with a repeating pattern
		}

		heartbeatResp := []byte{
			0x18,       // Heartbeat record type
			0x03, 0x03, // TLS 1.2
		}
		// Add length (2 bytes, big-endian)
		heartbeatResp = append(heartbeatResp, byte(len(largePayload)>>8), byte(len(largePayload)))
		// Add the actual payload
		heartbeatResp = append(heartbeatResp, largePayload...)

		_, _ = conn.Write(heartbeatResp)
	}()

	defer func() { <-serverDone }() // Wait for server goroutine to finish

	host := "127.0.0.1"
	port := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)

	// Mock startTLSFunc so the Check function doesn't attempt a real
	// StartTLS handshake; our test server already returns the bytes
	// expected by the parser.
	old := startTLSFunc
	startTLSFunc = func(ctx context.Context, conn net.Conn, port string) error { return nil }

	defer func() { startTLSFunc = old }()

	var h Heartbleed

	err = h.Check(host, port, 771)
	if err != nil {
		t.Fatalf("Heartbleed.Check failed: %v", err)
	}

	if !h.ExtensionEnabled {
		t.Fatalf("expected heartbeat extension to be detected")
	}

	if h.Vulnerable != vulnerable {
		t.Fatalf("expected server to be detected as vulnerable when returning large payload, got status=%s", h.Vulnerable)
	}

	fmt.Printf("TestHeartbleedWithMockStartTLS completed: extension=%v vulnerable=%s\n", h.ExtensionEnabled, h.Vulnerable)
}
