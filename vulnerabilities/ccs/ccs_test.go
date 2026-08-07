package ccs

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestCheckCCS(t *testing.T) {
	t.Run("SafeServer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lc := net.ListenConfig{}

		// Create a listener on a random port to act as our safe server
		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		// Start a goroutine to handle the single connection from the checker
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return // Listener was closed
			}
			defer conn.Close()

			// Read ClientHello
			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// Send ServerHelloDone
			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}

			// Read the first CCS message
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// A safe server sends a fatal alert for an unexpected CCS.
			alertMsg := []byte{recordTypeAlert, 0x03, 0x01, 0x00, 0x02, alertLevelFatal, alertUnexpectedMessage}

			conn.Write(alertMsg)
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			// A standard TLS server should not produce an error during the check
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != notVulnerable {
			t.Errorf("Expected server to be not vulnerable, got: %s", r.Vulnerable)
		}
	})

	t.Run("ConnectFail", func(t *testing.T) {
		var r CCSInjection

		err := r.Check("127.0.0.1", "1") // Use a port that is likely not open
		if err == nil {
			t.Fatal("Expected a connection error, but got nil")
		}
	})

	t.Run("NoResponseServer", func(t *testing.T) {
		old := startTLSFunc
		startTLSFunc = func(ctx context.Context, conn net.Conn, port string) error { return nil }

		t.Cleanup(func() { startTLSFunc = old })

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		defer cancel()

		lc := net.ListenConfig{}

		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != notVulnerable {
			t.Errorf("Expected server to be not vulnerable when it closes after unexpected CCS, got: %s", r.Vulnerable)
		}
	})

	t.Run("VulnerableServer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lc := net.ListenConfig{}

		// Create a listener on a random port to act as our vulnerable server
		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		// Start a goroutine to handle the single connection from the checker
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return // Listener was closed
			}
			defer conn.Close()

			// The checker will send a ClientHello. We must read it.
			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// To advance the client's state machine, we send a ServerHelloDone.
			// This signals that the server part of the handshake is over.
			// Record Header: Handshake, TLS 1.0, length 4
			// Handshake Header: ServerHelloDone, length 0
			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}

			// The client will now send its first CCS message. A vulnerable server
			// will incorrectly process it. We simulate this by reading and ignoring it.
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// The client's check for an immediate alert will time out. It will then send a second CCS.
			// We read and ignore that one as well.
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// The client now expects a response. A vulnerable server would not send the
			// expected 'unexpected_message' alert. We send a dummy application data record
			// to confirm the vulnerability.
			appData := []byte{0x17, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
			conn.Write(appData)

			// Wait for the client to close the connection to avoid EOF.
			// The client will close the connection when the Check function returns.
			// We read until we get an error, which will be io.EOF when the client
			// closes its side.
			io.Copy(io.Discard, conn)
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != vulnerable {
			t.Errorf("Expected server to be vulnerable, got: %s", r.Vulnerable)
		}
	})

	t.Run("FatalAlertNonUnexpectedMessageIsNotVulnerable", func(t *testing.T) {
		// A server that responds to the premature CCS with a fatal alert of any
		// description (not just unexpected_message) is still actively rejecting
		// the message — it must be treated as NOT vulnerable.
		// Patched OpenSSL 1.1.x typically sends record_overflow (70) or
		// decode_error (50) rather than unexpected_message (10).
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lc := net.ListenConfig{}

		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			// Simulate patched OpenSSL 1.1.x: fatal alert with desc=70 (record_overflow).
			fatalAlert := []byte{recordTypeAlert, 0x03, 0x01, 0x00, 0x02, alertLevelFatal, 0x46}
			_, _ = conn.Write(fatalAlert)
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != notVulnerable {
			t.Errorf("Expected server to be NOT vulnerable when it responds with any fatal alert, "+
				"got: %s", r.Vulnerable)
		}
	})

	t.Run("SuspiciousThenFatalIsNotVulnerable", func(t *testing.T) {
		// A server that responds to CCS #1 with a warning-level alert (ambiguous)
		// but then rejects CCS #2 with a fatal alert should be reported as not vulnerable.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lc := net.ListenConfig{}

		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}

			// Read first CCS and respond with a warning alert (ambiguous — not a definitive rejection).
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			warningAlert := []byte{recordTypeAlert, 0x03, 0x01, 0x00, 0x02, 0x01, alertUnexpectedMessage}

			_, err = conn.Write(warningAlert)
			if err != nil {
				return
			}

			// Read second CCS and then send fatal alert to indicate proper rejection.
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			fatalAlert := []byte{recordTypeAlert, 0x03, 0x01, 0x00, 0x02, alertLevelFatal, alertUnexpectedMessage}
			_, _ = conn.Write(fatalAlert)
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != notVulnerable {
			t.Errorf("Expected server to be not vulnerable after fatal second response, got: %s", r.Vulnerable)
		}
	})

	t.Run("AppDataResponseIsVulnerable", func(t *testing.T) {
		// A server that responds to the first CCS with application data has
		// clearly processed the out-of-order CCS — conclusively vulnerable.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		lc := net.ListenConfig{}

		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 2048)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			serverHelloDoneMsg := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, 0x04,
				handshakeTypeServerHelloDone, 0x00, 0x00, 0x00}

			_, err = conn.Write(serverHelloDoneMsg)
			if err != nil {
				return
			}

			// Read CCS and respond with application data (server accepted and continued).
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))

			_, err = conn.Read(buf)
			if err != nil {
				return
			}

			appData := []byte{recordTypeApplicationData, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
			_, _ = conn.Write(appData)

			io.Copy(io.Discard, conn)
		}()

		host, port, _ := net.SplitHostPort(ln.Addr().String())

		var r CCSInjection

		err = r.Check(host, port)
		if err != nil {
			t.Fatalf("Check failed with an unexpected error: %v", err)
		}

		if r.Vulnerable != vulnerable {
			t.Errorf("Expected server to be vulnerable when it responds with AppData, got: %s", r.Vulnerable)
		}
	})
}
