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
}
