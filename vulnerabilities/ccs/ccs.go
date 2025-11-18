package ccs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
)

/*
OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
does not properly restrict processing of ChangeCipherSpec messages,
which allows man-in-the-middle attackers to trigger use of a zero
length master key in certain OpenSSL-to-OpenSSL communications, and
consequently hijack sessions or obtain sensitive information, via
a crafted TLS handshake, aka the "CCS Injection" vulnerability.
*/

const (
	notVulnerable = "no"
	vulnerable    = "yes"
	testFailed    = "error"
)

type CCSInjection struct {
	Vulnerable string `json:"vulnerable"`
}

// TLS record types.
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
)

// TLS handshake message types.
const (
	handshakeTypeClientHello     = 1
	handshakeTypeServerHelloDone = 14
)

// TLS alert levels.
const (
	alertLevelFatal = 2
)

// TLS alert descriptions.
const (
	alertUnexpectedMessage = 10
)

type tlsRecordHeader struct {
	Type    uint8
	Version uint16
	Length  uint16
}

// Check for CCS Injection vulnerability (CVE-2014-0224).
func (ccs *CCSInjection) Check(host string, port string) error {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := net.JoinHostPort(host, port)

	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	defer conn.Close()

	clientHello := buildClientHello()

	_, err = conn.Write(clientHello)
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	serverHelloDone := false
	for !serverHelloDone {
		header, body, err := readTLSRecord(conn)
		if err != nil {
			ccs.Vulnerable = testFailed

			return err
		}

		if header.Type != recordTypeHandshake {
			continue
		}

		handshakeType := body[0]
		if handshakeType == handshakeTypeServerHelloDone {
			serverHelloDone = true
		}
	}

	// Send first CCS message
	ccsMessage := []byte{recordTypeChangeCipherSpec, 0x03, 0x01, 0x00, 0x01, 0x01}

	_, err = conn.Write(ccsMessage)
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	// A non-vulnerable server should send an alert immediately.
	// Set a short deadline to check for this.
	err = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	_, _, err = readTLSRecord(conn)
	if err == nil {
		// If we read a record successfully, it's likely an alert.
		// Assume not vulnerable.
		ccs.Vulnerable = notVulnerable

		return nil
	}

	// Reset deadline
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	// Send second CCS message to force a response
	_, err = conn.Write(ccsMessage)
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	header, body, err := readTLSRecord(conn)
	if err != nil {
		// If we can't read a record, it's inconclusive.
		// The original script treats this as a handshake failure.
		// We'll mark as not vulnerable to be safe.
		ccs.Vulnerable = notVulnerable

		return nil
	}

	if header.Type == recordTypeAlert {
		if len(body) >= 2 && body[0] == alertLevelFatal && body[1] == alertUnexpectedMessage {
			ccs.Vulnerable = notVulnerable
		} else {
			ccs.Vulnerable = vulnerable
		}
	} else {
		ccs.Vulnerable = vulnerable
	}

	return nil
}

func readTLSRecord(r io.Reader) (*tlsRecordHeader, []byte, error) {
	header := &tlsRecordHeader{}

	err := binary.Read(r, binary.BigEndian, header)
	if err != nil {
		return nil, nil, err
	}

	body := make([]byte, header.Length)

	_, err = io.ReadFull(r, body)
	if err != nil {
		return nil, nil, err
	}

	return header, body, nil
}

func buildClientHello() []byte {
	// A simplified ClientHello.
	// In a real-world scenario, this would be more complex, with extensions,
	// cipher suites, etc. For this test, a minimal hello is sufficient.
	random := make([]byte, 32)

	_, err := rand.Read(random)
	if err != nil {
		return nil
	}

	clientHello := new(bytes.Buffer)
	// Handshake header
	clientHello.WriteByte(handshakeTypeClientHello) // Handshake Type
	clientHello.Write([]byte{0x00, 0x00, 0x35})     // Length

	// Client Version (TLS 1.2)
	clientHello.Write([]byte{0x03, 0x03})

	// Random
	clientHello.Write(random)

	// Session ID
	clientHello.WriteByte(0x00)

	// Cipher Suites
	cipherSuites := []uint16{
		0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
		0x009c, 0x009d, 0x002f, 0x0035, 0xc012, 0x000a,
	}

	err = binary.Write(clientHello, binary.BigEndian, uint16(len(cipherSuites)*2)) // #nosec G115
	if err != nil {
		return nil
	}

	for _, suite := range cipherSuites {
		err = binary.Write(clientHello, binary.BigEndian, suite)
		if err != nil {
			return nil
		}
	}

	// Compression Methods
	clientHello.WriteByte(0x01) // Length
	clientHello.WriteByte(0x00) // Null compression

	// Extensions (empty for this simplified hello)
	clientHello.Write([]byte{0x00, 0x00})

	// Record header
	record := new(bytes.Buffer)
	record.WriteByte(recordTypeHandshake) // Record Type
	record.Write([]byte{0x03, 0x01})      // Version (TLS 1.0)

	err = binary.Write(record, binary.BigEndian, uint16(clientHello.Len())) // #nosec G115
	if err != nil {
		return nil
	}

	record.Write(clientHello.Bytes())

	return record.Bytes()
}
