package ccs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

/*
CCS Injection vulnerability in OpenSSL (CVE-2014-0224)
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
	recordTypeApplicationData  = 23
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

// startTLSFunc is a package-level variable so it can be replaced in tests.
var startTLSFunc = starttls.StartTLS

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

	err = startTLSFunc(ctx, conn, port)
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

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
			if isConnectionClosedErr(err) {
				ccs.Vulnerable = notVulnerable

				return nil
			}

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

	err = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	firstResponseSuspicious := false

	header, body, err := readTLSRecord(conn)
	if err == nil {
		if isUnexpectedMessageAlert(header, body) {
			ccs.Vulnerable = notVulnerable

			return nil
		}

		if isFatalAlert(header, body) {
			firstResponseSuspicious = true
		}
	}

	// Reset deadline.
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	// Send a second CCS to confirm that the server does not reject the message.
	_, err = conn.Write(ccsMessage)
	if err != nil {
		if isConnectionClosedErr(err) {
			if firstResponseSuspicious {
				ccs.Vulnerable = vulnerable
			} else {
				ccs.Vulnerable = notVulnerable
			}
		} else {
			ccs.Vulnerable = vulnerable
		}

		return nil
	}

	err = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	header, body, err = readTLSRecord(conn)
	if err != nil {
		if isConnectionClosedErr(err) {
			if firstResponseSuspicious {
				ccs.Vulnerable = vulnerable
			} else {
				ccs.Vulnerable = notVulnerable
			}

			return nil
		}

		if firstResponseSuspicious {
			ccs.Vulnerable = vulnerable
		} else {
			ccs.Vulnerable = notVulnerable
		}

		return nil
	}

	if isUnexpectedMessageAlert(header, body) {
		ccs.Vulnerable = notVulnerable
		return nil
	}

	if isFatalAlert(header, body) {
		ccs.Vulnerable = vulnerable
		return nil
	}

	if isConfirmedVulnerableResponse(header, body) {
		ccs.Vulnerable = vulnerable
		return nil
	}

	ccs.Vulnerable = vulnerable

	return nil
}

func isConnectionClosedErr(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	var opErr *net.OpError

	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EPIPE) || errors.Is(opErr.Err, syscall.ECONNRESET) {
			return true
		}
	}

	return false
}

func isFatalAlert(header *tlsRecordHeader, body []byte) bool {
	return header.Type == recordTypeAlert && len(body) >= 2 && body[0] == alertLevelFatal
}

func isUnexpectedMessageAlert(header *tlsRecordHeader, body []byte) bool {
	return header.Type == recordTypeAlert && len(body) >= 2 &&
		body[0] == alertLevelFatal && body[1] == alertUnexpectedMessage
}

func isConfirmedVulnerableResponse(header *tlsRecordHeader, body []byte) bool {
	if header.Type == recordTypeAlert {
		if len(body) < 2 {
			return false
		}

		return body[0] != alertLevelFatal
	}

	// Any continuation of TLS state after malformed CCS strongly suggests
	// vulnerable behavior.
	return header.Type == recordTypeHandshake ||
		header.Type == recordTypeChangeCipherSpec ||
		header.Type == recordTypeApplicationData
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
	// A simplified but valid ClientHello.
	// The handshake length must match the bytes written in the payload,
	// otherwise many servers reject the message immediately.
	random := make([]byte, 32)

	_, err := rand.Read(random)
	if err != nil {
		return nil
	}

	clientHello := new(bytes.Buffer)
	// Handshake header: type + length placeholder
	clientHello.WriteByte(handshakeTypeClientHello)
	clientHello.Write([]byte{0x00, 0x00, 0x00})

	// Client Version (TLS 1.0) to match the CCS injection probe flow.
	clientHello.Write([]byte{0x03, 0x01})

	// Random
	clientHello.Write(random)

	// Session ID
	clientHello.WriteByte(0x00)

	// Cipher Suites
	cipherSuites := []uint16{0x0005, 0x000a, 0x002f, 0x0035}

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

	payloadBytes := clientHello.Bytes()
	handshakeLength := len(payloadBytes) - 4
	// high byte of 24-bit handshake length (0 for this small ClientHello)
	payloadBytes[1] = 0
	payloadBytes[2] = byte(uint16(handshakeLength) >> 8) // #nosec G115
	payloadBytes[3] = byte(uint16(handshakeLength))      // #nosec G115

	// Record header
	record := new(bytes.Buffer)
	record.WriteByte(recordTypeHandshake) // Record Type
	record.Write([]byte{0x03, 0x01})      // Version (TLS 1.0)

	err = binary.Write(record, binary.BigEndian, uint16(len(payloadBytes))) // #nosec G115
	if err != nil {
		return nil
	}

	record.Write(payloadBytes)

	return record.Bytes()
}
