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

	clientHello := buildClientHello(host)

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
				// Server closed before sending ServerHelloDone — unable to probe.
				ccs.Vulnerable = notVulnerable

				return nil
			}

			ccs.Vulnerable = testFailed

			return err
		}

		// If the server sent an alert during the handshake (e.g. protocol_version
		// or handshake_failure because it does not support TLS 1.0), it cannot be
		// exploited by CVE-2014-0224 which requires TLS ≤ 1.1 to be accepted.
		if header.Type == recordTypeAlert {
			ccs.Vulnerable = notVulnerable

			return nil
		}

		if header.Type != recordTypeHandshake {
			continue
		}

		// Guard against a malformed zero-length handshake record.
		if len(body) == 0 {
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

	// Read the server's response to the first CCS.
	//
	// Decision logic:
	//   - Any fatal alert (any description) → server actively rejected the CCS → not vulnerable.
	//   - Connection closed → server dropped the connection on bad input → not vulnerable.
	//   - Handshake / CCS / AppData record → server processed the CCS and continued
	//     the handshake → conclusively vulnerable.
	//   - No response (timeout) → server silently accepted CCS #1 and switched to
	//     encrypted mode. A second CCS is sent; ANY response (including a fatal alert
	//     from the now-confused server) confirms the vulnerability.
	//   - Warning-level alert → ambiguous; send a second CCS for confirmation.

	// ccs1TimedOut tracks whether CCS #1 went unanswered. When true, any response
	// to CCS #2 is a vulnerable signature (the server entered encrypted mode).
	ccs1TimedOut := false

	header, body, err := readTLSRecord(conn)
	if err == nil {
		if isFatalAlert(header, body) {
			// Any fatal alert is a definitive rejection.
			ccs.Vulnerable = notVulnerable

			return nil
		}

		if isContinuationRecord(header) {
			// Server processed the CCS and kept the handshake going.
			ccs.Vulnerable = vulnerable

			return nil
		}

		// Warning-level alert: ambiguous — fall through to second probe.
	} else {
		if isConnectionClosedErr(err) {
			// Server closed the connection on bad input — not vulnerable.
			ccs.Vulnerable = notVulnerable

			return nil
		}
		// Deadline exceeded: server accepted CCS #1 silently and switched to
		// encrypted mode. Mark this so the second probe is interpreted correctly.
		ccs1TimedOut = true
	}

	// Reset deadline before the second write.
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		ccs.Vulnerable = testFailed

		return err
	}

	// Send a second CCS.
	//   - If ccs1TimedOut: any server response (including a fatal alert triggered
	//     by the server trying to decrypt CCS #2 after switching cipher state)
	//     confirms the vulnerability. A second timeout also confirms it.
	//   - If ccs1 returned a warning: a fatal alert here means eventual rejection
	//     (not vulnerable); continuation or timeout means vulnerable.
	_, err = conn.Write(ccsMessage)
	if err != nil {
		if isConnectionClosedErr(err) {
			if ccs1TimedOut {
				// Server entered encrypted mode and then closed — vulnerable.
				ccs.Vulnerable = vulnerable
			} else {
				// Server closed after a warning on CCS #1 — treat as rejection.
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
			if ccs1TimedOut {
				// Connection closed after silent CCS #1 accept — vulnerable.
				ccs.Vulnerable = vulnerable
			} else {
				// Connection closed after warning on CCS #1 — deferred rejection.
				ccs.Vulnerable = notVulnerable
			}

			return nil
		}

		// Timeout on CCS #2: server accepted both silently — vulnerable.
		ccs.Vulnerable = vulnerable

		return nil
	}

	// Server responded to CCS #2.
	if isFatalAlert(header, body) {
		if ccs1TimedOut {
			// Fatal alert after a silent CCS #1 means the server entered encrypted
			// mode and is now failing to decrypt CCS #2 — conclusively vulnerable.
			ccs.Vulnerable = vulnerable
		} else {
			// Fatal alert after a warning on CCS #1 — server eventually rejected.
			ccs.Vulnerable = notVulnerable
		}

		return nil
	}

	// Any other response (continuation record or warning) after CCS #2 — vulnerable.
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

// isFatalAlert returns true for any fatal-level alert record, regardless of
// the alert description. Any fatal alert is an unambiguous rejection of the
// premature CCS — patched implementations may send unexpected_message (10),
// record_overflow (70), decode_error (50), or other codes.
func isFatalAlert(header *tlsRecordHeader, body []byte) bool {
	return header.Type == recordTypeAlert && len(body) >= 2 &&
		body[0] == alertLevelFatal
}

// isContinuationRecord returns true when the server responded to the premature
// CCS with a record that implies it processed the message and continued the
// handshake state machine — a conclusive sign of vulnerability.
func isContinuationRecord(header *tlsRecordHeader) bool {
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

// buildSNIExtension encodes a server_name_list for the given host per RFC 6066 §3.
// The resulting bytes are the extension data payload (type + length header written by caller).
func buildSNIExtension(host string) []byte {
	// Strip port if present (e.g. "example.com:443" → "example.com").
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	name := []byte(host)
	nameLen := len(name)
	// server_name_list:
	//   uint16  list_length  = 1 (name_type) + 2 (name_length) + nameLen
	//   uint8   name_type    = 0x00 (host_name)
	//   uint16  name_length
	//   []byte  name
	listLen := 1 + 2 + nameLen
	buf := make([]byte, 2+1+2+nameLen)
	binary.BigEndian.PutUint16(buf[0:], uint16(listLen)) // #nosec G115
	buf[2] = 0x00                                        // name_type: host_name
	binary.BigEndian.PutUint16(buf[3:], uint16(nameLen)) // #nosec G115
	copy(buf[5:], name)

	return buf
}

func buildClientHello(host string) []byte {
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

	// Client Version: TLS 1.0 (0x03 0x01).
	//
	// CVE-2014-0224 is a TLS ≤ 1.1 vulnerability. The distinguishing behaviour
	// (a vulnerable server silently accepting an out-of-order CCS vs. a patched
	// server rejecting it with a fatal alert) only manifests reliably when using
	// TLS 1.0 with an RSA key exchange. With TLS 1.2 and ECDHE, both vulnerable
	// and patched OpenSSL reject the premature CCS, making them indistinguishable.
	//
	// Servers that have TLS 1.0 disabled will send a protocol_version or
	// handshake_failure alert during the ServerHelloDone wait; those are handled
	// by the loop above and correctly reported as not vulnerable (a server that
	// does not accept TLS 1.0 cannot be exploited by this CVE).
	clientHello.Write([]byte{0x03, 0x01})

	// Random
	clientHello.Write(random)

	// Session ID
	clientHello.WriteByte(0x00)

	// Cipher Suites: RSA key-exchange only (no DHE/ECDHE).
	// RSA key exchange means no ServerKeyExchange message, so ServerHelloDone
	// immediately follows the Certificate. Vulnerable OpenSSL will silently accept
	// a CCS at this point; patched versions send a fatal alert.
	cipherSuites := []uint16{
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
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

	// Extensions
	sniData := buildSNIExtension(host)
	extBuf := new(bytes.Buffer)
	// SNI extension (type 0x0000)
	extBuf.Write([]byte{0x00, 0x00})
	_ = binary.Write(extBuf, binary.BigEndian, uint16(len(sniData))) // #nosec G115
	extBuf.Write(sniData)
	// Secure renegotiation (type 0xff01): empty
	extBuf.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00})
	_ = binary.Write(clientHello, binary.BigEndian, uint16(extBuf.Len())) // #nosec G115
	clientHello.Write(extBuf.Bytes())

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
