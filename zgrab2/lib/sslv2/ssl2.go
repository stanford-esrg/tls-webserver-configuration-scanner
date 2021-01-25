/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package sslv2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"github.com/zmap/zgrab2/lib/sslv2/x509"
)

// Protocol message codes
const (
	MSG_TYPE_CLIENT_HELLO      byte = 1
	MSG_TYPE_SERVER_HELLO      byte = 4
	MSG_TYPE_CLIENT_MASTER_KEY byte = 2
)

// Version codes
const (
	SSL_VERSION_2 uint16 = 0x0002
)

// ErrInvalidLength is returned when a byte slice to be Unmarshaled is too
// short, or when a single record length is greater than the max length of 32512
// bytes.
var ErrInvalidLength = errors.New("Invalid SSLv2 packet length")

var ErrUnexpectedMessage = errors.New("Unexpected message type")

type Header struct {
	Length        uint16
	PaddingLength uint8
	raw           []byte
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *Header) MarshalBinary() (b []byte, err error) {
	// Only supports 2 byte headers
	if h.Length > uint16(MAX_TWO_BYTE_RECORD_BYTES) {
		err = ErrInvalidLength
		return
	}
	b = make([]byte, 2)
	b[0] = byte(h.Length >> 8)
	b[1] = byte(h.Length)
	b[0] |= 0x80
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *Header) UnmarshalBinary(b []byte) (err error) {
	if len(b) < 2 {
		return ErrInvalidLength
	}
	hasPadding := b[0]&0x80 == 0
	if hasPadding && len(b) < 3 {
		return ErrInvalidLength
	}
	h.Length = uint16(b[0]&0x7f)<<8 | uint16(b[1])
	if hasPadding {
		h.PaddingLength = b[2]
		h.raw = b[0:3]
	} else {
		h.raw = b[0:2]
	}
	return
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *ServerHello) MarshalBinary() (b []byte, err error) {
	// 1 byte version
	// 1 byte did-hit-session-id
	// 1 byte certificate type
	// 2 byte version
	// Three 2-byte lengths for each variable length field
	// The fields themselves
	length := 1 + 1 + 1 + 2 + 2*3 + len(h.Certificate.Raw) + 3*len(h.Ciphers) + len(h.ConnectionID)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_TYPE_SERVER_HELLO
	buf[1] = h.SessionIDHit
	buf[2] = h.CertificateType
	buf = buf[3:]

	// Version
	binary.BigEndian.PutUint16(buf, h.Version)
	buf = buf[2:]

	// Put in all the lengths
	binary.BigEndian.PutUint16(buf, uint16(len(h.Certificate.Raw)))
	buf = buf[2:]

	binary.BigEndian.PutUint16(buf, uint16(3*len(h.Ciphers)))
	buf = buf[2:]

	binary.BigEndian.PutUint16(buf, uint16(len(h.ConnectionID)))
	buf = buf[2:]

	// Copy all the remaining fields
	buf = buf[len(h.Certificate.Raw):]

	encodedCiphers := buf
	for idx, cipher := range h.Ciphers {
		b := encodedCiphers[3*idx : 3*idx+3]
		b[0] = byte((cipher & 0x00FF0000) >> 16)
		b[1] = byte((cipher & 0x0000FF00) >> 8)
		b[2] = byte(cipher)
	}

	copy(buf, encodedCiphers)
	buf = buf[len(encodedCiphers):]

	copy(buf, h.ConnectionID)
	buf = buf[len(h.ConnectionID):]

	// And we're done
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *ServerHello) UnmarshalBinary(b []byte) (err error) {
	if len(b) < 11 {
		return ErrInvalidLength
	}
	if b[0] != MSG_TYPE_SERVER_HELLO {
		return ErrUnexpectedMessage
	}
	h.SessionIDHit = b[1]
	h.CertificateType = b[2]
	h.Version = binary.BigEndian.Uint16(b[3:5])
	certificateLength := int(binary.BigEndian.Uint16(b[5:7]))
	cipherSpecsLength := int(binary.BigEndian.Uint16(b[7:9]))
	connectionIDLength := int(binary.BigEndian.Uint16(b[9:11]))
	variableLength := certificateLength + cipherSpecsLength + connectionIDLength
	totalLength := 11 + variableLength

	buf := b[11:]
	if len(buf) < variableLength {
		return ErrInvalidLength
	}
	h.Certificate = new(ServerCertificate)
	h.Certificate.Raw = make([]byte, certificateLength)
	copy(h.Certificate.Raw, buf[0:certificateLength])
	buf = buf[certificateLength:]

	if cipherSpecsLength%3 != 0 {
		return fmt.Errorf("invalid cipher specs length %d, must be a multiple of 3", cipherSpecsLength)
	}

	h.Ciphers = make([]CipherKind, cipherSpecsLength/3)
	for idx := range h.Ciphers {
		b := buf[3*idx : 3*idx+3]
		h.Ciphers[idx].UnmarshalBinary(b)
	}
	buf = buf[cipherSpecsLength:]
	h.ConnectionID = buf[0:connectionIDLength]
	h.raw = b[0:totalLength]

	// Parse the certificates
	h.Certificate.Certificate, _ = x509.ParseCertificate(h.Certificate.Raw)
	return
}

type HandshakeData struct {
	ClientHello  *ClientHello  `json:"client_hello,omitempty"`
	ServerHello  *ServerHello  `json:"server_hello,omitempty"`
	ServerVerify *ServerVerify `json:"server_verify,omitempty"`
}

func Client(c net.Conn, config *Config) *Conn {
	ssl := &Conn{
		nc:       c,
		isServer: false,
		config:   config,
	}
	return ssl
}
