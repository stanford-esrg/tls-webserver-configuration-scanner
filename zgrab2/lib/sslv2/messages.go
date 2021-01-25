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
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/zmap/zgrab2/lib/sslv2/x509"
)

type ClientHello struct {
	Version   uint16       `json:"version"`
	Ciphers   []CipherKind `json:"ciphers,omitempty"`
	SessionID []byte       `json:"session_id,omitempty"`
	Challenge []byte       `json:"challenge,omitempty"`
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *ClientHello) MarshalBinary() (b []byte, err error) {
	// 1 byte flag + 2 byte version + 3 2-byte lengths of the variable len fields
	length := 1 + 2 + 2*3 + len(h.Ciphers)*3 + len(h.SessionID) + len(h.Challenge)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_TYPE_CLIENT_HELLO
	buf = buf[1:]
	binary.BigEndian.PutUint16(buf, h.Version)
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.Ciphers)*3))
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.SessionID)))
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.Challenge)))
	buf = buf[2:]

	encodedCiphers := make([]byte, 3*len(h.Ciphers))
	for idx, cipher := range h.Ciphers {
		b := encodedCiphers[3*idx : 3*idx+3]
		b[0] = byte((cipher & 0x00FF0000) >> 16)
		b[1] = byte((cipher & 0x0000FF00) >> 8)
		b[2] = byte(cipher)
	}

	copy(buf, encodedCiphers)
	buf = buf[len(encodedCiphers):]
	copy(buf, h.SessionID)
	buf = buf[len(h.SessionID):]
	copy(buf, h.Challenge)
	buf = buf[len(h.Challenge):]
	return
}

type ServerCertificate struct {
	Raw         []byte            `json:"raw,omitempty"`
	Certificate *x509.Certificate `json:"parsed,omitempty"`
}

type ServerHello struct {
	SessionIDHit    byte               `json:"session_id_hit"`
	CertificateType byte               `json:"certificate_type"`
	Version         uint16             `json:"version"`
	Certificate     *ServerCertificate `json:"certificate,omitempty"`
	Ciphers         []CipherKind       `json:"ciphers,omitempty"`
	ConnectionID    []byte             `json:"connection_id,omitempty"`

	raw []byte
}

// The ClientMasterKey struct represents the client-master-key message in the SSLv2
// handshake protocol. The structure of the message is:
//   client-master-key {
//     char MSG-CLIENT-MASTER-KEY
//     char CIPHER-KIND[3]
//     char CLEAR-KEY-LENGTH-MSB
//     char CLEAR-KEY-LENGTH-LSB
//     char ENCRYPTED-KEY-LENGTH-MSB
//     char ENCRYPTED-KEY-LENGTH-LSB
//     char KEY-ARG-LENGTH-MSB
//     char KEY-ARG-LENGTH-LSB
//     char CLEAR-KEY-DATA[MSB<<8|LSB]
//     char ENCRYPTED-KEY-DATA[MSB<<8|LSB]
//     char KEY-ARG-DATA[MSB<<8|LSB]
// }
//
// See http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
type ClientMasterKey struct {
	CipherKind   CipherKind
	ClearKey     []byte
	EncryptedKey []byte
	KeyArg       []byte
}

// MarshalSSLv2 implments the marshaler interface
func (cmk *ClientMasterKey) MarshalSSLv2() (b []byte, err error) {

	// Validate all the lengths fit within the max sizes
	if len(cmk.ClearKey) > 0xFFFF {
		err = fmt.Errorf("ClearKey too long: %d", len(cmk.ClearKey))
		return
	}
	if len(cmk.EncryptedKey) > 0xFFFF {
		err = fmt.Errorf("EncryptedKey too long: %d", len(cmk.EncryptedKey))
		return
	}
	if len(cmk.KeyArg) > 0xFFFF {
		err = fmt.Errorf("KeyArg too long: %d", len(cmk.KeyArg))
		return
	}

	// Write out the bytes
	buf := new(bytes.Buffer)
	mw := newMessageWriter(buf)
	mw.Write([]byte{MSG_TYPE_CLIENT_MASTER_KEY})
	mw.WriteMarshaler(&cmk.CipherKind)
	clearKeyLength := uint16(len(cmk.ClearKey))
	encryptedKeyLength := uint16(len(cmk.EncryptedKey))
	keyArgLength := uint16(len(cmk.KeyArg))
	binary.Write(mw, binary.BigEndian, clearKeyLength)
	binary.Write(mw, binary.BigEndian, encryptedKeyLength)
	binary.Write(mw, binary.BigEndian, keyArgLength)
	mw.Write(cmk.ClearKey)
	mw.Write(cmk.EncryptedKey)
	mw.Write(cmk.KeyArg)

	return buf.Bytes(), mw.Error()
}

type ServerVerify struct {
	Raw         []byte `json:"-"`
	MessageType int    `json:"-"`
	Challenge   []byte `json:"-"`
	Valid       bool   `json:"valid"`
	ExtraClear  bool   `json:"extra_clear,omitempty"`
}
