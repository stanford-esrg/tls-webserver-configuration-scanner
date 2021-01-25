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
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/json"
	"fmt"

	"github.com/dadrian/go-idea"
	"github.com/dadrian/rc2"
)

// CipherKind holds a 3-byte ID for a cipher spec. It is invalid for a
// CipherKind to be greater than 0x00FFFFFF
type CipherKind uint32

// Standard SSLv3 CipherKinds
const (
	SSL_CK_RC4_128_WITH_MD5              CipherKind = 0x010080
	SSL_CK_RC4_128_EXPORT40_WITH_MD5     CipherKind = 0x020080
	SSL_CK_RC2_128_CBC_WITH_MD5          CipherKind = 0x030080
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 CipherKind = 0x040080
	SSL_CK_IDEA_128_CBC_WITH_MD5         CipherKind = 0x050080
	SSL_CK_DES_64_CBC_WITH_MD5           CipherKind = 0x060040
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5     CipherKind = 0x0700C0
)

var AllCiphers = []CipherKind{
	SSL_CK_RC4_128_WITH_MD5,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5,
	SSL_CK_RC2_128_CBC_WITH_MD5,
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSL_CK_IDEA_128_CBC_WITH_MD5,
	SSL_CK_DES_64_CBC_WITH_MD5,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
}

var nonExportCiphers = []CipherKind{
	SSL_CK_RC4_128_WITH_MD5,
	SSL_CK_RC2_128_CBC_WITH_MD5,
	SSL_CK_IDEA_128_CBC_WITH_MD5,
	SSL_CK_DES_64_CBC_WITH_MD5,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
}

var ExportCiphers = []CipherKind{
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5,
}

// SSLv2CipherFromTLS returns an SSLv2 object representing a cipher from SSLv3
// or newer.
func SSLv2CipherFromTLS(newCipher uint32) CipherKind {
	return CipherKind(newCipher)
}

// MarshalBinary implements the binary marshaler interface
func (ck *CipherKind) MarshalSSLv2() ([]byte, error) {
	cku := uint32(*ck)
	// Ciphers can only be three bytes
	if cku > 0x00FFFFFF {
		return nil, fmt.Errorf("invalid cipher id %d", cku)
	}
	out := []byte{
		byte(cku >> 16),
		byte(cku >> 8),
		byte(cku),
	}
	return out, nil
}

// UnmarshalBinary implements the BinaryUnmarshler interface
func (ck *CipherKind) UnmarshalBinary(b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("buffer too short for CipherKind: %d", len(b))
	}
	var cku uint32
	cku = (uint32(b[0]) << 16) + (uint32(b[1]) << 8) + uint32(b[2])
	*ck = CipherKind(cku)
	return nil
}

func (ck *CipherKind) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name string `json:"name,omitempty"`
		ID   int    `json:"id,omitempty"`
	}{}
	name, _ := ciphersToNames[*ck]
	aux.Name = name
	aux.ID = int(*ck)
	return json.Marshal(aux)
}

func findCommonCipher(base, options []CipherKind) (ck CipherKind, ok bool) {
	for _, b := range base {
		for _, o := range options {
			if b == o {
				return b, true
			}
		}
	}
	return
}

type keyDerivationFunc func([]byte, []byte, []byte) ([]byte, []byte)

func eightByteDerivation(masterKey, challenge, connectionID []byte) (clientReadKey, clientWriteKey []byte) {
	// Implements the following key derivation for the following ciphers:
	// 	SSL_CK_DES_64_CBC_WITH_MD5
	// 		KEY-MATERIAL-0 = MD5[ MASTER-KEY, CHALLENGE, CONNECTION-ID ]
	// 		CLIENT-READ-KEY = KEY-MATERIAL-0[0-7]
	//		CLIENT-WRITE-KEY = KEY-MATERIAL-0[8-15]
	h0 := md5.New()
	h0.Write(masterKey)
	h0.Write([]byte("0"))
	h0.Write(challenge)
	h0.Write(connectionID)
	km0 := h0.Sum(nil)

	clientReadKey = km0[0:8]
	clientWriteKey = km0[8:16]
	return
}

func sixteenByteDerivation(masterKey, challenge, connectionID []byte) (clientReadKey, clientWriteKey []byte) {
	// Implements the following key derivation for the following ciphers:
	// 	SSL_CK_RC4_128_WITH_MD5
	// 	SSL_CK_RC4_128_EXPORT40_WITH_MD5
	// 	SSL_CK_RC2_128_CBC_WITH_MD5
	// 	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
	// 	SSL_CK_IDEA_128_CBC_WITH_MD5
	// 		KEY-MATERIAL-0 = MD5[ MASTER-KEY, "0", CHALLENGE, CONNECTION-ID ]
	// 		KEY-MATERIAL-1 = MD5[ MASTER-KEY, "1", CHALLENGE, CONNECTION-ID ]
	// 		CLIENT-READ-KEY = KEY-MATERIAL-0[0-15]
	// 		CLIENT-WRITE-KEY = KEY-MATERIAL-1[0-15]
	h0 := md5.New()
	h0.Write(masterKey)
	h0.Write([]byte("0"))
	h0.Write(challenge)
	h0.Write(connectionID)
	km0 := h0.Sum(nil)

	h1 := md5.New()
	h1.Write(masterKey)
	h1.Write([]byte("1"))
	h1.Write(challenge)
	h1.Write(connectionID)
	km1 := h1.Sum(nil)

	clientReadKey = km0[0:16]
	clientWriteKey = km1[0:16]
	return
}

func twentyFourByteDerivation(masterKey, challenge, connectionID []byte) (clientReadKey, clientWriteKey []byte) {
	// Implements key derivation for the following ciphers:
	//	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	// 		KEY-MATERIAL-0 = MD5[ MASTER-KEY, "0", CHALLENGE, CONNECTION-ID ]
	// 		KEY-MATERIAL-1 = MD5[ MASTER-KEY, "1", CHALLENGE, CONNECTION-ID ]
	// 		KEY-MATERIAL-2 = MD5[ MASTER-KEY, "2", CHALLENGE, CONNECTION-ID ]
	//		CLIENT-READ-KEY-0 = KEY-MATERIAL-0[0-7]
	// 		CLIENT-READ-KEY-1 = KEY-MATERIAL-0[8-15]
	// 		CLIENT-READ-KEY-2 = KEY-MATERIAL-1[0-7]
	// 		CLIENT-WRITE-KEY-0 = KEY-MATERIAL-1[8-15]
	// 		CLIENT-WRITE-KEY-1 = KEY-MATERIAL-2[0-7]
	// 		CLIENT-WRITE-KEY-2 = KEY-MATERIAL-2[8-15]
	h0 := md5.New()
	h0.Write(masterKey)
	h0.Write([]byte("0"))
	h0.Write(challenge)
	h0.Write(connectionID)
	km0 := h0.Sum(nil)

	h1 := md5.New()
	h1.Write(masterKey)
	h1.Write([]byte("1"))
	h1.Write(challenge)
	h1.Write(connectionID)
	km1 := h1.Sum(nil)

	h2 := md5.New()
	h2.Write(masterKey)
	h2.Write([]byte("2"))
	h2.Write(challenge)
	h2.Write(connectionID)
	km2 := h2.Sum(nil)
	clientReadKey = append(clientReadKey, km0[0:8]...)
	clientReadKey = append(clientReadKey, km0[8:16]...)
	clientReadKey = append(clientReadKey, km1[0:8]...)

	clientWriteKey = append(clientWriteKey, km1[8:16]...)
	clientWriteKey = append(clientWriteKey, km2[0:8]...)
	clientWriteKey = append(clientWriteKey, km2[8:16]...)
	return
}

func cipherDES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherRC2(key, iv []byte, isRead bool) interface{} {
	block, _ := rc2.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherIDEA(key, iv []byte, isRead bool) interface{} {
	block, _ := idea.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type cipherSuite struct {
	id CipherKind

	clearKeyLen, encKeyLen, keyArgLen int

	deriveKey keyDerivationFunc
	cipher    func(key, iv []byte, isRead bool) interface{}
}

var cipherImplementations []*cipherSuite = []*cipherSuite{
	{SSL_CK_RC4_128_WITH_MD5, 0, 16, 0, sixteenByteDerivation, cipherRC4},
	{SSL_CK_RC4_128_EXPORT40_WITH_MD5, 11, 5, 0, sixteenByteDerivation, cipherRC4},
	{SSL_CK_RC2_128_CBC_WITH_MD5, 0, 16, 8, sixteenByteDerivation, cipherRC2},
	{SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5, 11, 5, 8, sixteenByteDerivation, cipherRC2},
	{SSL_CK_IDEA_128_CBC_WITH_MD5, 0, 16, 8, sixteenByteDerivation, cipherIDEA},
	{SSL_CK_DES_64_CBC_WITH_MD5, 0, 8, 8, eightByteDerivation, cipherDES},
	{SSL_CK_DES_192_EDE3_CBC_WITH_MD5, 0, 24, 8, twentyFourByteDerivation, cipher3DES},
}
