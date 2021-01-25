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
	"testing"
)

// Standard SSLv3 CipherKinds
var cipherSerializations = []struct {
	cipherKind    CipherKind
	serialization []byte
}{
	{SSL_CK_RC4_128_WITH_MD5, []byte{0x01, 0x00, 0x80}},
	{SSL_CK_RC4_128_EXPORT40_WITH_MD5, []byte{0x02, 0x00, 0x80}},
	{SSL_CK_RC2_128_CBC_WITH_MD5, []byte{0x03, 0x00, 0x80}},
	{SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5, []byte{0x04, 0x00, 0x80}},
	{SSL_CK_IDEA_128_CBC_WITH_MD5, []byte{0x05, 0x00, 0x80}},
	{SSL_CK_DES_64_CBC_WITH_MD5, []byte{0x06, 0x00, 0x40}},
	{SSL_CK_DES_192_EDE3_CBC_WITH_MD5, []byte{0x07, 0x00, 0xC0}},
}

func TestCipherSerialization(t *testing.T) {
	for idx, test := range cipherSerializations {
		out, err := test.cipherKind.MarshalSSLv2()
		if err != nil {
			t.Errorf("error serializing cipher with index %d, value %d: %s", idx, uint32(test.cipherKind), err.Error())
		} else if !bytes.Equal(out, test.serialization) {
			t.Errorf("mismatched serialization: got %v, expected %v", out, test.serialization)
		}
	}
}
