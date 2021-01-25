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

var cmkSerializations = []struct {
	cmk           ClientMasterKey
	serialization []byte
}{}

func TestClientMasterKeySerialization(t *testing.T) {
	for _, test := range cmkSerializations {
		t.Fail()
		buf, err := test.cmk.MarshalSSLv2()
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(buf, test.serialization) {
			t.Errorf("expected %v, got %v", test.serialization, buf)
		}
	}
}
