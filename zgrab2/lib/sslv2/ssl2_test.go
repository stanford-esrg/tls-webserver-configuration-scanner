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
	"testing"

	. "gopkg.in/check.v1"
)

func TestSSLv2(t *testing.T) { TestingT(t) }

type SSLv2Suite struct {
}

var _ = Suite(&SSLv2Suite{})

func (s *SSLv2Suite) TestMarshalUnmarshalTwoByteHeader(c *C) {
	h := Header{
		Length: 0x08F2,
	}
	b, err := h.MarshalBinary()
	c.Assert(err, IsNil)
	c.Check(len(b), Equals, 2)
	c.Check(b[0], Equals, byte(0x88))
	c.Check(b[1], Equals, byte(0xF2))
	dec := Header{}
	err = dec.UnmarshalBinary(b)
	c.Assert(err, IsNil)
	c.Check(dec.raw, DeepEquals, b)
	dec.raw = nil
	c.Check(dec, DeepEquals, h)
}
