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

import "io"

// Record sizes for two- and three-byte issues
const (
	MAX_TWO_BYTE_RECORD_BYTES   = 32767
	MAX_THREE_BYTE_RECORD_BYTES = 16383
	MAX_RECORD_BYTES            = MAX_TWO_BYTE_RECORD_BYTES
)

type Config struct {
	Ciphers    []CipherKind
	ExtraClear bool
}

type marshaler interface {
	MarshalSSLv2() ([]byte, error)
}

type messageWriter struct {
	w   io.Writer
	err error
}

func newMessageWriter(w io.Writer) *messageWriter {
	return &messageWriter{
		w: w,
	}
}

func (m *messageWriter) WriteMarshaler(data marshaler) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	var b []byte
	b, m.err = data.MarshalSSLv2()
	return m.Write(b)
}

func (m *messageWriter) Write(b []byte) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	var n int
	n, m.err = m.w.Write(b)
	return n, m.err
}

func (m *messageWriter) Error() error {
	return m.err
}

type unmarshaler interface {
	UnmarshalSSLv2(b []byte) ([]byte, error)
}

type messageReader struct {
	r   io.Reader
	err error
}
