package sslv2

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"time"
)

type halfConn struct {
	cipherSpec interface{}
	seqNum     uint32
}

func (rc *halfConn) decrypt(b []byte) (d []byte, err error) {
	payload := b
	d = make([]byte, len(payload))
	switch c := rc.cipherSpec.(type) {
	case cipher.Stream:
		c.XORKeyStream(d, payload)
	case cbcMode:
		blockSize := c.BlockSize()
		if l := len(payload); l%blockSize != 0 {
			return nil, fmt.Errorf("record length %d is not a multiple of block size %d", l, c.BlockSize())
		}
		c.CryptBlocks(d, payload)
	default:
		panic("unimplemented cipher")
	}
	return
}

type Conn struct {
	rc, wc   halfConn
	nc       net.Conn
	isServer bool

	config *Config

	hs *HandshakeData
}

func (c *Conn) readRecord() (header Header, b []byte, err error) {
	headerBytes := make([]byte, 2)
	_, err = c.nc.Read(headerBytes)
	if err != nil {
		return
	}
	// Check to see if it's a 3-byte header
	if headerBytes[0]&0x80 == 0 {
		headerBytes = append(headerBytes, byte(0))
		if _, err = c.nc.Read(headerBytes[2:]); err != nil {
			return
		}
	}
	if err = header.UnmarshalBinary(headerBytes); err != nil {
		return
	}
	body := make([]byte, header.Length)
	var n int
	n, err = c.nc.Read(body)
	b = body[0:n]
	if c.rc.cipherSpec != nil {
		b, err = c.rc.decrypt(b)
	}
	return
}

func (c *Conn) writeRecord(b []byte) (err error) {
	h := Header{
		Length: uint16(len(b)),
	}
	var headerBytes []byte
	if headerBytes, err = h.MarshalBinary(); err != nil {
		return
	}
	record := append(headerBytes, b...)
	if _, err = c.nc.Write(record); err != nil {
		return
	}
	return nil
}

func (c *Conn) Handshake() (err error) {
	if c.isServer {
		panic("sslv2 server unimplemented")
	}
	return c.clientHandshake()
}

func (c *Conn) clientHandshake() (err error) {
	if c.isServer {
		panic("cannot do a client handshake as a server")
	}

	// Make client hello
	ch := new(ClientHello)
	ch.Version = SSL_VERSION_2

	// Assign ciphers based on config. Default to all ciphers
	var ciphers []CipherKind
	if len(c.config.Ciphers) == 0 {
		ciphers = AllCiphers
	} else {
		ciphers = c.config.Ciphers
	}
	ch.Ciphers = ciphers

	// Challenge is 0x02 for simplicity. This is a scanner, not a implementation
	// of a secure channel.
	ch.Challenge = make([]byte, 16)
	for idx := range ch.Challenge {
		ch.Challenge[idx] = 0x02
	}

	// Send the ClientHello, read the ServerHello
	var b []byte
	var h Header
	if b, err = ch.MarshalBinary(); err != nil {
		return
	}
	if err = c.writeRecord(b); err != nil {
		return
	}
	if h, b, err = c.readRecord(); err != nil {
		return
	}

	hs := new(HandshakeData)
	c.hs = hs

	// Parse the ServerHello
	sh := new(ServerHello)
	hs.ServerHello = sh
	if err = sh.UnmarshalBinary(b); err != nil {
		return
	}
	if sh.Certificate == nil {
		err = errors.New("could not parse certificate")
		return
	}

	// Pick a common cipher, if there isn't one, just try using the first one of
	// ours because of CVE-2015-3197.
	chosenCipherKind, ok := findCommonCipher(ciphers, sh.Ciphers)
	if !ok {
		chosenCipherKind = ciphers[0]
	}

	// Find our implementation of the cipher
	var chosenCipher *cipherSuite
	for _, c := range cipherImplementations {
		if c.id == chosenCipherKind {
			chosenCipher = c
		}
	}

	// This shouldn't ever happen, since we implemented every SSLv2 cipher, but if
	// someone else is using this code to do something crazy, let's at least not
	// crash.
	if chosenCipher == nil {
		err = fmt.Errorf("chosen cipher %d not implemented", chosenCipherKind)
		return
	}

	// We have a certificate, pull out the RSA key from it. All SSLv2 ciphers
	// use RSA key exchange.
	if sh.Certificate == nil {
		err = errors.New("missing certificate")
		return
	}
	cert := sh.Certificate.Certificate
	if cert == nil {
		err = errors.New("missing certificate")
		return
	}
	var pubKey *rsa.PublicKey
	pubKey, ok = cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err = errors.New("certificate does not contain an RSA key")
		return
	}

	// Let's get ready to encrypt the masterKey. The master key is always 0x01
	// 0x02 ... 0x16 because this is a scanner, not a secure channel
	// implementation. We'll probably switch this to random eventually.
	masterKey := make([]byte, chosenCipher.encKeyLen+chosenCipher.clearKeyLen)
	for idx := range masterKey {
		masterKey[idx] = byte(idx)
	}

	// Shove everything in the ClientMasterKey
	cmk := new(ClientMasterKey)
	cmk.CipherKind = chosenCipherKind
	cmk.ClearKey = make([]byte, chosenCipher.clearKeyLen)
	copy(cmk.ClearKey, masterKey[0:chosenCipher.clearKeyLen])
	if c.config.ExtraClear {
		extra := make([]byte, len(masterKey))
		cmk.ClearKey = append(cmk.ClearKey, extra...)
	}
	cmk.EncryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, masterKey[chosenCipher.clearKeyLen:])
	cmk.KeyArg = make([]byte, chosenCipher.keyArgLen)

	// Use a fixed KeyArg similar to master key
	for idx := range cmk.KeyArg {
		cmk.KeyArg[idx] = byte(idx)
	}

	// Send the CMK, read the server verify
	if b, err = cmk.MarshalSSLv2(); err != nil {
		return
	}
	if err = c.writeRecord(b); err != nil {
		return
	}
	if h, b, err = c.readRecord(); err != nil {
		return
	}

	// Derive the connection keys
	clientReadKey, clientWriteKey := chosenCipher.deriveKey(masterKey, ch.Challenge, sh.ConnectionID)
	c.rc.cipherSpec = chosenCipher.cipher(clientReadKey, cmk.KeyArg, true)
	c.wc.cipherSpec = chosenCipher.cipher(clientWriteKey, cmk.KeyArg, false)

	// Parse and decrypt server verify
	hs.ServerVerify = new(ServerVerify)
	hs.ServerVerify.Raw = b
	var d []byte
	d, err = c.rc.decrypt(b)
	if l := len(d); l < int(h.PaddingLength)+17 {
		err = ErrInvalidLength
		return
	}
	d = d[0 : len(d)-int(h.PaddingLength)]
	hs.ServerVerify.Challenge = d[17:]
	if bytes.Equal(ch.Challenge, hs.ServerVerify.Challenge) {
		hs.ServerVerify.Valid = true
	}
	if c.config.ExtraClear && !hs.ServerVerify.Valid {
		clientReadKey, clientWriteKey = chosenCipher.deriveKey(cmk.ClearKey[chosenCipher.clearKeyLen:], ch.Challenge, sh.ConnectionID)
		c.rc.cipherSpec = chosenCipher.cipher(clientReadKey, cmk.KeyArg, true)
		c.wc.cipherSpec = chosenCipher.cipher(clientWriteKey, cmk.KeyArg, false)
		d, err = c.rc.decrypt(b)
		if l := len(d); l < int(h.PaddingLength)+17 {
			err = ErrInvalidLength
			return
		}
		d = d[0 : len(d)-int(h.PaddingLength)]
		hs.ServerVerify.Challenge = d[17:]
		if bytes.Equal(ch.Challenge, hs.ServerVerify.Challenge) {
			hs.ServerVerify.ExtraClear = true
		}
	}
	return nil
}

func (c *Conn) HandshakeLog() *HandshakeData {
	return c.hs
}

// Read reads data from the connection. Read can be made to time out and return
// a Error with Timeout() == true after a fixed time limit; see SetDeadline and
// SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// Write writes data to the connection. Write can be made to time out and return
// a Error with Timeout() == true after a fixed time limit; see SetDeadline and
// SetWriteDeadline.
func (c *Conn) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

// Close closes the connection. Any blocked Read or Write operations will be
// unblocked and return errors.
func (c *Conn) Close() error {
	return c.nc.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.nc.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.nc.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// It is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations fail with a timeout
// (see type Error) instead of blocking. The deadline applies to all future I/O,
// not just the immediately following call to Read or Write.
//
// An idle timeout can be implemented by repeatedly extending the deadline after
// successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.nc.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.nc.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.nc.SetWriteDeadline(t)
}
