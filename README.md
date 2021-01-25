Defaults Scanner
=========

This repo contains TLS Webserver Configuration Scanner implementation under zgrab2 modules `Default` & `SMTP`

## Building

You will need to have a valid `$GOPATH` set up, for more information about `$GOPATH`, see https://golang.org/doc/code.html.

Once you have a working `$GOPATH`, run:
```
$ go version
go version go1.12.6 linux/amd6
```
Verify that you have the correct version of go installed.
```
$ git clone git@github.com:stanford-esrg/tls-webserver-configuration-scanner.git
$ cd tls-webserver-configuration-scanner
$ go get github.com/zmap/zgrab2
$ rm -rf $GOPATH/src/github.com/zmap/zcrypto/ $GOPATH/src/github.com/zmap/zgrab2/
$ cp -r zcrypto/ zgrab2/ $GOPATH/src/github.com/zmap/
$ go get github.com/dadrian/go-idea github.com/dadrian/rc2 golang.org/x/crypto/curve25519 golang.org/x/crypto/ed25519 golang.org/x/crypto/md4 golang.org/x/net/http/httpguts golang.org/x/net/http/httpproxy golang.org/x/net/http2/hpack golang.org/x/net/idna golang.org/x/text/unicode/norm golang.org/x/text/width gopkg.in/mgo.v2/bson golang.org/x/crypto/chacha20poly1305
$ cd $GOPATH/src/github.com/zmap/zgrab2
$ make clean && make
```
