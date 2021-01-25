package smtp

import (
	"time"
	"fmt"
	"math/rand"
	def "github.com/zmap/zgrab2/lib/defaults"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zcrypto/tls"
	"errors"
	"github.com/zmap/zgrab2/lib/sslv2"
)

func doSSL2Handshake(conn Connection) (error, *sslv2.HandshakeData) {
	sslv2Config := new(sslv2.Config)
	sslv2Config.Ciphers = sslv2.AllCiphers
	ssl := sslv2.Client(conn.Conn, sslv2Config)
	err := ssl.Handshake()
	hs := ssl.HandshakeLog()
	return err, hs
}

func doHandshake(conn Connection, tlsFlags zgrab2.TLSFlags, target_ciphers []tls.CipherSuite) (error, *zgrab2.TLSLog) {
	tlsFlags.MaxVersion = tls.VersionTLS12
	tlsFlags.ForceSuites = true
	tlsFlags.CipherSuite = def.CipherSlice(target_ciphers).ToHexStr()
	tlsFlags.CurvePreferences = def.CurveSlice(def.CURVES_DEFAULT).ToIntStr()

	tlsConn, err := tlsFlags.GetTLSConnection(conn.Conn)

	if err != nil {
		return err, nil
	}

	if tlsConn != nil {
		defer tlsConn.Close()
	}

	err = tlsConn.Handshake()

	if err != nil {
		if tlsConn != nil {
			log := tlsConn.GetLog()
			if log != nil {
				if log.HandshakeLog != nil {
					return err, log
				}
				return err, nil
			}
			return err, nil
		}
		return err, nil
	}

	log := tlsConn.GetLog()
	return nil, log
}

func (scanner *Scanner) checkSSLv2Support(target zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags, tlsFlags zgrab2.TLSFlags) (SupportStatus, def.HandshakeSSL20, *ScanResults) {
        if tlsFlags.HandshakeDelay > 0 {
                time.Sleep(time.Duration(rand.Intn(tlsFlags.HandshakeDelay))*time.Second)
        }

        c, err := target.Open(&baseFlags)
        if err != nil {
		return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{err}}, nil
        }
        defer c.Close()

        result := &ScanResults{}

        conn := Connection{Conn: c}
        banner, err := conn.ReadResponse()

        if err != nil {
		return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{err}}, nil
        }

        result.Banner = banner

	ret, err := conn.SendCommand(getCommand("EHLO", scanner.config.EHLODomain))
	if err != nil {
		return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{err}}, result
	}
	result.EHLO = ret

	ret, err = conn.SendCommand("STARTTLS")
	if err != nil {
                return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{err}}, result
	}
	result.StartTLS = ret
	code, err := getSMTPCode(ret)
	if err != nil {
                return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{err}}, result
	}
	if code < 200 || code >= 300 {
                return UNKNOWN_SUPPORT, def.HandshakeSSL20{Error: def.Err{fmt.Errorf("SMTP error code %d returned from STARTTLS command (%s)", code, ret)}}, result
	}

	hs_err, log := doSSL2Handshake(conn)

	var ciphers []sslv2.CipherKind
	var support_status SupportStatus = UNSUPPORTED

	if log != nil && log.ServerHello != nil && hs_err == nil {
		support_status = SUPPORTED
		ciphers = log.ServerHello.Ciphers
	}

	return support_status, def.HandshakeSSL20{def.Err{hs_err}, log, true, ciphers}, result
}

func (scanner *Scanner) checkCipherSupport(target zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags, tlsFlags zgrab2.TLSFlags, target_ciphers []tls.CipherSuite) (SupportStatus, def.Handshake, *ScanResults) {
        if tlsFlags.HandshakeDelay > 0 {
                time.Sleep(time.Duration(rand.Intn(tlsFlags.HandshakeDelay))*time.Second)
        }

        c, err := target.Open(&baseFlags)
        if err != nil {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{err}, nil, true, tls.VersionTLS12}, nil
        }
        defer c.Close()

        result := &ScanResults{}

        conn := Connection{Conn: c}
        banner, err := conn.ReadResponse()

        if err != nil {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{err}, nil, true, tls.VersionTLS12}, nil
        }

        result.Banner = banner

	ret, err := conn.SendCommand(getCommand("EHLO", scanner.config.EHLODomain))
	if err != nil {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{err}, nil, true, tls.VersionTLS12}, result
	}
	result.EHLO = ret

	ret, err = conn.SendCommand("STARTTLS")
	if err != nil {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{err}, nil, true, tls.VersionTLS12}, result
	}
	result.StartTLS = ret
	code, err := getSMTPCode(ret)
	if err != nil {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{err}, nil, true, tls.VersionTLS12}, result
	}
	if code < 200 || code >= 300 {
                return UNKNOWN_SUPPORT, def.Handshake{def.Err{fmt.Errorf("SMTP error code %d returned from STARTTLS command (%s)", code, ret)}, nil, true, tls.VersionTLS12}, result
	}

	hs_err, log := doHandshake(conn, tlsFlags, target_ciphers)
	cipher := def.GetSelectedCipher(log)
	ss_err, support_status := def.CipherSupportStatus(cipher, target_ciphers, log)

	// (SupportStatus, *Handshake, *ScanResults)
	var final_err error
	var final_status SupportStatus = UNSUPPORTED

	if hs_err != nil {
		if ss_err != nil {
			final_err = errors.New("Handshake Err: " + hs_err.Error() + " Support Status Error: " + ss_err.Error())
		} else {
			final_err = hs_err
		}
        } else {
                final_err = ss_err
        }

	if support_status {
		final_status = SUPPORTED
	}

	return final_status, def.Handshake{def.Err{final_err}, log, true, tls.VersionTLS12}, result
}
