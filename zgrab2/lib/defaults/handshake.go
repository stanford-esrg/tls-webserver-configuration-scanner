package defaults

import (
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"math/rand"
	"time"
)

func doTLSHandshake_(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, target_ciphers []tls.CipherSuite,
	target_curves []tls.CurveID, sig_and_hashes string) (error, *zgrab2.TLSLog) {

	tlsFlags.MinVersion = int(target_version)
	tlsFlags.MaxVersion = int(target_version)
	tlsFlags.ForceSuites = true
	tlsFlags.CipherSuite = CipherSlice(target_ciphers).ToHexStr()
	tlsFlags.CurvePreferences = CurveSlice(target_curves).ToIntStr()
	tlsFlags.SignatureAlgorithms = sig_and_hashes

	// sleep time
	if tlsFlags.HandshakeDelay > 0 && tlsFlags.SessionResumptionDelay == 0 {
		time.Sleep(time.Duration(rand.Intn(tlsFlags.HandshakeDelay)) * time.Second)
	}

	if tlsFlags.SessionResumptionDelay > 0 && tlsFlags.HandshakeDelay == 0 {
		time.Sleep(time.Duration(tlsFlags.SessionResumptionDelay) * time.Second)
	}

	conn, err := t.OpenTLS(&baseFlags, &tlsFlags)
	if conn != nil {
		defer conn.Close()
	}

	if err != nil {
		if conn != nil {
			log := conn.GetLog()
			if log != nil {
				if log.HandshakeLog != nil {
					return err, log
				}
			}
			// error, no log
			return err, nil
		}
		// error, no conn
		return err, nil
	}
	// success case
	log := conn.GetLog()
	return nil, log
}

func doTLSHandshake(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, target_ciphers []tls.CipherSuite,
	target_curves []tls.CurveID, sig_and_hashes string) (error, *zgrab2.TLSLog) {

	var err error
	var log *zgrab2.TLSLog

	for i := 0; i < CONNECTION_ATTEMPTS; i++ {
		err, log = doTLSHandshake_(t, baseFlags, tlsFlags, target_version, target_ciphers, target_curves, sig_and_hashes)
		if (err != nil && !CONNECTION_ERRORS.invPartialContains(err.Error())) || err == nil {
			break
		}
	}

	return err, log
}

func doResumptionHS_(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, target_ciphers []tls.CipherSuite,
	target_curves []tls.CurveID, sig_and_hashes string) (error, *zgrab2.TLSLog, *tls.Conn) {

	tlsFlags.MinVersion = int(target_version)
	tlsFlags.MaxVersion = int(target_version)
	tlsFlags.ForceSuites = true
	tlsFlags.CipherSuite = CipherSlice(target_ciphers).ToHexStr()
	tlsFlags.CurvePreferences = CurveSlice(target_curves).ToIntStr()
	tlsFlags.SignatureAlgorithms = sig_and_hashes

	// sleep time
	if tlsFlags.HandshakeDelay > 0 && tlsFlags.SessionResumptionDelay == 0 {
		time.Sleep(time.Duration(rand.Intn(tlsFlags.HandshakeDelay)) * time.Second)
	}

	if tlsFlags.SessionResumptionDelay > 0 && tlsFlags.HandshakeDelay == 0 {
		time.Sleep(time.Duration(tlsFlags.SessionResumptionDelay) * time.Second)
	}

	conn, err := t.OpenTLS(&baseFlags, &tlsFlags)
	if conn != nil {
		defer conn.Close()
	}

	if err != nil {
		if conn != nil {
			log := conn.GetLog()
			if log != nil {
				if log.HandshakeLog != nil {
					return err, log, &(conn.Conn)
				}
			}
			// error, no log
			return err, nil, &(conn.Conn)
		}
		// error, no conn
		return err, nil, nil
	}
	// success case
	log := conn.GetLog()
	return nil, log, &(conn.Conn)
}

func doResumptionHS(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, target_ciphers []tls.CipherSuite,
	target_curves []tls.CurveID, sig_and_hashes string) (error, *zgrab2.TLSLog, *tls.Conn) {

	var err error
	var log *zgrab2.TLSLog
	var tls_conn *tls.Conn

	for i := 0; i < CONNECTION_ATTEMPTS; i++ {
		err, log, tls_conn = doResumptionHS_(t, baseFlags, tlsFlags, target_version, target_ciphers, target_curves, sig_and_hashes)
		if (err != nil && !CONNECTION_ERRORS.invPartialContains(err.Error())) || err == nil {
			break
		}
	}

	return err, log, tls_conn
}
