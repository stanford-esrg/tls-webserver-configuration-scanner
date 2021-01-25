package defaults

import (
	"errors"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
)

func getCiphersByCertType(target_version tls.TLSVersion, cert_type string) []tls.CipherSuite {

	var cipher_array []tls.CipherSuite

	// Elliptic curves were only introduced in TLS12
	// This is just to cut down on the nr of handshakes
	// Rare case we ignore: servers support both RSA + ECDSA (as per conversation with Zakir)
	if cert_type == "ECDSA" {
		cipher_array = CipherSlice(CIPHERS_ECDSA).copy()
	} else {
		if target_version == tls.VersionTLS12 {
			cipher_array = CipherSlice(CIPHERS_RSA).copy()
		} else {
			cipher_array = CipherSlice(CIPHERS_BY_VERSION[target_version]).copy()
		}
	}
	return cipher_array
}

func GetSelectedCipher(log *zgrab2.TLSLog) tls.CipherSuite {
	var cipher tls.CipherSuite

	if log != nil && log.HandshakeLog != nil && log.HandshakeLog.ServerHello != nil {
		cipher = log.HandshakeLog.ServerHello.CipherSuite
	}

	return cipher
}

func CipherSupportStatus(selected_cipher tls.CipherSuite,
	presented_ciphers []tls.CipherSuite, log *zgrab2.TLSLog) (error, bool) {

	var support_status bool
	var err error

	if log == nil || log.HandshakeLog == nil || log.HandshakeLog.ServerHello == nil {
		return errors.New("Cipher is not supported or unexpected error."), false
	}

	cipher_struct := CipherSlice(presented_ciphers)

	if cipher_struct.indexOf(selected_cipher) == -1 {
		err = errors.New("Index out of bounds error. Server selected cipher that wasn't presented.")
	} else {
		support_status = true
	}

	return err, support_status
}

func scanCiphers(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion,
	presented_ciphers []tls.CipherSuite) Handshake {

	var err error

	hs_err, log := doTLSHandshake(t, baseFlags, tlsFlags,
		target_version, presented_ciphers, CURVES_COMMON, SIG_AND_HASHES)

	selected_cipher := GetSelectedCipher(log)
	ss_err, support_status := CipherSupportStatus(selected_cipher, presented_ciphers, log)

	if hs_err != nil {
		if ss_err != nil {
			err = errors.New("Handshake Err: " + hs_err.Error() + "||" + "Support Status Error: " + ss_err.Error())
		} else {
			err = hs_err
		}
	} else {
		err = ss_err
	}

	return Handshake{Err{err}, log, support_status, target_version}
}

// Find all ciphers supported by a server and version "target_version"
func ciphersScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion,
	presented_ciphers []tls.CipherSuite) []Handshake {

	var handshakes []Handshake

	presented_ciphers = CipherSlice(presented_ciphers).shuffle()

	for len(presented_ciphers) > 0 {
		h := scanCiphers(t, baseFlags, tlsFlags, target_version, presented_ciphers)
		handshakes = append(handshakes, h)
		selected_cipher := GetSelectedCipher(h.Log)
		//fmt.Println(selected_cipher)
		presented_ciphers = CipherSlice(presented_ciphers).updatePresentedItems(selected_cipher)
	}

	return handshakes
}

/*
 * Assumption: Filtered Logs are kept in order before extracting
 * the cipher1 and cipher2. This saves 1 tls handshake.
 */
func serverPreferenceTest(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion,
	cipher1 tls.CipherSuite, cipher2 tls.CipherSuite) (bool, Handshake) {

	h := scanCiphers(t, baseFlags, tlsFlags, target_version,
		[]tls.CipherSuite{cipher2, cipher1})

	if !h.ScanStatus {
		return false, h
	}

	selected_cipher := GetSelectedCipher(h.Log)

	return selected_cipher == cipher1, h
}

func getSupportedCiphers(hs []Handshake) []tls.CipherSuite {

	var supported_ciphers []tls.CipherSuite

	for _, h := range hs {
		if h.ScanStatus {
			supported_ciphers = append(supported_ciphers, GetSelectedCipher(h.Log))
		}
	}

	return supported_ciphers
}

func CipherScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, versionSupportResult TLSVersionSupport) *CipherSuiteSupport {

	var server_preference bool
	var server_pref_hs Handshake
	var handshakes []Handshake
	var supported_ciphers []tls.CipherSuite

	verNoTLS13 := VersionSlice(versionSupportResult.SupportedVersions).copy().remove(tls.VersionTLS13)
	highest_version := verNoTLS13.getHighest()

	// Scan for SSL20 is not needed, since version scan collects SSL20 Ciphers
	if TLS_VERSIONS_NOT13.copy().indexOf(highest_version) != -1 {

		if highest_version == tls.VersionTLS12 {
			hs_ecdsa := ciphersScan(t, baseFlags, tlsFlags, highest_version, CipherSlice(CIPHERS_ECDSA).copy())
			hs_rsa := ciphersScan(t, baseFlags, tlsFlags, highest_version, CipherSlice(CIPHERS_RSA).copy())
			handshakes = append(hs_ecdsa, hs_rsa...)
		} else {
			presented_ciphers := CipherSlice(CIPHERS_BY_VERSION[highest_version]).copy()
			handshakes = ciphersScan(t, baseFlags, tlsFlags, highest_version, presented_ciphers)
		}

		supported_ciphers = getSupportedCiphers(handshakes)

		if len(supported_ciphers) >= 2 {
			server_preference, server_pref_hs = serverPreferenceTest(t, baseFlags, tlsFlags,
				highest_version, supported_ciphers[0], supported_ciphers[1])
		}

		return &CipherSuiteSupport{
			CiphersSupported:        supported_ciphers,
			CipherHandshakes:        handshakes,
			ServerPreferenceSupport: server_preference,
			ServerPreferenceHS:      server_pref_hs,
		}
	}

	return nil
}
