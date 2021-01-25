package defaults

import (
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/sslv2"
)

func hasVersionSupport(target_version tls.TLSVersion, log *zgrab2.TLSLog) bool {

	// Assumption: If the log is not nil, we can trust the data in the TLSLog
	if log != nil && log.HandshakeLog != nil && log.HandshakeLog.ServerHello != nil {
		serverHello := log.HandshakeLog.ServerHello

		if target_version == tls.VersionTLS13 {
			//TLS1.3 is done over a 1.2 handshake, so we must check SupportedVersions
			return serverHello.SupportedVersions == tls.VersionTLS13
		}
		// Server selects highest version it supports
		// not necessarily the target_version.
		// We set status to true if a valid version is selected
		return (TLS_VERSIONS_NOT13.copy()).indexOf(serverHello.Version) != -1
	}
	return false
}

//Function valid for TLS1.2 -> SSL3.0
func getSelectedVersion(log *zgrab2.TLSLog) tls.TLSVersion {
	var version tls.TLSVersion
	if log != nil && log.HandshakeLog != nil && log.HandshakeLog.ServerHello != nil {
		version = log.HandshakeLog.ServerHello.Version
	}
	return version
}

// Tests support for TSLv1.2 - SSL3.0
func tls12ssl30SupportScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags, tlsFlags zgrab2.TLSFlags) []Handshake {
	var handshakes []Handshake
	var target_version tls.TLSVersion

	versions_to_scan := VersionSlice([]tls.TLSVersion{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10, tls.VersionSSL30})

	for len(versions_to_scan) > 0 {
		target_version = versions_to_scan[0]
		err, log := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
			CipherSlice(CIPHERS_BY_VERSION[target_version]).copy(),
			CurveSlice(CURVES_COMMON).copy(), SIG_AND_HASHES)

		support_status := hasVersionSupport(target_version, log)
		h := Handshake{Err{err}, log, support_status, target_version}
		handshakes = append(handshakes, h)
		selected_version := getSelectedVersion(log)
		versions_to_scan = versions_to_scan.updatePresentedItems(selected_version)
	}
	return handshakes
}

// Tests support for SSLv2.0
func ssl20SupportScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags) HandshakeSSL20 {

	var ciphers []sslv2.CipherKind
	var support_status bool

	log, err := t.SSLv2Handshake(&baseFlags)

	if log != nil && log.ServerHello != nil && err == nil {
		support_status = true
		ciphers = log.ServerHello.Ciphers
	}

	return HandshakeSSL20{Err{err}, log, support_status, ciphers}
}

func tls13SupportScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags, tlsFlags zgrab2.TLSFlags) Handshake {

	err, log := doTLSHandshake(t, baseFlags, tlsFlags, tls.VersionTLS13,
		CipherSlice(CIPHERS_TLS13).copy(),
		CurveSlice(CURVES_COMMON).copy(), SIG_AND_HASHES)

	support_status := hasVersionSupport(tls.VersionTLS13, log)

	return Handshake{Err{err}, log, support_status, tls.VersionTLS13}
}

func TLSVersionSupportScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags, tlsFlags zgrab2.TLSFlags) TLSVersionSupport {

	tls13 := tls13SupportScan(t, baseFlags, tlsFlags)
	tls12_ssl30 := tls12ssl30SupportScan(t, baseFlags, tlsFlags)
	ssl20 := ssl20SupportScan(t, baseFlags)

	supported_versions := []tls.TLSVersion{}
	handshakes := make(map[string]Handshake)

	// add results for TLS13
	handshakes[tls.TLSVersion(tls.VersionTLS13).String()] = tls13
	if tls13.ScanStatus {
		supported_versions = append(supported_versions, tls.VersionTLS13)
	}

	// add results for TLS12 - SSL30
	for _, h := range tls12_ssl30 {
		handshakes[h.TargetVersion.String()] = h
		if h.ScanStatus {
			selected_version := getSelectedVersion(h.Log)
			supported_versions = append(supported_versions, selected_version)
		}
	}

	if ssl20.ScanStatus {
		supported_versions = append(supported_versions, tls.VersionSSL20)
	}

	return TLSVersionSupport{
		SupportedVersions: supported_versions,
		VersionHandshakes: handshakes,
		SSL20Handshake:    ssl20,
	}
}
