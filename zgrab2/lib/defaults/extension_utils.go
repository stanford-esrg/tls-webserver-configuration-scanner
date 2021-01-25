package defaults

import (
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"strings"
)

func extSuppStatus(log *zgrab2.TLSLog) bool {
	return log != nil && log.HandshakeLog != nil && log.HandshakeLog.ServerHello != nil
}

func extractCompressionSupport(log *zgrab2.TLSLog) bool {
	return extSuppStatus(log) && log.HandshakeLog.ServerHello.CompressionMethod != 0
}

/* Extracts:
 * server_name, status_request, heartbeat, alpn, session_ticket,
 * renegotiation_info, signed_certificate_timestamp
 */

func extractExtensionSupport(log *zgrab2.TLSLog) ([]ExtensionID, bool) {

	var extensions []ExtensionID
	var heartbleed bool

	if extSuppStatus(log) {
		sh := log.HandshakeLog.ServerHello
		if sh.SNISupport {
			extensions = append(extensions, ExtensionServerName)
		}
		if sh.OcspStapling {
			extensions = append(extensions, ExtensionStatusRequest)
		}
		if sh.MultiStapling {
			extensions = append(extensions, ExtensionStatusRequestV2)
		}
		if sh.HeartbeatSupported {
			extensions = append(extensions, ExtensionHeartBeat)
		}
		if sh.AlpnProtocol != "" && strings.Contains(StrSlice(ALPN_PROTOS).copy().join(","), sh.AlpnProtocol) {
			extensions = append(extensions, ExtensionALPN)
		}
		if sh.ExtendedMasterSecret {
			extensions = append(extensions, ExtensionExtendedMasterSecret)
		}
		if sh.TicketSupported {
			extensions = append(extensions, ExtensionSessionTicket)
		}
		if sh.SecureRenegotiation {
			extensions = append(extensions, ExtensionRenegotiationInfo)
		}
		if len(sh.SignedCertificateTimestamps) > 0 {
			extensions = append(extensions, ExtensionSignedCertificateTimestamp)
		}
		if log.HeartbleedLog.Vulnerable {
			heartbleed = true
		}
	}
	return extensions, heartbleed
}

func testALPNProtocol(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, presented_protos string) (string, Handshake) {

	var proto string

	tlsFlags.NextProtos = presented_protos

	err, log := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BY_VERSION[target_version]).copy(),
		CurveSlice(CURVES_COMMON).copy(), SIG_AND_HASHES)

	hs := Handshake{Err{err}, log, extSuppStatus(log), target_version}

	if extSuppStatus(log) {
		proto = log.HandshakeLog.ServerHello.AlpnProtocol
	}

	return proto, hs
}

func doALPNScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion) ([]string, []Handshake) {

	var handshakes []Handshake
	var supported_protos []string

	presented_protos := StrSlice(ALPN_PROTOS).copy()
	for len(presented_protos) > 0 {
		proto, h := testALPNProtocol(t, baseFlags, tlsFlags, target_version, presented_protos.join(","))

		handshakes = append(handshakes, h)

		if proto != "" && strings.Contains(presented_protos.join(","), proto) {
			supported_protos = append(supported_protos, proto)
		}

		presented_protos = presented_protos.updatePresentedItems(proto)
	}

	return supported_protos, handshakes
}

func doExtHS(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion) (error, *zgrab2.TLSLog) {

	//Extensions
	tlsFlags.NoSNI = false
	tlsFlags.HeartbeatEnabled = true
	tlsFlags.SessionTicket = true
	tlsFlags.SCTExt = true
	tlsFlags.ExtendedMasterSecret = true
	tlsFlags.NextProtos = StrSlice(ALPN_PROTOS).copy().join(",")
	tlsFlags.Heartbleed = true
	tlsFlags.NoStapling = false
	tlsFlags.MultiStapling = true
	tlsFlags.NoSecureRenegotiation = false

	err, log := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BY_VERSION[target_version]).copy(),
		CurveSlice(CURVES_COMMON).copy(), SIG_AND_HASHES)

	return err, log
}

func doCompressHS(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion) (error, *zgrab2.TLSLog) {

	//Extensions
	tlsFlags.CompressMethod = COMPRESSION_METHODS

	err, log := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BY_VERSION[target_version]).copy(),
		CurveSlice(CURVES_COMMON).copy(), SIG_AND_HASHES)

	return err, log
}

func doSessionTicketResumption(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion) ([]Handshake, *tls.SessionTicket, bool) {

	var hs []Handshake
	var ticket *tls.SessionTicket

	tlsFlags.NoStapling = true
	tlsFlags.NoSecureRenegotiation = true

	sessionCache := tls.NewLRUClientSessionCache(1)

	tlsFlags.SessionTicket = true
	tlsFlags.SessionCache = sessionCache

	err1, log1, conn1 := doResumptionHS(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BROWSER_UNION).copy(),
		CurveSlice(CURVES_DEFAULT).copy(), SIG_AND_HASHES)

	if extSuppStatus(log1) {
		ticket = log1.HandshakeLog.SessionTicket
	}

	tlsFlags.HandshakeDelay = 0
	tlsFlags.SessionResumptionDelay = SESSION_RESUMPTION_DELAY

	err2, log2, conn2 := doResumptionHS(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BROWSER_UNION).copy(),
		CurveSlice(CURVES_DEFAULT).copy(), SIG_AND_HASHES)

	tlsFlags.SessionCache = nil

	hs = append(hs, Handshake{Err{err1}, log1, extSuppStatus(log1) && conn1 != nil, target_version})
	hs = append(hs, Handshake{Err{err2}, log2, extSuppStatus(log2) && conn2 != nil, target_version})

	return hs, ticket, conn2 != nil && conn2.ConnectionState().DidResume && ticket != nil
}

func doSessionIDResumption(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion) ([]Handshake, bool) {

	var hs []Handshake
	var sessionID []byte
	var SIDRSupport bool

	tlsFlags.NoStapling = true
	tlsFlags.NoSecureRenegotiation = true
	tlsFlags.SessionTicket = false

	err1, log1 := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BROWSER_UNION).copy(),
		CurveSlice(CURVES_DEFAULT).copy(), SIG_AND_HASHES)

	if extSuppStatus(log1) {
		sessionID = log1.HandshakeLog.ServerHello.SessionID
	}

	tlsFlags.SessionID = sessionID

	tlsFlags.HandshakeDelay = 0
	tlsFlags.SessionResumptionDelay = SESSION_RESUMPTION_DELAY

	err2, log2 := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CipherSlice(CIPHERS_BROWSER_UNION).copy(),
		CurveSlice(CURVES_DEFAULT).copy(), SIG_AND_HASHES)

	tlsFlags.SessionID = []byte{}

	hs = append(hs, Handshake{Err{err1}, log1, extSuppStatus(log1), target_version})
	hs = append(hs, Handshake{Err{err2}, log2, extSuppStatus(log2), target_version})

	if extSuppStatus(log2) && byteArrayEq(sessionID, log2.HandshakeLog.ServerHello.SessionID) && len(log2.HandshakeLog.ServerHello.SessionID) > 0 {
		SIDRSupport = true
	}

	return hs, SIDRSupport
}

// Scans for extension support
func ExtensionScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, version_support TLSVersionSupport) *ExtensionSupport {

	var extsupport []ExtensionID
	var exths []Handshake
	var heartbleed bool
	var compression bool

	verNoTLS13 := VersionSlice(version_support.SupportedVersions).copy().remove(tls.VersionTLS13)
	highest_version := verNoTLS13.getHighest()

	if TLS_VERSIONS_NOT13.copy().indexOf(highest_version) != -1 {
		e_err, e_log := doExtHS(t, baseFlags, tlsFlags, highest_version)
		e_hs := Handshake{Err{e_err}, e_log, extSuppStatus(e_log), highest_version}
		exths = append(exths, e_hs)
		extsupport, heartbleed = extractExtensionSupport(e_log)

		c_err, c_log := doCompressHS(t, baseFlags, tlsFlags, highest_version)
		c_hs := Handshake{Err{c_err}, c_log, extSuppStatus(c_log), highest_version}
		exths = append(exths, c_hs)
		compression = extractCompressionSupport(c_log)

		st_hs, ticket, st_supp := doSessionTicketResumption(t, baseFlags, tlsFlags, highest_version)
		exths = append(exths, st_hs[0])
		exths = append(exths, st_hs[1])

		sid_hs, sid_supp := doSessionIDResumption(t, baseFlags, tlsFlags, highest_version)
		exths = append(exths, sid_hs[0])
		exths = append(exths, sid_hs[1])

		protos, proto_hs := doALPNScan(t, baseFlags, tlsFlags, highest_version)
		exths = append(exths, proto_hs...)

		return &ExtensionSupport{extsupport, protos, ticket, exths, st_supp, sid_supp, heartbleed, compression}
	}

	return nil
}
