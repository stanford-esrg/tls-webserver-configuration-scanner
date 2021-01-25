package defaults

import (
	"errors"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
)

func getSelectedCurve(log *zgrab2.TLSLog) tls.CurveID {
	var curve tls.CurveID

	if log != nil && log.HandshakeLog != nil && log.HandshakeLog.ServerKeyExchange != nil && log.HandshakeLog.ServerKeyExchange.ECDHParams != nil {

		ep := log.HandshakeLog.ServerKeyExchange.ECDHParams
		curve = tls.CurveID(ep.TLSCurveID)
	}

	return curve
}

func curveSupportStatus(selected_curve tls.CurveID,
	presented_curves []tls.CurveID, log *zgrab2.TLSLog) (error, bool) {

	var support_status bool
	var err error

	if log == nil || log.HandshakeLog == nil || log.HandshakeLog.ServerKeyExchange == nil || log.HandshakeLog.ServerKeyExchange.ECDHParams == nil {
		return errors.New("Unexpected error."), false
	}

	curve_struct := CurveSlice(presented_curves)

	if curve_struct.indexOf(selected_curve) == -1 {
		err = errors.New("Index out of bounds error. Server selected curve that wasn't presented.")
	} else {
		support_status = true
	}
	return err, support_status
}

func scanCurves(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, presented_curves []tls.CurveID) Handshake {

	var err error

	hs_err, log := doTLSHandshake(t, baseFlags, tlsFlags, target_version,
		CIPHERS_ECDHE, presented_curves, SIG_AND_HASHES)

	selected_curve := getSelectedCurve(log)
	ss_err, support_status := curveSupportStatus(selected_curve, presented_curves, log)

	if hs_err != nil {
		if ss_err != nil {
			err = errors.New("Handshake Err: " + hs_err.Error() + "||" + "Support Status Err: " + ss_err.Error())
		} else {
			err = hs_err
		}
	} else {
		err = ss_err
	}

	return Handshake{Err{err}, log, support_status, target_version}
}

// Tests support for CURVES_UNION (multiple scans), enumerates all curves supported
func curveScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, target_version tls.TLSVersion, first_selected_curve tls.CurveID) []Handshake {

	var handshakes []Handshake

	// see if first_selected_curve is in CURVES_UNION
	presented_curves := CurveSlice(CURVES_UNION).copy()

	// if first_selected_curve is in CURVES_UNION --> remove curve from list
	if presented_curves.indexOf(first_selected_curve) != -1 {
		presented_curves = presented_curves.remove(first_selected_curve)
	}

	for len(presented_curves) > 0 {
		h := scanCurves(t, baseFlags, tlsFlags, target_version, presented_curves)
		handshakes = append(handshakes, h)
		selected_curve := getSelectedCurve(h.Log)
		presented_curves = presented_curves.updatePresentedItems(selected_curve)

	}

	return handshakes
}

// Combines all curves supported (common + uncommon) in a slice
func extractSupportedCurves(curve_handshakes []Handshake) []tls.CurveID {

	var curves_supported []tls.CurveID

	for _, h := range curve_handshakes {
		if h.ScanStatus {
			curve := getSelectedCurve(h.Log)
			curves_supported = append(curves_supported, curve)
		}
	}
	return curves_supported
}

func getFirstCurveHS(highest_version tls.TLSVersion,
	version_support TLSVersionSupport) (tls.CurveID, Handshake) {

	log := version_support.VersionHandshakes[highest_version.String()].Log
	first_selected_curve := getSelectedCurve(log)
	err, support_status := curveSupportStatus(first_selected_curve,
		CurveSlice(CURVES_UNION).copy(), log)

	return first_selected_curve, Handshake{Err{err}, log, support_status, highest_version}
}

// Scans for curve support
func EllipticCurveScan(t zgrab2.ScanTarget, baseFlags zgrab2.BaseFlags,
	tlsFlags zgrab2.TLSFlags, version_support TLSVersionSupport) *EllipticCurveSupport {

	var curves_supported []tls.CurveID
	var curve_handshakes []Handshake

	verNoTLS13 := VersionSlice(version_support.SupportedVersions).copy().remove(tls.VersionTLS13)
	highest_version := verNoTLS13.getHighest()

	//Elliptic curve supported TLS10 onward
	if highest_version >= tls.VersionTLS10 {

		// Support for CURVES_UNION
		first_selected_curve, first_hs := getFirstCurveHS(highest_version, version_support)

		curve_handshakes = curveScan(t, baseFlags, tlsFlags,
			highest_version, first_selected_curve)

		curve_handshakes = append(curve_handshakes, first_hs)

		curves_supported = extractSupportedCurves(curve_handshakes)

		return &EllipticCurveSupport{
			CurvesSupported: curves_supported,
			CurveHandshakes: curve_handshakes,
		}
	}

	return nil
}
