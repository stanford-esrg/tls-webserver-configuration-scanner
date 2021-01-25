package defaults

import (
	"encoding/json"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/sslv2"
	"strings"
)

type Err struct {
	Error error `json:"error"`
}

type ExtensionID uint16

type HTTPResponseInfo struct {
	ResponseStatusCode int
	ResponseProtocol   string
	ResponseHeader     []string `json:"response_header"`
	ResponseBody       string   `json:"response_body"`
}

type HTTPSupport struct {
	//HTTP
	SupportsHTTP bool `json:"http_support"`
	HTTPResponse *HTTPResponseInfo
	HTTPError    Err `json:"http_error"`
	//HTTPS
	SupportsHTTPS bool `json:"https_support"`
	HTTPSResponse *HTTPResponseInfo
	HTTPSError    Err `json:"https_error"`

	SupportsHTTP2 bool `json:"http2_support"`
	HTTP2Response *HTTPResponseInfo
	HTTP2Error    Err `json:"http2_error"`
}

type Handshake struct {
	Error         Err            `json:"error"`
	Log           *zgrab2.TLSLog `json:"handshake_log"`
	ScanStatus    bool           `json:"scan_status"`
	TargetVersion tls.TLSVersion `json:intended_version`
}

type HandshakeSSL20 struct {
	Error           Err                  `json:"error"`
	Log             *sslv2.HandshakeData `json:"handshake_log"`
	ScanStatus      bool                 `json:"scan_status"`
	SelectedCiphers []sslv2.CipherKind   `json:"supported_ciphers"`
}

type TLSVersionSupport struct {
	SupportedVersions []tls.TLSVersion     `json:"supported_versions"`
	VersionHandshakes map[string]Handshake `json:"handshakes"`
	SSL20Handshake    HandshakeSSL20       `json:"ssl20_handshake"`
}

type EllipticCurveSupport struct {
	CurvesSupported []tls.CurveID `json:"supported_curves"`
	CurveHandshakes []Handshake   `json:"curve_handshakes"`
}

type CipherSuiteSupport struct {
	CiphersSupported        []tls.CipherSuite `json:"supported_ciphers"`
	CipherHandshakes        []Handshake       `json:"handshakes"`
	ServerPreferenceSupport bool              `json:"server_preference_support"`
	ServerPreferenceHS      Handshake         `json:"server_preference_handshake"`
}

type ExtensionSupport struct {
	ExtensionsSupported     []ExtensionID      `json:"supported_extensions"`
	ProtocolsSupported      []string           `json:"supported_protocols"`
	SessionTicket           *tls.SessionTicket `json:"session_ticket"`
	ExtensionHandshakes     []Handshake        `json:"extension_handshakes"`
	SessionTicketResumption bool               `json:"session_ticket_resumption"`
	SessionIDResumption     bool               `json:"session_id_resumption"`
	HeartBleed              bool               `json:"heart_bleed"`
	Compression             bool               `json:"compression"`
}

type DefaultsResults struct {
	HttpSupport      HTTPSupport           `json:"HTTPSupport"`
	VersionSupport   TLSVersionSupport     `json:"TLSVersionSupport"`
	CipherSupport    *CipherSuiteSupport   `json:"CipherSuiteSupport"`
	EllipticCurves   *EllipticCurveSupport `json:"EllipticCurveSupport"`
	ExtensionSupport *ExtensionSupport     `json:"ExtensionSupport"`
}

// IGNORES DSA algorithm as we only present RSA / ECDSA ciphers in Versions Scans
func getCertType(target_version tls.TLSVersion, version_scan_result TLSVersionSupport) string {
	var cert_type string = "RSA"

	if target_version == tls.VersionTLS12 {
		hs := version_scan_result.VersionHandshakes[tls.TLSVersion(tls.VersionTLS12).String()]
		cipher := GetSelectedCipher(hs.Log)
		if strings.Contains(cipher.String(), "ECDSA") {
			cert_type = "ECDSA"
		}
	}

	return cert_type
}

// Marshaling Functions

func (err Err) MarshalJSON() ([]byte, error) {
	if err.Error != nil {
		return json.Marshal(err.Error.Error())
	}
	return json.Marshal(nil)
}

func (ext ExtensionID) String() string {
	if name, ok := extensionNames[ext]; ok {
		return name
	}
	return "unknown"
}

func (ext ExtensionID) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{
		Name:  ext.String(),
		Value: uint16(ext),
	}
	return json.Marshal(&aux)
}
