package smtp

import def "github.com/zmap/zgrab2/lib/defaults"

type SupportStatus string

const (
	UNKNOWN_SUPPORT = SupportStatus("Unknown")
	SUPPORTED = SupportStatus("Supported")
	UNSUPPORTED = SupportStatus("Unsupported")
)

type SmtpTLSSupport struct {
	SupportsInsecure SupportStatus `json:"supports_insecure"`
	SupportsSecure SupportStatus `json:"supports_secure"`
	SupportsSSL2 SupportStatus `json:"supports_ssl2"`
	InsecureHandshake def.Handshake `json:"insecure_handshake"`
	SecureHandshake def.Handshake `json:"secure_handshake"`
	SSL2Handshake def.HandshakeSSL20 `json:"ssl2_handshake"`
	InsecureScanResults *ScanResults `json:"insecure_scan_results"`
	SecureScanResults *ScanResults `json:"secure_scan_results"`
	SSL2ScanResults *ScanResults `json:"ssl2_scan_results"`
	PlainError def.Err `json:"plain_error"`
	PlainScanResults *ScanResults `json:"plain_scan_results"`
}

