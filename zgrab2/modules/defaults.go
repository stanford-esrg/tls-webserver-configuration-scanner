package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/defaults"
	"math/rand"
	"time"
)

// -----------------------------------------------------------------------------------------------
// BEGINS INTERFACE REQUIRED FILLER FUNCTIONS
// -----------------------------------------------------------------------------------------------

type DefaultsFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

type DefaultsModule struct {
}

type DefaultsScanner struct {
	config *DefaultsFlags
}

func init() {
	var defaultsModule DefaultsModule
	_, err := zgrab2.AddCommand("defaults", "TLS Configuration Grab", "Grab configuration info for TLS", 443, &defaultsModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *DefaultsScanner) GetName() string {
	return s.config.Name
}

func (s *DefaultsScanner) GetTrigger() string {
	return s.config.Trigger
}

func (m *DefaultsModule) NewFlags() interface{} {
	return new(DefaultsFlags)
}

func (m *DefaultsModule) NewScanner() zgrab2.Scanner {
	return new(DefaultsScanner)
}

func (f *DefaultsFlags) Help() string {
	return "TODO: Help!"
}

func (s *DefaultsScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*DefaultsFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	return nil
}

func (s *DefaultsScanner) InitPerSender(senderID int) error {
	return nil
}

func (f *DefaultsFlags) Validate(args []string) error {
	return nil
}

func (s *DefaultsScanner) Protocol() string {
	return "defaults"
}

// -----------------------------------------------------------------------------------------------
// ENDS INTERFACE REQUIRED FILLER FUNCTIONS
// -----------------------------------------------------------------------------------------------

// Experimental Scan: scans for web server configuration
func (s *DefaultsScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	baseFlags := s.config.BaseFlags
	tlsFlags := s.config.TLSFlags

	// sleep time
	if tlsFlags.StartDelay > 0 {
		time.Sleep(time.Duration(rand.Intn(tlsFlags.StartDelay)) * time.Second)
	}

	http_support := defaults.HttpSupportScan(t, tlsFlags)

	supported_versions := defaults.TLSVersionSupportScan(t, baseFlags, tlsFlags)

	supported_ciphers := defaults.CipherScan(t, baseFlags, tlsFlags, supported_versions)

	supported_curves := defaults.EllipticCurveScan(t, baseFlags, tlsFlags, supported_versions)

	ext_support := defaults.ExtensionScan(t, baseFlags, tlsFlags, supported_versions)

	results := defaults.DefaultsResults{
		HttpSupport:      http_support,
		VersionSupport:   supported_versions,
		CipherSupport:    supported_ciphers,
		EllipticCurves:   supported_curves,
		ExtensionSupport: ext_support,
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}
