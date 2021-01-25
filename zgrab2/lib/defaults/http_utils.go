package defaults

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http2"
	"github.com/zmap/zgrab2/lib/modern_http"
	"io/ioutil"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Args: Scan Target <-> IP, Domain
// Outputs: string <-> http://[ip]
// Expects: Target has an IP
// Avoids DNS Lookup by using direct target IP
func http_uri(t zgrab2.ScanTarget) string {
	return "http://" + t.IP.String()
}

func https_uri(t zgrab2.ScanTarget) string {
	return "https://" + t.IP.String()
}

func processHTTPResponse(resp *http.Response) (*HTTPResponseInfo, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	encoded_body := base64.StdEncoding.EncodeToString(body)
	header_info := make([]string, 0)
	for k, v := range resp.Header {
		values := strings.Join(v, "||")
		key := Strconcat(k, ": ")
		header_info = append(header_info, Strconcat(key, values))
	}

	return &HTTPResponseInfo{resp.StatusCode, resp.Proto, header_info, encoded_body}, nil
}

func performHTTPRequest_(req *http.Request,
	client *http.Client, delay_time int) (*HTTPResponseInfo, error) {

	if delay_time > 0 {
		time.Sleep(time.Duration(rand.Intn(delay_time)) * time.Second)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	httpResponseInfo, err := processHTTPResponse(resp)
	if err != nil {
		return nil, err
	}

	return httpResponseInfo, err
}

func performHTTPRequest(req *http.Request,
	client *http.Client, delay_time int) (*HTTPResponseInfo, error) {

	var err error
	var response_info *HTTPResponseInfo

	for i := 0; i < CONNECTION_ATTEMPTS; i++ {
		response_info, err = performHTTPRequest_(req, client, delay_time)
		if (err != nil && !CONNECTION_ERRORS.invPartialContains(err.Error())) || err == nil {
			break
		}
	}

	return response_info, err
}

// Args: Scan Target <-> IP, Domain
// Outputs: SupportsHTTP, HTTPResponseStatusCode, HTTPResponseHeader, HTTPResponseBody, error
func httpScan(t zgrab2.ScanTarget, delay_time int) (*HTTPResponseInfo, error) {
	client := &http.Client{
		Timeout: time.Duration(HTTP_TIMEOUT),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			IdleConnTimeout: time.Duration(HTTP_TIMEOUT),
		},
	}

	req, err := http.NewRequest("GET", http_uri(t), nil)
	if err != nil {
		return nil, errors.New("Failed to construct HTTP Request")
	}

	//Sets Host header to Domain
	req.Host = t.Domain
	req.Header.Set("User-Agent", "Mozilla/5.0 zgrab/0.x")
	req.Header.Add("Accept-Encoding", "gzip;q=1.0, deflate;q=0.9, compress;q=0.8, *;q=0.7")

	httpResponseInfo, err := performHTTPRequest(req, client, delay_time)
	if err != nil {
		return nil, err
	}

	return httpResponseInfo, err
}

func httpsScan(t zgrab2.ScanTarget, delay_time int) (*HTTPResponseInfo, error) {

	cbu := CipherSlice(CIPHERS_BROWSER_UNION).toUIntArray()

	//Client avoids DNS lookup
	client := &http.Client{
		Timeout: time.Duration(HTTP_TIMEOUT),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			IdleConnTimeout:     time.Duration(HTTP_TIMEOUT),
			TLSHandshakeTimeout: time.Duration(HTTP_TIMEOUT),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       cbu,
				ServerName:         t.Domain,
				// For some reason setting SignatureAndHashes
				// or compression methods is ignored
				// to compensate the default for InsecureSkipVerify
				// will be tls.defaultSkipVerify
			},
			DialContext: func(ctx context.Context,
				network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: time.Duration(HTTP_TIMEOUT)}).DialContext(ctx, network, t.IP.String()+":443")
			},
		},
	}
	req, err := http.NewRequest("GET", https_uri(t), nil)
	if err != nil {
		return nil, errors.New("Failed to construct HTTPS Request")
	}

	req.Host = t.Domain
	req.Header.Set("User-Agent", "Mozilla/5.0 zgrab/0.x")
	req.Header.Add("Accept-Encoding", "gzip;q=1.0, deflate;q=0.9, compress;q=0.8, *;q=0.7")

	httpResponseInfo, err := performHTTPRequest(req, client, delay_time)
	if err != nil {
		return nil, err
	}

	return httpResponseInfo, err
}

func http2Scan(t zgrab2.ScanTarget, delay_time int) (*HTTPResponseInfo, error) {

	cbu := CipherSlice(CIPHERS_BROWSER_UNION).toUIntArray()

	//Client avoids DNS lookup
	client := &http.Client{
		Timeout: time.Duration(HTTP_TIMEOUT),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       cbu,
				ServerName:         t.Domain,
				// For some reason setting SignatureAndHashes
				// or compression methods is ignored
				// to compensate the default for InsecureSkipVerify
				// will be tls.defaultSkipVerify
			},
			DialTLS: func(network, addr string, tls_cfg *tls.Config) (net.Conn, error) {
				dialer := new(net.Dialer)
				dialer.Timeout = time.Duration(HTTP_TIMEOUT)
				return tls.DialWithDialer(dialer, network, addr, tls_cfg)
			},
		},
	}
	req, err := http.NewRequest("GET", https_uri(t), nil)
	if err != nil {
		return nil, errors.New("Failed to construct HTTPS Request")
	}

	req.Host = t.Domain
	req.Header.Set("User-Agent", "Mozilla/5.0 zgrab/0.x")
	req.Header.Add("Accept-Encoding", "gzip;q=1.0, deflate;q=0.9, compress;q=0.8, *;q=0.7")

	httpResponseInfo, err := performHTTPRequest(req, client, delay_time)
	if err != nil {
		return nil, err
	}

	return httpResponseInfo, err
}

// scans for http/https support
// arguments: scan target <-> ip, domain
// outputs: httpsupport
func HttpSupportScan(t zgrab2.ScanTarget, tlsFlags zgrab2.TLSFlags) HTTPSupport {
	httpRI, httpErr := httpScan(t, tlsFlags.HandshakeDelay)
	httpsRI, httpsErr := httpsScan(t, tlsFlags.HandshakeDelay)
	http2RI, http2Err := http2Scan(t, tlsFlags.HandshakeDelay)
	return HTTPSupport{
		SupportsHTTP:  httpErr == nil,
		HTTPResponse:  httpRI,
		HTTPError:     Err{httpErr},
		SupportsHTTPS: httpsErr == nil,
		HTTPSResponse: httpsRI,
		HTTPSError:    Err{httpsErr},
		SupportsHTTP2: http2Err == nil && http2RI.ResponseProtocol == "HTTP/2.0",
		HTTP2Response: http2RI,
		HTTP2Error:    Err{http2Err},
	}
}
