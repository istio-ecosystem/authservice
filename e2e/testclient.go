// Copyright 2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/html"
)

// LoggingRoundTripper is a http.RoundTripper that logs requests and responses.
type LoggingRoundTripper struct {
	LogFunc  func(...any)
	LogBody  bool
	Delegate http.RoundTripper
}

// RoundTrip logs all the requests and responses using the configured settings.
func (l LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.LogFunc != nil {
		if dump, derr := httputil.DumpRequest(req, l.LogBody); derr == nil {
			l.LogFunc(string(dump))
		}
	}

	res, err := l.Delegate.RoundTrip(req)
	if err == nil && l.LogFunc != nil {
		if dump, derr := httputil.DumpResponse(res, l.LogBody); derr == nil {
			l.LogFunc(string(dump))
		}
	}

	return res, err
}

// CookieTracker is a http.RoundTripper that tracks cookies received from the server.
type CookieTracker struct {
	Delegate http.RoundTripper
	Cookies  map[string]*http.Cookie
}

// RoundTrip tracks the cookies received from the server.
func (c *CookieTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, ck := range c.Cookies {
		req.AddCookie(ck)
	}

	res, err := c.Delegate.RoundTrip(req)

	if err == nil {
		// Track the cookies received from the server
		for _, ck := range res.Cookies() {
			c.Cookies[ck.Name] = ck
		}
	}

	return res, err
}

// OIDCTestClient encapsulates a http.Client and keeps track of the state of the OIDC login process.
type OIDCTestClient struct {
	http         *http.Client     // Delegate HTTP client
	loginURL     string           // URL of the IdP where users need to authenticate
	loginMethod  string           // Method (GET/POST) to use when posting the credentials to the IdP
	idpBaseURL   string           // Base URL of the IdP
	logoutURL    string           // URL of the IdP where users need to log out
	logoutMethod string           // Method (GET/POST) to use when posting the logout request to the IdP
	logoutForm   url.Values       // Form data to use when posting the logout request to the IdP
	customCA     *x509.CertPool   // Custom TLS configuration, if needed
	mappings     *AddressMappings // Custom address mappings
	logFunc      func(...any)     // Logging function to log all requests and responses
	logBody      bool             // Whether to log the request and response bodies
}

// Option is a functional option for configuring the OIDCTestClient.
type Option func(*OIDCTestClient) error

// WithCustomCA configures the OIDCTestClient to use a custom CA bundle to verify certificates.
func WithCustomCA(caCert string) Option {
	return func(o *OIDCTestClient) error {
		caCert, err := os.ReadFile(caCert)
		if err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		o.customCA = caCertPool
		return nil
	}
}

// WithLoggingOptions configures the OIDCTestClient to log requests and responses.
func WithLoggingOptions(logFunc func(...any), logBody bool) Option {
	return func(o *OIDCTestClient) error {
		o.logFunc = logFunc
		o.logBody = logBody
		return nil
	}
}

// AddressMappings is a custom dialer that resolves specific host:port to specific target addresses.
type AddressMappings struct {
	addresses map[string]string
}

// DialContext is a custom dialer that resolves specific host:port to specific target addresses.
func (a *AddressMappings) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if resolved, ok := a.addresses[addr]; ok {
		addr = resolved
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// DialTLSContext is a custom dialer that resolves specific host:port to specific target addresses.
func (a *AddressMappings) DialTLSContext(tlsConfig *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		cfg := tlsConfig.Clone()
		if resolved, ok := a.addresses[addr]; ok {
			// Use the original hostname for the SNI, to avoid certificate verification errors
			cfg.ServerName = addr[:strings.Index(addr, ":")]
			addr = resolved
		}
		return tls.Dial(network, addr, cfg)
	}
}

// WithCustomAddressMappings configures the OIDCTestClient to resolve specific host:port to
// specific target addresses.
func WithCustomAddressMappings(mappings map[string]string) Option {
	return func(o *OIDCTestClient) error {
		o.mappings = &AddressMappings{
			addresses: mappings,
		}
		return nil
	}
}

// WithBaseURL configures the OIDCTestClient to use the specified IdP base url.
// Required when the form action URL is relative. For example the logout one.
func WithBaseURL(idpBaseURL string) Option {
	return func(o *OIDCTestClient) error {
		o.idpBaseURL = idpBaseURL
		return nil
	}
}

// NewOIDCTestClient creates a new OIDCTestClient.
func NewOIDCTestClient(opts ...Option) (*OIDCTestClient, error) {
	var (
		defaultTransport = http.DefaultTransport.(*http.Transport).Clone()
		logging          = &LoggingRoundTripper{Delegate: defaultTransport}
		cookieTracker    = &CookieTracker{Cookies: make(map[string]*http.Cookie), Delegate: logging}
		client           = &OIDCTestClient{http: &http.Client{Transport: cookieTracker}}
	)

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	logging.LogFunc = client.logFunc
	logging.LogBody = client.logBody

	defaultTransport.TLSClientConfig = &tls.Config{RootCAs: client.customCA}
	if client.mappings != nil {
		defaultTransport.DialContext = client.mappings.DialContext
		defaultTransport.DialTLSContext = client.mappings.DialTLSContext(defaultTransport.TLSClientConfig)
	}

	return client, nil
}

// Get sends a GET request to the specified URL.
func (o *OIDCTestClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return o.Send(req)
}

// Send sends the specified request.
func (o *OIDCTestClient) Send(req *http.Request) (*http.Response, error) {
	return o.http.Do(req)
}

// Login logs in to the IdP using the provided credentials.
func (o *OIDCTestClient) Login(formData map[string]string) (*http.Response, error) {
	if o.loginURL == "" {
		return nil, fmt.Errorf("login URL is not set")
	}
	data := url.Values{}
	for k, v := range formData {
		data.Add(k, v)
	}
	req, err := http.NewRequest(o.loginMethod, o.loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return o.Send(req)
}

// Logout logs out from the IdP.
func (o *OIDCTestClient) Logout() (*http.Response, error) {
	if o.logoutURL == "" {
		return nil, fmt.Errorf("logout URL is not set")
	}
	req, err := http.NewRequest(o.logoutMethod, o.logoutURL, strings.NewReader(o.logoutForm.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return o.Send(req)
}

// ParseLoginForm parses the HTML response body to get the URL where the login page would post the user-entered credentials.
func (o *OIDCTestClient) ParseLoginForm(responseBody io.ReadCloser, formID string) error {
	body, err := io.ReadAll(responseBody)
	if err != nil {
		return err
	}
	o.loginURL, o.loginMethod, _, err = extractFromData(string(body), idFormMatcher{formID}, false)
	return err
}

// ParseLogoutForm parses the HTML response body to get the URL where the logout page would post the session logout.
func (o *OIDCTestClient) ParseLogoutForm(responseBody io.ReadCloser) error {
	body, err := io.ReadAll(responseBody)
	if err != nil {
		return err
	}
	var logoutURL string
	logoutURL, o.logoutMethod, o.logoutForm, err = extractFromData(string(body), firstFormMatcher{}, true)
	if err != nil {
		return err
	}

	// If the logout URL is relative, use the host from the OIDCTestClient configuration
	if !strings.HasPrefix(logoutURL, "http") {
		logoutURL = o.idpBaseURL + logoutURL
	}
	o.logoutURL = logoutURL
	return nil
}

// extractFromData extracts the form action, method and values from the HTML response body.
func extractFromData(responseBody string, match formMatch, includeFromInputs bool) (string, string, url.Values, error) {
	// Parse HTML response
	doc, err := html.Parse(strings.NewReader(responseBody))
	if err != nil {
		return "", "", nil, err
	}

	// Find the form with the specified ID or match criteria
	form := findForm(doc, match)
	if form == nil {
		return "", "", nil, fmt.Errorf("%s not found", match)
	}

	var (
		action, method string
		formValues     = make(url.Values)
	)

	// Get the action and method of the form
	for _, a := range form.Attr {
		switch a.Key {
		case "action":
			action = a.Val
		case "method":
			method = strings.ToUpper(a.Val)
		}
	}

	// If we want to include inputs, recursively iterate the children
	if includeFromInputs {
		formValues = findFormInputs(form)
	}

	return action, method, formValues, nil
}

// findForm recursively searches for a form in the HTML response body that matches the specified criteria.
func findForm(n *html.Node, match formMatch) *html.Node {
	// Check if the current node is a form and matches the specified criteria
	if match.matches(n) {
		return n
	}

	// Else, recursively search for the form in child nodes
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if form := findForm(c, match); form != nil {
			return form
		}
	}
	return nil
}

// findFormInputs recursively searches for input fields in the HTML form node.
func findFormInputs(formNode *html.Node) url.Values {
	form := make(url.Values)
	for c := formNode.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "input" {
			var name, value string
			for _, a := range c.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "value":
					value = a.Val
				}
			}
			form.Add(name, value)
		} else {
			for k, v := range findFormInputs(c) {
				form[k] = append(form[k], v...)
			}
		}
	}
	return form
}

var (
	_ formMatch = idFormMatcher{}
	_ formMatch = firstFormMatcher{}
)

type (
	// formMatch is an interface that defines the criteria to match a form in the HTML response body.
	formMatch interface {
		matches(*html.Node) bool
		String() string
	}

	// idFormMatcher matches a form with the specified ID.
	idFormMatcher struct {
		id string
	}

	// firstFormMatcher matches the first form in the HTML response body.
	firstFormMatcher struct{}
)

func (m idFormMatcher) matches(n *html.Node) bool {
	if n.Type != html.ElementNode || n.Data != "form" {
		return false
	}

	for _, a := range n.Attr {
		if a.Key == "id" && a.Val == m.id {
			return true
		}
	}
	return false
}

func (m idFormMatcher) String() string {
	return fmt.Sprintf("form with ID '%s'", m.id)
}

func (m firstFormMatcher) matches(n *html.Node) bool {
	return n.Type == html.ElementNode && n.Data == "form"
}

func (m firstFormMatcher) String() string {
	return "first form"
}

// NewSkipHostnameVerificationConfig returns a TLS configuration that
// doesn't perform the default certificate verification because it
// will verify the hostname. Instead, it verifies the server's
// certificate chain in VerifyPeerCertificate and ignores the server
// name.
//
// See https://github.com/golang/go/issues/21971#issuecomment-332693931
// and https://pkg.go.dev/crypto/tls?tab=doc#example-Config-VerifyPeerCertificate
// for more info.
func NewSkipHostnameVerificationConfig(rootCAs *x509.CertPool) *tls.Config {
	// Disable "G402 (CWE-295): TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH)"
	// #nosec G402
	return &tls.Config{
		// Set to true because otherwise the certs AND the hostname are verified.
		// Instead, the certificate verification will be done by the custom
		// VerifyPeerCertificate, ignoring the server name,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(certificates [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(certificates))
			for i, asn1Data := range certificates {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return fmt.Errorf("failed to parse certificate from server: %w", err)
				}
				certs[i] = cert
			}

			// Leave DNSName empty to skip hostname verification.
			opts := x509.VerifyOptions{
				Roots:         rootCAs,
				Intermediates: x509.NewCertPool(),
			}
			// Skip the first cert because it's the leaf. All others
			// are intermediates.
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			return err
		},
	}
}
