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

package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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
	if dump, derr := httputil.DumpRequestOut(req, l.LogBody); derr == nil {
		l.LogFunc(string(dump))
	}

	res, err := l.Delegate.RoundTrip(req)

	if dump, derr := httputil.DumpResponse(res, l.LogBody); derr == nil {
		l.LogFunc(string(dump))
	}

	return res, err
}

// CookieTracker is a http.RoundTripper that tracks cookies received from the server.
type CookieTracker struct {
	Delegate http.RoundTripper
	Cookies  map[string]*http.Cookie
}

// RoundTrip tracks the cookies received from the server.
func (c CookieTracker) RoundTrip(req *http.Request) (*http.Response, error) {
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
	http        *http.Client            // Delegate HTTP client
	cookies     map[string]*http.Cookie // Cookies received from the server
	loginURL    string                  // URL of the IdP where users need to authenticate
	loginMethod string                  // Method (GET/POST) to use when posting the credentials to the IdP
	tlsConfig   *tls.Config             // Custom TLS configuration, if needed
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
		o.tlsConfig = &tls.Config{RootCAs: caCertPool}
		return nil
	}
}

// WithLoggingOptions configures the OIDCTestClient to log requests and responses.
func WithLoggingOptions(logFunc func(...any), logBody bool) Option {
	return func(o *OIDCTestClient) error {
		o.http.Transport = LoggingRoundTripper{
			LogBody:  logBody,
			LogFunc:  logFunc,
			Delegate: o.http.Transport,
		}
		return nil
	}
}

// NewOIDCTestClient creates a new OIDCTestClient.
func NewOIDCTestClient(opts ...Option) (*OIDCTestClient, error) {
	var (
		defaultTransport = http.DefaultTransport.(*http.Transport).Clone()
		cookies          = make(map[string]*http.Cookie)
		client           = &OIDCTestClient{
			cookies: cookies,
			http: &http.Client{
				Transport: CookieTracker{
					Cookies:  cookies,
					Delegate: defaultTransport,
				},
			},
		}
	)

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	defaultTransport.TLSClientConfig = client.tlsConfig

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
	for _, c := range o.cookies {
		req.AddCookie(c)
	}
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

// ParseLoginForm parses the HTML response body to get the URL where the login page would post the user-entered credentials.
func (o *OIDCTestClient) ParseLoginForm(responseBody io.ReadCloser, formID string) error {
	body, err := io.ReadAll(responseBody)
	if err != nil {
		return err
	}
	o.loginURL, o.loginMethod, err = getFormAction(string(body), formID)
	return err
}

// getFormAction returns the action attribute of the form with the specified ID in the given HTML response body.
func getFormAction(responseBody string, formID string) (string, string, error) {
	// Parse HTML response
	doc, err := html.Parse(strings.NewReader(responseBody))
	if err != nil {
		return "", "", err
	}

	// Find the form with the specified ID
	var findForm func(*html.Node) (string, string)
	findForm = func(n *html.Node) (string, string) {
		var (
			action string
			method = "POST"
		)
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == formID {
					for _, a := range n.Attr {
						if a.Key == "action" {
							action = a.Val
						} else if a.Key == "method" {
							method = strings.ToUpper(a.Val)
						}
					}
					return action, method
				}
			}
		}

		// Recursively search for the form in child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if ra, rm := findForm(c); ra != "" {
				return ra, rm
			}
		}

		return "", ""
	}

	action, method := findForm(doc)
	if action == "" {
		return "", "", fmt.Errorf("form with ID '%s' not found", formID)
	}

	return action, method, nil
}
