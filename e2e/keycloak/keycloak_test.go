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

package keycloak

import (
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
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal/authz"
)

const (
	dockerLocalHost         = "host.docker.internal"
	authServiceCookiePrefix = "authservice"
	keyCloakLoginFormID     = "kc-form-login"
	testCAFile              = "certs/ca.crt"
	username                = "authservice"
	password                = "authservice"
)

var (
	testURL               = fmt.Sprintf("https://%s:8443", dockerLocalHost)
	authServiceCookieName = authz.GetCookieName(&oidcv1.OIDCConfig{CookieNamePrefix: authServiceCookiePrefix})
	authServiceCookie     *http.Cookie
)

// skipIfDockerHostNonResolvable skips the test if the Docker host is not resolvable.
func skipIfDockerHostNonResolvable(t *testing.T) {
	_, err := net.ResolveIPAddr("ip", dockerLocalHost)
	if err != nil {
		t.Fatalf("skipping test: %[1]q is not resolvable\n"+
			"Please configure your environment so that %[1]q resolves to the address of the Docker host machine.\n"+
			"For example: echo \"127.0.0.1 %[1]s\" >>/etc/hosts",
			dockerLocalHost)
	}
}

func TestOIDC(t *testing.T) {
	skipIfDockerHostNonResolvable(t)

	client := testHTTPClient(t)

	// Send a request. This will be redirected to the IdP login page
	res, err := client.Get(testURL)
	require.NoError(t, err)
	logResponse(t, res)

	// Parse the response body to get the URL where the login page would post the user-entered credentials
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	formAction, err := getFormAction(string(body), keyCloakLoginFormID)
	require.NoError(t, err)

	// Generate a request to authenticate against the IdP by posting the credentials
	data := url.Values{}
	data.Add("username", username)
	data.Add("password", password)
	data.Add("credentialId", "")
	req, err := http.NewRequest("POST", formAction, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range res.Cookies() { // Propagate all returned cookies
		req.AddCookie(c)
	}
	// This cookie should have been captured by the client when the AuthService redirected the request to the IdP
	req.AddCookie(authServiceCookie)
	logRequest(t, req)

	// Post the login credentials. After this, the IdP should redirect to the original request URL
	res, err = client.Do(req)
	require.NoError(t, err)
	logResponse(t, res)

	// Verify the response to check that we were redirected to tha target service.
	body, err = io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, res.StatusCode, http.StatusOK)
	require.Contains(t, string(body), "Access allowed")
}

// testHTTPClient returns an HTTP client with custom transport that trusts the CA certificate used in the e2e tests.
func testHTTPClient(t *testing.T) *http.Client {
	caCert, err := os.ReadFile(testCAFile)
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: caCertPool}

	return &http.Client{
		Transport: transport,
		// We intercept the redirect call to the AuthService to be able to save the cookie set
		// bu the AuthService and use it when posting the credentials to authenticate to the IdP.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			for _, c := range req.Response.Cookies() {
				if c.Name == authServiceCookieName {
					authServiceCookie = c
					break
				}
			}
			return nil
		},
	}
}

// logRequest logs the request details.
func logRequest(t *testing.T, req *http.Request) {
	dump, err := httputil.DumpRequestOut(req, true)
	require.NoError(t, err)
	t.Log(string(dump))
}

// logResponse logs the response details.
func logResponse(t *testing.T, res *http.Response) {
	dump, err := httputil.DumpResponse(res, true)
	require.NoError(t, err)
	t.Log(string(dump))
}

// getFormAction returns the action attribute of the form with the specified ID in the given HTML response body.
func getFormAction(responseBody string, formID string) (string, error) {
	// Parse HTML response
	doc, err := html.Parse(strings.NewReader(responseBody))
	if err != nil {
		return "", err
	}

	// Find the form with the specified ID
	var findForm func(*html.Node) string
	findForm = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == formID {
					// Found the form, return its action attribute
					for _, a := range n.Attr {
						if a.Key == "action" {
							return a.Val
						}
					}
				}
			}
		}

		// Recursively search for the form in child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := findForm(c); result != "" {
				return result
			}
		}

		return ""
	}

	action := findForm(doc)
	if action == "" {
		return "", fmt.Errorf("form with ID '%s' not found", formID)
	}

	return action, nil
}
