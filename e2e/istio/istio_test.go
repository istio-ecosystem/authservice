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

package istio

import (
	"io"
	"net/http"

	"github.com/istio-ecosystem/authservice/e2e"
)

const (
	testURLTLS          = "https://http-echo.authservice.internal"
	testURLPlain        = "http://http-echo.authservice.internal"
	testCAFile          = "certs/ca.crt"
	keyCloakLoginFormID = "kc-form-login"
	username            = "authservice"
	password            = "authservice"
)

func (i *IstioSuite) TestIstioEnforcement() {
	for name, uri := range map[string]string{
		"client requests TLS":                              testURLTLS,
		"client requests plain text, is redirected to TLS": testURLPlain,
	} {
		i.Run(name, func() {
			// Initialize the test OIDC client that will keep track of the state of the OIDC login process
			// Initialize it for each test to not reuse the session between them
			client, err := e2e.NewOIDCTestClient(
				e2e.WithLoggingOptions(i.T().Log, true),
				e2e.WithCustomCA(testCAFile),
				// Map the keycloak cluster DNS name to the local address where the service is exposed
				e2e.WithCustomAddressMappings(map[string]string{
					"http-echo.authservice.internal:80":  "localhost:30002",
					"http-echo.authservice.internal:443": "localhost:30000",
					"keycloak.keycloak:8080":             "localhost:30001",
				}),
			)
			i.Require().NoError(err)

			// Send a request to the test server. It will be redirected to the IdP login page
			res, err := client.Get(uri)
			i.Require().NoError(err)

			// Parse the response body to get the URL where the login page would post the user-entered credentials
			i.Require().NoError(client.ParseLoginForm(res.Body, keyCloakLoginFormID))

			// Submit the login form to the IdP. This will authenticate and redirect back to the application
			res, err = client.Login(map[string]string{"username": username, "password": password, "credentialId": ""})
			i.Require().NoError(err)

			// Verify that we get the expected response from the application
			body, err := io.ReadAll(res.Body)
			i.Require().NoError(err)
			i.Require().Equal(http.StatusOK, res.StatusCode)
			i.Require().Contains(string(body), "Request served by http-echo")
			// as the destination app is an echo server that returns the received request in the body, we can verify this
			// received contained the proper tokens
			i.Require().Contains(string(body), "Authorization: Bearer")
			i.Require().Contains(string(body), "X-Access-Token:")
		})
	}
}
