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
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tetrateio/authservice-go/e2e/common"
)

const (
	dockerLocalHost     = "host.docker.internal"
	idpBaseURLHost      = "http://host.docker.internal:8080"
	keyCloakLoginFormID = "kc-form-login"
	testCAFile          = "certs/ca.crt"
	username            = "authservice"
	password            = "authservice"
)

var testURL = fmt.Sprintf("https://%s:8443", dockerLocalHost)

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

	// Initialize the test OIDC client that will keep track of the state of the OIDC login process
	client, err := common.NewOIDCTestClient(
		common.WithCustomCA(testCAFile),
		common.WithLoggingOptions(t.Log, true),
	)
	require.NoError(t, err)

	// Send a request to the test server. It will be redirected to the IdP login page
	res, err := client.Get(testURL)
	require.NoError(t, err)

	// Parse the response body to get the URL where the login page would post the user-entered credentials
	require.NoError(t, client.ParseLoginForm(res.Body, keyCloakLoginFormID))

	// Submit the login form to the IdP. This will authenticate and redirect back to the application
	res, err = client.Login(map[string]string{"username": username, "password": password, "credentialId": ""})
	require.NoError(t, err)

	// Verify that we get the expected response from the application
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, string(body), "Access allowed")
}

func TestOIDCRefreshTokens(t *testing.T) {
	skipIfDockerHostNonResolvable(t)

	// Initialize the test OIDC client that will keep track of the state of the OIDC login process
	client, err := common.NewOIDCTestClient(
		common.WithCustomCA(testCAFile),
		common.WithLoggingOptions(t.Log, true),
	)
	require.NoError(t, err)

	// Send a request to the test server. It will be redirected to the IdP login page
	res, err := client.Get(testURL)
	require.NoError(t, err)

	// Parse the response body to get the URL where the login page would post the user-entered credentials
	require.NoError(t, client.ParseLoginForm(res.Body, keyCloakLoginFormID))

	// Submit the login form to the IdP. This will authenticate and redirect back to the application
	res, err = client.Login(map[string]string{"username": username, "password": password, "credentialId": ""})
	require.NoError(t, err)

	// Verify that we get the expected response from the application
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, string(body), "Access allowed")

	// Access tokens should expire in 10 seconds (tried with 5, but keycloak setup fails)
	// Let's perform a request now and after 10 seconds to verify that the access token is refreshed

	t.Run("request with same tokens", func(t *testing.T) {
		res, err = client.Get(testURL)
		require.NoError(t, err)

		body, err = io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "Access allowed")
	})

	t.Log("waiting for access token to expire...")
	time.Sleep(10 * time.Second)

	t.Run("request with expired tokens", func(t *testing.T) {
		res, err = client.Get(testURL)
		require.NoError(t, err)

		body, err = io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "Access allowed")
	})
}

func TestOIDCLogout(t *testing.T) {
	skipIfDockerHostNonResolvable(t)

	// Initialize the test OIDC client that will keep track of the state of the OIDC login process
	client, err := common.NewOIDCTestClient(
		common.WithCustomCA(testCAFile),
		common.WithLoggingOptions(t.Log, true),
		common.WithBaseURL(idpBaseURLHost),
	)
	require.NoError(t, err)

	t.Run("first request requires login", func(t *testing.T) {
		// Send a request to the test server. It will be redirected to the IdP login page
		res, err := client.Get(testURL)
		require.NoError(t, err)

		// Parse the response body to get the URL where the login page would post the user-entered credentials
		require.NoError(t, client.ParseLoginForm(res.Body, keyCloakLoginFormID))

		// Submit the login form to the IdP. This will authenticate and redirect back to the application
		res, err = client.Login(map[string]string{"username": username, "password": password, "credentialId": ""})
		require.NoError(t, err)

		// Verify that we get the expected response from the application
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "Access allowed")
	})

	t.Run("second request works without login redirect", func(t *testing.T) {
		res, err := client.Get(testURL)
		require.NoError(t, err)

		// Verify that we get the expected response from the application
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "Access allowed")
	})

	t.Run("logout", func(t *testing.T) {
		// Logout
		res, err := client.Get(testURL + "/logout")
		require.NoError(t, err)

		// Parse the response body to get the URL where the login page would post the session logout
		require.NoError(t, client.ParseLogoutForm(res.Body))

		// Submit the logout form to the IdP. This will log out the user and redirect back to the application
		res, err = client.Logout()
		require.NoError(t, err)

		// Verify that we get the logout confirmation from the IDP
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "You are logged out")
	})

	t.Run("request after logout requires login again", func(t *testing.T) {
		// Send a request to the test server. It will be redirected to the IdP login page
		res, err := client.Get(testURL)
		require.NoError(t, err)

		// Parse the response body to get the URL where the login page would post the user-entered credentials
		require.NoError(t, client.ParseLoginForm(res.Body, keyCloakLoginFormID))

		// Submit the login form to the IdP. This will authenticate and redirect back to the application
		res, err = client.Login(map[string]string{"username": username, "password": password, "credentialId": ""})
		require.NoError(t, err)

		// Verify that we get the expected response from the application
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, string(body), "Access allowed")
	})
}
