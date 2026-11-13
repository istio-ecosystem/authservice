// Copyright 2025 Tetrate
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

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/istio-ecosystem/authservice/internal"
)

// WellKnownConfig represents the OIDC well-known configuration
type WellKnownConfig struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURL                  string   `json:"jwks_uri"`
	ResponseTypesSupported   []string `json:"response_types_supported"`
	SubjectTypesSupported    []string `json:"subject_types_supported"`
	IDTokenSigningAlgorithms []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	EndSessionEndpoint       string   `json:"end_session_endpoint"`
	RevocationEndpoint       string   `json:"revocation_endpoint"`
	IntrospectionEndpoint    string   `json:"introspection_endpoint"`
	ScopesSupported          []string `json:"scopes_supported"`
	ClaimsSupported          []string `json:"claims_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
	TokenRevocationEndpoint  string   `json:"token_revocation_endpoint"`
}

var (
	// wellKnownConfigs is a map of issuer URL to the OIDC well-known configuration
	// It is used to cache well-known configurations as they usually don't change. URLs are usually stable, and the only
	// things that are subject to change are the signing keys, but those are already watched periodically by the JWKS fetcher.
	wellKnownConfigs   = make(map[string]WellKnownConfig)
	wellKnownConfigsMu sync.RWMutex
)

// GetWellKnownConfig retrieves the OIDC well-known configuration from the given issuer URL.
func GetWellKnownConfig(ctx context.Context, client *http.Client, url string) (WellKnownConfig, error) {
	if err := ctx.Err(); err != nil {
		return WellKnownConfig{}, err
	}
	wellKnownConfigsMu.RLock()
	cfg, ok := wellKnownConfigs[url]
	wellKnownConfigsMu.RUnlock()
	if ok {
		return cfg, nil
	}

	// Make a GET request to the well-known configuration endpoint
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return WellKnownConfig{}, err
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return WellKnownConfig{}, internal.LogRequestError(ctx, internal.Logger(internal.IDP).Context(ctx),
			"OIDC discovery request failed", err, "dependency", request.URL.Host, "duration", time.Since(start))
	}
	defer func() { _ = response.Body.Close() }()

	// Check if the response status code is successful
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to retrieve OIDC config: HTTP %d", response.StatusCode)
		return WellKnownConfig{}, internal.LogRequestError(ctx, internal.Logger(internal.IDP).Context(ctx),
			"OIDC discovery failed", err, "dependency", request.URL.Host, "status", response.StatusCode, "duration", time.Since(start))
	}

	// Decode the JSON response into the OIDCConfig struct
	if err = json.NewDecoder(response.Body).Decode(&cfg); err != nil {
		return WellKnownConfig{}, internal.LogRequestError(ctx, internal.Logger(internal.IDP).Context(ctx),
			"invalid OIDC discovery response", err, "dependency", request.URL.Host, "duration", time.Since(start))
	}

	wellKnownConfigsMu.Lock()
	wellKnownConfigs[url] = cfg
	wellKnownConfigsMu.Unlock()
	return cfg, nil
}
