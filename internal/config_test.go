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

package internal

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

type errCheck struct {
	is  error
	as  error
	msg string
}

func (e errCheck) Check(t *testing.T, err error) {
	switch {
	case e.as != nil:
		require.ErrorAs(t, err, &e.as)
	case e.msg != "":
		require.ErrorContains(t, err, e.msg)
	default:
		require.ErrorIs(t, err, e.is)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		check errCheck
	}{
		{"empty", "", errCheck{is: ErrInvalidPath}},
		{"unexisting", "unexisting", errCheck{is: os.ErrNotExist}},
		{"invalid-config", "testdata/invalid-config.json", errCheck{msg: `unknown field "foo"`}},
		{"invalid-values", "testdata/invalid-values.json", errCheck{as: &configv1.ConfigMultiError{}}},
		{"duplicate-oidc", "testdata/duplicate-oidc.json", errCheck{is: ErrDuplicateOIDCConfig}},
		{"invalid-oidc-override", "testdata/invalid-oidc-override.json", errCheck{is: ErrInvalidOIDCOverride}},
		{"multiple-oidc", "testdata/multiple-oidc.json", errCheck{is: ErrMultipleOIDCConfig}},
		{"invalid-redis", "testdata/invalid-redis.json", errCheck{is: ErrInvalidURL}},
		{"invalid-oidc-uris", "testdata/invalid-oidc-uris.json", errCheck{is: ErrRequiredURL}},
		{"invalid-health-port", "testdata/invalid-health-port.json", errCheck{is: ErrHealthPortInUse}},
		{"invalid-callback-uri", "testdata/invalid-callback.json", errCheck{is: ErrMustNotBeRootPath}},
		{"invalid-logout-path", "testdata/invalid-logout.json", errCheck{is: ErrMustNotBeRootPath}},
		{"valid-logout-override-default", "testdata/valid-logout-override-default.json", errCheck{is: nil}},
		{"invalid-callback-and-logout-path", "testdata/invalid-callback-logout.json", errCheck{is: ErrMustBeDifferentPath}},
		{"oidc-dynamic", "testdata/oidc-dynamic.json", errCheck{is: nil}},
		{"valid", "testdata/mock.json", errCheck{is: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&LocalConfigFile{path: tt.path}).Validate()
			tt.check.Check(t, err)
		})
	}
}

func TestValidateURLs(t *testing.T) {
	const (
		validURL      = "http://fake/path"
		invalidURL    = "ht tp://invalid"
		validRedisURL = "redis://localhost:6379/0"
	)

	urlTests := []struct {
		name    string
		oidCCfg *oidcv1.OIDCConfig
		check   errCheck
	}{
		{"empty", &oidcv1.OIDCConfig{}, errCheck{is: nil}},
		{
			"invalid-redis",
			&oidcv1.OIDCConfig{RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: invalidURL}},
			errCheck{is: ErrInvalidURL},
		},
		{
			"invalid-jwks-fetcher",
			&oidcv1.OIDCConfig{
				JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
					JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{JwksUri: invalidURL},
				},
			},
			errCheck{is: ErrInvalidURL},
		},
		{"invalid-proxy-uri", &oidcv1.OIDCConfig{ProxyUri: invalidURL}, errCheck{is: ErrInvalidURL}},
		{"invalid-token-uri", &oidcv1.OIDCConfig{TokenUri: invalidURL}, errCheck{is: ErrInvalidURL}},
		{"invalid-authorization-uri", &oidcv1.OIDCConfig{AuthorizationUri: invalidURL}, errCheck{is: ErrInvalidURL}},
		{"invalid-callback-uri", &oidcv1.OIDCConfig{CallbackUri: invalidURL}, errCheck{is: ErrInvalidURL}},
		{
			"valid",
			&oidcv1.OIDCConfig{
				ProxyUri: validURL, AuthorizationUri: validURL, TokenUri: validURL, CallbackUri: validURL,
				JwksConfig:              &oidcv1.OIDCConfig_JwksFetcher{JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{JwksUri: validURL}},
				RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: validRedisURL},
			},
			errCheck{is: nil},
		},
	}

	configTests := []struct {
		name string
		cfg  func(*oidcv1.OIDCConfig) *configv1.Config
	}{
		{
			"default",
			func(oidcCfg *oidcv1.OIDCConfig) *configv1.Config {
				return &configv1.Config{DefaultOidcConfig: oidcCfg}
			},
		},
		{
			"chain-oidc",
			func(oidcCfg *oidcv1.OIDCConfig) *configv1.Config {
				return &configv1.Config{
					Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{{Type: &configv1.Filter_Oidc{Oidc: oidcCfg}}}}},
				}
			},
		},
		{
			"chain-oidc-override",
			func(oidcCfg *oidcv1.OIDCConfig) *configv1.Config {
				return &configv1.Config{
					Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{{Type: &configv1.Filter_OidcOverride{OidcOverride: oidcCfg}}}}},
				}
			},
		},
	}

	for _, ct := range configTests {
		t.Run(ct.name, func(t *testing.T) {
			for _, tt := range urlTests {
				t.Run(tt.name, func(t *testing.T) {
					cfg := ct.cfg(tt.oidCCfg)
					tt.check.Check(t, validateURLs(cfg))
				})
			}
		})
	}
}

func TestLoadMock(t *testing.T) {
	want := &configv1.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    8080,
		LogLevel:      "debug",
		Threads:       1,
		Chains: []*configv1.FilterChain{
			{
				Name: "mock",
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Mock{
							Mock: &mockv1.MockConfig{
								Allow: true,
							},
						},
					},
				},
			},
		},
	}

	var cfg LocalConfigFile
	g := run.Group{Logger: telemetry.NoopLogger()}
	g.Register(&cfg)
	err := g.Run("", "--config-path", "testdata/mock.json")

	require.NoError(t, err)
	require.True(t, proto.Equal(want, &cfg.Config))
}

func TestLoadOIDC(t *testing.T) {
	want := &configv1.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    8080,
		LogLevel:      "debug",
		Threads:       1,
		Chains: []*configv1.FilterChain{
			{
				Name: "oidc",
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Oidc{
							Oidc: &oidcv1.OIDCConfig{
								AuthorizationUri: "http://fake",
								TokenUri:         "http://fake",
								CallbackUri:      "http://fake/callback",
								JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
									JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{
										JwksUri:            "http://fake/jwks",
										SkipVerifyPeerCert: structpb.NewStringValue("true"),
									},
								},
								ClientId:                "fake-client-id",
								ClientSecret:            "fake-client-secret",
								CookieNamePrefix:        "",
								IdToken:                 &oidcv1.TokenConfig{Preamble: "Bearer", Header: "authorization"},
								ProxyUri:                "http://fake",
								RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: "redis://localhost:6379/0"},
								Scopes:                  []string{scopeOIDC},
								Logout:                  &oidcv1.LogoutConfig{Path: "/logout", RedirectUri: "http://fake"},
								TrustedCaConfig:         &oidcv1.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: "fake-ca-pem"},
								SkipVerifyPeerCert:      structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range []string{"oidc", "oidc-override"} {
		t.Run(tc, func(t *testing.T) {
			var cfg LocalConfigFile
			g := run.Group{Logger: telemetry.NoopLogger()}
			g.Register(&cfg)
			err := g.Run("", "--config-path", fmt.Sprintf("testdata/%s.json", tc))

			require.NoError(t, err)
			require.True(t, proto.Equal(want, &cfg.Config))
		})
	}
}

func TestConfigToJSONString(t *testing.T) {
	tests := []struct {
		name   string
		config *configv1.Config
		want   string
	}{
		{"nil", nil, "{}"},
		{"empty", &configv1.Config{}, "{}"},
		{"simple", &configv1.Config{ListenPort: 8080}, `{"listenPort":8080}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConfigToJSONString(tt.config)
			require.JSONEq(t, tt.want, got)
		})
	}
}
