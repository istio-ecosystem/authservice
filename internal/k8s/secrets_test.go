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

package k8s

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

func TestLoadOIDCClientSecret(t *testing.T) {
	validSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret",
		},
		Data: map[string][]byte{
			clientSecretKey: []byte("fake-client-secret"),
		},
	}
	invalidSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "invalid-secret",
		},
		Data: map[string][]byte{
			clientSecretKey + "-invalid": []byte("fake-client-secret"),
		},
	}

	kubeClient := fake.NewClientBuilder().WithObjects(validSecret, invalidSecret).Build()

	tests := []struct {
		name       string
		configFile string
		want       *configv1.Config
		err        error
	}{
		{
			name:       "valid-secret",
			configFile: "oidc-with-valid-secret-ref",
			want: &configv1.Config{
				ListenAddress: "0.0.0.0",
				ListenPort:    8080,
				LogLevel:      "debug",
				Threads:       1,
				Chains: []*configv1.FilterChain{
					{
						Name: "oidc",
						Filters: []*configv1.Filter{
							{
								Type: &configv1.Filter_Mock{
									Mock: &mockv1.MockConfig{
										Allow: true,
									},
								},
							},
							{
								Type: &configv1.Filter_Oidc{
									Oidc: &oidcv1.OIDCConfig{
										AuthorizationUri:        "http://fake",
										TokenUri:                "http://fake",
										CallbackUri:             "http://fake/callback",
										JwksConfig:              &oidcv1.OIDCConfig_Jwks{Jwks: "fake-jwks"},
										ClientId:                "fake-client-id",
										ClientSecretConfig:      &oidcv1.OIDCConfig_ClientSecret{ClientSecret: "fake-client-secret"},
										CookieNamePrefix:        "",
										IdToken:                 &oidcv1.TokenConfig{Preamble: "Bearer", Header: "authorization"},
										ProxyUri:                "http://fake",
										RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: "redis://localhost:6379/0"},
										Scopes:                  []string{internal.ScopeOIDC},
										Logout:                  &oidcv1.LogoutConfig{Path: "/logout", RedirectUri: "http://fake"},
									},
								},
							},
						},
					},
				},
			},
			err: nil,
		},
		{
			name:       "invalid-secret",
			configFile: "oidc-with-invalid-secret-ref",
			err:        ErrNoSecretData,
		},
		{
			name:       "not-found-secret",
			configFile: "oidc-with-non-existing-secret-ref",
			err:        ErrGetSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg internal.LocalConfigFile
			sl := NewSecretLoader(&cfg.Config)
			sl.k8sClient = kubeClient
			g := run.Group{Logger: telemetry.NoopLogger()}
			g.Register(&cfg, sl)
			err := g.Run("", "--config-path", fmt.Sprintf("testdata/%s.json", tt.configFile))

			require.ErrorIs(t, err, tt.err)
			if tt.err == nil {
				require.True(t, proto.Equal(tt.want, &cfg.Config))
			}
		})
	}
}

func TestLoadWithInvalidKubeConfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "non-existing-file")

	var cfg internal.LocalConfigFile
	sl := NewSecretLoader(&cfg.Config)

	g := run.Group{Logger: telemetry.NoopLogger()}
	g.Register(&cfg, sl)
	err := g.Run("", "--config-path", "testdata/oidc-with-valid-secret-ref.json")

	require.ErrorIs(t, err, ErrLoadingConfig)
}
