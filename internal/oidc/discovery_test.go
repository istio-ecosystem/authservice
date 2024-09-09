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

package oidc

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"
)

var (
	invalidWellKnownJSON = `{]]}`
	validWellKnownJSON   = `
{
	"issuer": "http://example.com",
	"authorization_endpoint": "http://example.com/authorize",
	"token_endpoint": "http://example.com/token",
	"jwks_uri": "http://example.com/jwks"
}`

	validWellKnown = WellKnownConfig{
		Issuer:                "http://example.com",
		AuthorizationEndpoint: "http://example.com/authorize",
		TokenEndpoint:         "http://example.com/token",
		JWKSURL:               "http://example.com/jwks",
	}
)

func TestWellKnownConfig(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		cfg        string
		wantError  bool
		wantConfig WellKnownConfig
	}{
		{"ok", "http://example.com/.well-known/openid-configuration", validWellKnownJSON, false, validWellKnown},
		{"not-found", "http://example.com/not-found", validWellKnownJSON, true, WellKnownConfig{}},
		{"invalid-url", "invalid", validWellKnownJSON, true, WellKnownConfig{}},
		{"invalid-json", "http://example2.com/.well-known/openid-configuration", invalidWellKnownJSON, true, WellKnownConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer()
			s.Start()
			t.Cleanup(s.Stop)
			s.wellKnownConfig = tt.cfg

			got, err := GetWellKnownConfig(s.newHTTPClient(), tt.url)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantConfig, got)
		})
	}
}

func TestWellKnownConfigCache(t *testing.T) {
	s := newServer()
	s.wellKnownConfig = validWellKnownJSON
	s.Start()
	c := s.newHTTPClient()

	got, err := GetWellKnownConfig(c, "http://example.com/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, validWellKnown, got)

	// Stop the server and run the well-known request again.
	// It should succeed and return the cached value.
	s.Stop()

	got, err = GetWellKnownConfig(c, "http://example.com/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, validWellKnown, got)
}

type idpServer struct {
	server          *http.Server
	listener        *bufconn.Listener
	wellKnownConfig string
}

func newServer() *idpServer {
	s := &http.Server{}
	idpServer := &idpServer{server: s, listener: bufconn.Listen(1024)}

	handler := http.NewServeMux()
	handler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if idpServer.wellKnownConfig != "" {
			_, _ = w.Write([]byte(idpServer.wellKnownConfig))
		}
	})
	s.Handler = handler
	return idpServer
}

// Start starts the server in a goroutine.
func (s *idpServer) Start() {
	go func() { _ = s.server.Serve(s.listener) }()
}

// Stop stops the server.
func (s *idpServer) Stop() {
	_ = s.listener.Close()
}

// newHTTPClient returns a new http.Client that can be used to make requests to the server via the bufconn.Listener.
func (s *idpServer) newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return s.listener.DialContext(ctx)
			},
		},
	}
}
