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

package server

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/run/pkg/test"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc/test/bufconn"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
)

func TestHealthServer(t *testing.T) {

	var (
		g   = run.Group{Logger: telemetry.NoopLogger()}
		irq = test.NewIRQService(func() {})
		l   = bufconn.Listen(1024)
		hs  = NewHealthServer(nil)
	)

	hs.(*healthServer).l = l
	g.Register(hs, irq)

	go func() {
		require.NoError(t, g.Run())
	}()
	t.Cleanup(func() {
		require.NoError(t, irq.Close())
	})

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return l.Dial()
			},
		},
	}

	tests := []struct {
		method string
		url    string
		want   int
	}{
		{http.MethodGet, "http://bufconn" + HealthzPath, http.StatusOK},
		{http.MethodGet, "http://bufconn" + "/other", http.StatusBadRequest},
		{http.MethodPost, "http://bufconn" + HealthzPath, http.StatusBadRequest},
		{http.MethodPost, "http://bufconn" + "/other", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			require.NoError(t, err)
			resp, err := client.Do(req)
			require.NoError(t, err)
			require.Equal(t, tt.want, resp.StatusCode)
		})
	}
}

func TestHealthConfig(t *testing.T) {

	tests := []struct {
		name                  string
		config                *configv1.Config
		wantAddress, wantPath string
	}{
		{"default", nil, ":10004", "/healthz"},
		{"address", &configv1.Config{HealthListenAddress: "test"}, "test:10004", "/healthz"},
		{"port", &configv1.Config{HealthListenPort: 8000}, ":8000", "/healthz"},
		{"address and port", &configv1.Config{HealthListenAddress: "test", HealthListenPort: 8000}, "test:8000", "/healthz"},
		{"path", &configv1.Config{HealthListenPath: "/test"}, ":10004", "/test"},
		{"all", &configv1.Config{HealthListenAddress: "test", HealthListenPort: 8000, HealthListenPath: "/test"}, "test:8000", "/test"},
		{"address defaults to listen address", &configv1.Config{ListenAddress: "test"}, "test:10004", "/healthz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHealthServer(tt.config)
			require.Equal(t, tt.wantAddress, hs.(*healthServer).getAddressAndPort())
			require.Equal(t, tt.wantPath, hs.(*healthServer).getPath())
		})
	}
}
