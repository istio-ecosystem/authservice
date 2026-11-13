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

package authz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
	"google.golang.org/grpc/codes"

	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	inthttp "github.com/istio-ecosystem/authservice/internal/http"
	"github.com/istio-ecosystem/authservice/internal/oidc"
)

func TestTokenRequestsCancel(t *testing.T) {
	for _, operation := range []string{"token", "exchange", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			stopped := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				_, _ = io.Copy(io.Discard, req.Body)
				close(started)
				select {
				case <-req.Context().Done():
				case <-release:
				}
				close(stopped)
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			log := function.NewLogger(func(level telemetry.Level, _ string, _ error, _ function.Values) {
				if level == telemetry.LevelError {
					t.Error("caller cancellation logged as a service failure")
				}
			})
			handler := &oidcHandler{
				config:     &oidcv1.OIDCConfig{TokenUri: server.URL, TokenExchange: &oidcv1.OIDCConfig_TokenExchange{TokenExchangeUri: server.URL}},
				httpClient: server.Client(),
				sessions:   &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, 0, 0)},
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch operation {
				case "exchange":
					_, _ = handler.exchangeAccessToken(ctx, log, "private-access-token")
				case "refresh":
					_ = handler.refreshToken(ctx, log, &oidc.TokenResponse{}, "private-refresh-token", "private-session")
				default:
					_, _ = performIDPRequest(ctx, log, server.Client(), server.URL, url.Values{"code": {"private-code"}}, nil)
				}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("token request did not start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("token request ignored cancellation")
			}
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("IdP continued after cancellation")
			}
		})
	}
}

func TestTokenRequestFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		level  telemetry.Level
	}{
		{"denial", http.StatusBadRequest, "private-response", telemetry.LevelInfo},
		{"service-error", http.StatusServiceUnavailable, "private-response", telemetry.LevelError},
		{"invalid-json", http.StatusOK, "private-response", telemetry.LevelError},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				require.Equal(t, "Bearer private-header", req.Header.Get("Authorization"))
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.Contains(t, string(body), "private-form")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			var logs []string
			var levels []telemetry.Level
			log := function.NewLogger(func(level telemetry.Level, msg string, err error, values function.Values) {
				levels = append(levels, level)
				logs = append(logs, fmt.Sprint(msg, err, values))
			})
			ctx := telemetry.KeyValuesToContext(t.Context(), "x-request-id", "public-request")
			result, code := performIDPRequest(ctx, log, server.Client(), server.URL+"/?code=private-query",
				url.Values{"client_secret": {"private-form"}}, http.Header{"Authorization": {"Bearer private-header"}})
			require.Nil(t, result)
			require.NotEqual(t, codes.OK, code)
			require.Equal(t, []telemetry.Level{test.level}, levels)
			rendered := strings.Join(logs, "\n")
			require.NotContains(t, rendered, "private-")
			require.Contains(t, rendered, "public-request")
			require.Contains(t, rendered, "dependency")
			require.Contains(t, rendered, "duration")
		})
	}
}

func TestTokenRequestTimeoutVisibleOnce(t *testing.T) {
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		<-req.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	var errors int
	log := function.NewLogger(func(level telemetry.Level, _ string, _ error, _ function.Values) {
		if level == telemetry.LevelError {
			errors++
		}
	})
	client, err := inthttp.NewHTTPClient(&oidcv1.OIDCConfig{}, inthttp.NewTLSConfigPool(nil), log)
	require.NoError(t, err)
	client.Timeout = 100 * time.Millisecond
	_, code := performIDPRequest(t.Context(), log, client, server.URL, nil, nil)
	require.Equal(t, codes.Internal, code)
	require.Equal(t, 1, errors)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("IdP continued after timeout")
	}
}

func TestCallbackLogRedaction(t *testing.T) {
	for _, query := range []string{"?state=private-state", "?state=private-state&code=private-code", "?state=private-state&code=private-code;bad"} {
		t.Run(query, func(t *testing.T) {
			var logs []string
			log := function.NewLogger(func(_ telemetry.Level, msg string, err error, values function.Values) {
				logs = append(logs, fmt.Sprint(msg, err, values))
			})
			log.SetLevel(telemetry.LevelDebug)
			store := oidc.NewMemoryStore(&oidc.Clock{}, 0, 0)
			require.NoError(t, store.SetAuthorizationState(t.Context(), sessionID, &oidc.AuthorizationState{State: "private-stored-state"}))
			handler := &oidcHandler{sessions: &mockSessionStoreFactory{store: store}}
			handler.retrieveTokens(t.Context(), log, modifyCallbackRequestPath("/callback"+query), &envoy.CheckResponse{}, sessionID)
			require.NotEmpty(t, logs)
			require.NotContains(t, strings.Join(logs, "\n"), "private-")
		})
	}
}
