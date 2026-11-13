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

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLogMiddleware(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		canceled bool
		level    telemetry.Level
		count    int
	}{
		{"service-failure", errors.New("private-credential"), false, telemetry.LevelInfo, 1},
		{"caller-cancel", context.Canceled, true, telemetry.LevelInfo, 0},
		{"expected-denial", status.Error(codes.Unauthenticated, "private-credential"), false, telemetry.LevelInfo, 1},
		{"success-debug", nil, false, telemetry.LevelDebug, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs []string
			var levels []telemetry.Level
			log := function.NewLogger(func(level telemetry.Level, msg string, err error, values function.Values) {
				levels = append(levels, level)
				logs = append(logs, fmt.Sprint(msg, err, values))
			})
			log.SetLevel(test.level)
			ctx, cancel := context.WithCancel(telemetry.KeyValuesToContext(t.Context(), EnvoyXRequestID, "public-request"))
			defer cancel()
			if test.canceled {
				cancel()
			}
			middleware := LogMiddleware{log: log}
			response, err := middleware.UnaryServerInterceptor(ctx, map[string]string{"cookie": "private-credential"},
				&grpc.UnaryServerInfo{FullMethod: "/envoy.service.auth.v3.Authorization/Check"},
				func(context.Context, any) (any, error) { return "private-credential", test.err })
			require.Equal(t, "private-credential", response)
			require.Equal(t, test.err, err)
			require.Len(t, logs, test.count)
			if len(logs) > 0 {
				rendered := strings.Join(logs, "\n")
				require.NotContains(t, rendered, "private-credential")
				require.Contains(t, rendered, "public-request")
				require.Contains(t, rendered, "duration")
				if test.name == "service-failure" {
					require.Equal(t, telemetry.LevelError, levels[0])
				}
				if test.name == "expected-denial" {
					require.Equal(t, telemetry.LevelInfo, levels[0])
				}
			}
		})
	}
}

func TestLogMiddlewareAuthDenial(t *testing.T) {
	log := function.NewLogger(func(telemetry.Level, string, error, function.Values) {
		t.Error("an expected auth denial must not produce a failure log at INFO")
	})
	response := &envoy.CheckResponse{}
	_, err := (LogMiddleware{log: log}).UnaryServerInterceptor(t.Context(), &envoy.CheckRequest{},
		&grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) { return response, nil })
	require.NoError(t, err)
}
