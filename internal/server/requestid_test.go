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
	"testing"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
)

func TestPropagateRequestId(t *testing.T) {
	tests := []struct {
		name string
		req  interface{}
		want []interface{}
	}{
		{"not-envoy-request", struct{}{}, nil},
		{"no-x-request-id", &envoy.CheckRequest{}, nil},
		{"with-x-request-id", header("test"), []interface{}{EnvoyXRequestID, "test-request-id"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, _ = PropagateRequestID(ctx, tt.req, nil, func(ctx context.Context, _ interface{}) (interface{}, error) {
				kvs := telemetry.KeyValuesFromContext(ctx)
				require.Equal(t, tt.want, kvs)
				return nil, nil
			})
		})
	}
}
