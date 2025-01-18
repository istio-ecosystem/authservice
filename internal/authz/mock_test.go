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
	"testing"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	mockv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/mock"
)

func TestProcessMock(t *testing.T) {
	tests := []struct {
		name  string
		allow bool
		want  codes.Code
	}{
		{"allow", true, codes.OK},
		{"deny", false, codes.PermissionDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				m    = NewMockHandler(&mockv1.MockConfig{Allow: tt.allow})
				req  = &envoy.CheckRequest{}
				resp = &envoy.CheckResponse{}
			)
			err := m.Process(context.Background(), req, resp)
			require.NoError(t, err)
			require.Equal(t, int32(tt.want), resp.Status.Code)
		})
	}
}
