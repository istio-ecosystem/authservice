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

package authz

import (
	"context"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	mockv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/mock"
	"github.com/istio-ecosystem/authservice/internal"
)

var _ Handler = (*mockHandler)(nil)

// mockHandler handler is an implementation of the Handler interface.
type mockHandler struct {
	log    telemetry.Logger
	config *mockv1.MockConfig
}

// NewMockHandler creates a new Mock implementation of the Handler interface.
func NewMockHandler(cfg *mockv1.MockConfig) Handler {
	return &mockHandler{
		log:    internal.Logger(internal.Authz).With("type", "mockHandler"),
		config: cfg,
	}
}

// Process a CheckRequest and populate a CheckResponse according to the mockHandler configuration.
func (m *mockHandler) Process(ctx context.Context, _ *envoy.CheckRequest, resp *envoy.CheckResponse) error {
	log := m.log.Context(ctx)

	code := codes.PermissionDenied
	if m.config.GetAllow() {
		code = codes.OK
	}

	log.Debug("process", "status", code.String())
	resp.Status = &status.Status{Code: int32(code)}
	return nil
}
