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

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/oidc"
)

var _ Handler = (*oidcHandler)(nil)

// oidc handler is an implementation of the Handler interface that implements
// the OpenID connect protocol.
type oidcHandler struct {
	log      telemetry.Logger
	config   *oidcv1.OIDCConfig
	jwks     oidc.JWKSProvider
	sessions *oidc.SessionStoreFactory
}

// NewOIDCHandler creates a new OIDC implementation of the Handler interface.
func NewOIDCHandler(cfg *oidcv1.OIDCConfig, jwks oidc.JWKSProvider, sessions *oidc.SessionStoreFactory) (Handler, error) {
	return &oidcHandler{
		log:      internal.Logger(internal.Authz).With("type", "oidc"),
		config:   cfg,
		jwks:     jwks,
		sessions: sessions,
	}, nil
}

// Process a CheckRequest and populate a CheckResponse according to the mockHandler configuration.
func (o *oidcHandler) Process(_ context.Context, _ *envoy.CheckRequest, _ *envoy.CheckResponse) error {
	return nil
}
