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
	"fmt"
	"strings"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/authz"
	"github.com/tetrateio/authservice-go/internal/authz/oidc"
)

var (
	// allow a request
	allow = &envoy.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.OK),
			Message: "",
		},
	}

	// deny a request with the given code and message
	deny = func(code codes.Code, message string) *envoy.CheckResponse {
		return &envoy.CheckResponse{
			Status: &status.Status{
				Code:    int32(code),
				Message: message,
			},
		}
	}
)

// ExtAuthZFilter is an implementation of the Envoy AuthZ filter.
type ExtAuthZFilter struct {
	log telemetry.Logger
	cfg *configv1.Config
}

// NewExtAuthZFilter creates a new ExtAuthZFilter.
func NewExtAuthZFilter(cfg *configv1.Config) *ExtAuthZFilter {
	return &ExtAuthZFilter{
		log: internal.Logger(internal.Authz),
		cfg: cfg,
	}
}

// Register the ExtAuthZFilter with the given gRPC server.
func (e *ExtAuthZFilter) Register(server *grpc.Server) {
	envoy.RegisterAuthorizationServer(server, e)
}

// Check is the implementation of the Envoy AuthorizationServer interface.
func (e *ExtAuthZFilter) Check(ctx context.Context, req *envoy.CheckRequest) (response *envoy.CheckResponse, err error) {
	for _, c := range e.cfg.Chains {
		match := matches(c.Match, req)

		log := e.log.Context(ctx).With("chain", c.Name)
		log.Debug("evaluate filter chain", "match", match)

		if !match {
			continue
		}

		// Inside a filter chain, all filters must match
		for i, f := range c.Filters {
			var (
				h    authz.Authz
				resp = &envoy.CheckResponse{}
			)

			log.Debug("applying filter", "type", fmt.Sprintf("%T", f.Type), "index", i)

			switch ft := f.Type.(type) {
			case *configv1.Filter_Mock:
				h = authz.NewMockHandler(ft.Mock)
			case *configv1.Filter_Oidc:
				// TODO(nacx): Read the redis store config to configure the redi store
				store := oidc.NewMemoryStore(
					oidc.Clock{},
					time.Duration(ft.Oidc.AbsoluteSessionTimeout),
					time.Duration(ft.Oidc.IdleSessionTimeout),
				)
				// TODO(nacx): Check if the Oidc setting is enough or we have to pull the default Oidc settings
				h = authz.NewOIDCHandler(ft.Oidc, store)
			case *configv1.Filter_OidcOverride:
				// TODO(nacx): Read the redis store config to configure the redi store
				store := oidc.NewMemoryStore(
					oidc.Clock{},
					time.Duration(ft.OidcOverride.AbsoluteSessionTimeout),
					time.Duration(ft.OidcOverride.IdleSessionTimeout),
				)
				// TODO(nacx): Check if the OidcOverride is enough or we have to pull the default Oidc settings
				h = authz.NewOIDCHandler(ft.OidcOverride, store)
			}

			if err = h.Process(ctx, req, resp); err != nil {
				// If there is an error just return it without a verdict, and let the Envoy ext_authz
				// failure policy decide if the request can continue or not.
				return nil, err
			}

			allow := codes.Code(resp.Status.Code) == codes.OK
			log.Debug("filter result", "index", i, "allow", allow, "error", err)
			if !allow {
				return resp, nil
			}
		}

		// Return OK if the chain matched and all filters allowed the request
		return allow, nil
	}

	if e.cfg.AllowUnmatchedRequests {
		return allow, nil
	}

	return deny(codes.PermissionDenied, "no chains matched"), nil
}

// matches returns true if the given request matches the given match configuration
func matches(m *configv1.Match, req *envoy.CheckRequest) bool {
	if m == nil {
		return true
	}
	headerValue := req.GetAttributes().GetRequest().GetHttp().GetHeaders()[strings.ToLower(m.Header)]
	if m.GetEquality() != "" {
		return headerValue == m.GetEquality()
	}
	return strings.HasPrefix(headerValue, m.GetPrefix())
}
