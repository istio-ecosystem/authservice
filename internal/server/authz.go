// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

package server

import (
	"context"
	"fmt"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	log := e.log.Context(ctx)

	for _, c := range e.cfg.Chains {
		if matches(c.Match, req) {
			log = log.With("chain", c.Name)
			log.Debug("matched filter chain")

			// Inside a filter chain, all filters must match
			for i, f := range c.Filters {
				var (
					ok  bool
					err error
				)

				switch ft := f.Type.(type) {
				case *configv1.Filter_Mock:
					e.log.Debug("applying filter", "type", "mock", "index", i)
					ok, err = e.checkMock(context.Background(), req, ft.Mock)
				case *configv1.Filter_Oidc:
					e.log.Debug("applying filter", "type", "oidc", "index", i)
					ok, err = e.checkOidc(context.Background(), req, ft.Oidc)
				case *configv1.Filter_OidcOverride:
					e.log.Debug("applying filter", "type", "oidc_override", "index", i)
					ok, err = e.checkOidc(context.Background(), req, ft.OidcOverride)
				}

				// If there is an error just return it without a verdict, and let the Envoy ext_authz
				// failure policy decide if the request can continue or not.
				if err != nil {
					return nil, err
				}

				if !ok {
					return deny(codes.PermissionDenied, fmt.Sprintf("%s[%d] filter denied the request", c.Name, i)), nil
				}
			}

			// Use the first filter chain that matches
			return allow, nil
		}
	}

	if e.cfg.AllowUnmatchedRequests {
		return allow, nil
	}

	return deny(codes.PermissionDenied, "no chains matched"), nil
}

// checkMock checks the given request against the given mock configuration.
func (e *ExtAuthZFilter) checkMock(_ context.Context, _ *envoy.CheckRequest, mock *mockv1.MockConfig) (bool, error) {
	return mock.Allow, nil
}

// checkOidc checks the given request against the given oidc configuration.
func (e *ExtAuthZFilter) checkOidc(_ context.Context, _ *envoy.CheckRequest, _ *oidcv1.OIDCConfig) (bool, error) {
	// TODO
	return false, nil
}

// matches returns true if the given request matches the given match configuration
func matches(_ *configv1.Match, _ *envoy.CheckRequest) bool {
	// TODO
	return true
}
