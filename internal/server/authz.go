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
	"fmt"
	"regexp"
	"strings"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	"github.com/istio-ecosystem/authservice/internal"
	"github.com/istio-ecosystem/authservice/internal/authz"
	"github.com/istio-ecosystem/authservice/internal/oidc"
)

// EnvoyXRequestID is the header name for the request id
const EnvoyXRequestID = "x-request-id"

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
	log      telemetry.Logger
	cfg      *configv1.Config
	tlsPool  internal.TLSConfigPool
	jwks     oidc.JWKSProvider
	sessions oidc.SessionStoreFactory
}

// NewExtAuthZFilter creates a new ExtAuthZFilter.
func NewExtAuthZFilter(cfg *configv1.Config, tlsPool internal.TLSConfigPool, jwks oidc.JWKSProvider, sessions oidc.SessionStoreFactory) *ExtAuthZFilter {
	return &ExtAuthZFilter{
		log:      internal.Logger(internal.Authz),
		cfg:      cfg,
		tlsPool:  tlsPool,
		jwks:     jwks,
		sessions: sessions,
	}
}

// Register the ExtAuthZFilter with the given gRPC server.
func (e *ExtAuthZFilter) Register(server *grpc.Server) {
	envoy.RegisterAuthorizationServer(server, e)
}

// Check is the implementation of the Envoy AuthorizationServer interface.
func (e *ExtAuthZFilter) Check(ctx context.Context, req *envoy.CheckRequest) (response *envoy.CheckResponse, err error) {
	log := e.log.Context(ctx)

	// If there are no trigger rules, allow the request with no check executions.
	// TriggerRules are used to determine which request should be checked by the filter and which don't.
	if !mustTriggerCheck(log, e.cfg.TriggerRules, req) {
		log.Debug(fmt.Sprintf("no matching trigger rule, so allowing request to proceed without any authservice functionality %s://%s%s",
			req.GetAttributes().GetRequest().GetHttp().GetScheme(),
			req.GetAttributes().GetRequest().GetHttp().GetHost(),
			req.GetAttributes().GetRequest().GetHttp().GetPath()))
		return allow, nil
	}

	for _, c := range e.cfg.Chains {
		match := matches(c.Match, req)

		log = log.With("chain", c.Name)
		log.Debug("evaluate filter chain", "match", match)

		if !match {
			continue
		}

		if len(c.Filters) == 0 {
			log.Debug("no filters in chain, allowing request")
			return allow, nil
		}

		resp := &envoy.CheckResponse{}

		// Inside a filter chain, all filters must match
		for i, f := range c.Filters {
			log.Debug("applying filter", "type", fmt.Sprintf("%T", f.Type), "index", i)

			// Note that the  Default_Oidc or the Oidc_Override types can't reach this point. The configurations have
			// already been merged when loaded from the configuration file and populated accordingly in the Oidc settings.
			var h authz.Handler
			switch ft := f.Type.(type) {
			case *configv1.Filter_Mock:
				h = authz.NewMockHandler(ft.Mock)
			case *configv1.Filter_Oidc:
				if h, err = authz.NewOIDCHandler(ft.Oidc, e.tlsPool, e.jwks, e.sessions, oidc.Clock{}, oidc.NewRandomGenerator()); err != nil {
					return nil, err
				}
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

		// At this point all filters allowed the request, so return the response with any additional headers the filters may have added.
		return resp, nil
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

// mustTriggerCheck returns true if the request must be checked by the authservice filters.
// If any of the TriggerRules match the request path, then the request must be checked.
func mustTriggerCheck(log telemetry.Logger, rules []*configv1.TriggerRule, req *envoy.CheckRequest) bool {
	// If there are no trigger rules, authservice checks should be triggered for all requests.
	// If the request path is empty, (unlikely, but the piece used to match the rules) then trigger the checks.
	if len(rules) == 0 || len(req.GetAttributes().GetRequest().GetHttp().GetPath()) == 0 {
		return true
	}

	for i, rule := range rules {
		l := log.With("rule-index", i)
		if matchTriggerRule(l, rule, req.GetAttributes().GetRequest().GetHttp().GetPath()) {
			return true
		}
	}
	return false
}

func matchTriggerRule(log telemetry.Logger, rule *configv1.TriggerRule, path string) bool {
	if rule == nil {
		return false
	}

	// if any of the excluded paths match, this rule doesn't match
	for i, match := range rule.GetExcludedPaths() {
		l := log.With("excluded-match-index", i)
		if stringMatch(l, match, path) {
			return false
		}
	}

	// if no excluded paths match, and there are no included paths, this rule matches
	if len(rule.GetIncludedPaths()) == 0 {
		return true
	}

	for i, match := range rule.GetIncludedPaths() {
		// if any of the included paths match, this rule matches
		l := log.With("included-match-index", i)
		if stringMatch(l, match, path) {
			return true
		}
	}

	// if none of the included paths match, this rule doesn't match
	return false
}

func stringMatch(log telemetry.Logger, match *configv1.StringMatch, path string) bool {
	switch m := match.GetMatchType().(type) {
	case *configv1.StringMatch_Exact:
		return m.Exact == path
	case *configv1.StringMatch_Prefix:
		return strings.HasPrefix(path, m.Prefix)
	case *configv1.StringMatch_Suffix:
		return strings.HasSuffix(path, m.Suffix)
	case *configv1.StringMatch_Regex:
		b, err := regexp.MatchString(m.Regex, path)
		if err != nil {
			log.Error("error matching regex", err, "regex", m.Regex, "match", false)
		}
		return b
	default:
		return false
	}
}
