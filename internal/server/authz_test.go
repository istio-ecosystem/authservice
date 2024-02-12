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
	"testing"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
)

func TestUnmatchedRequests(t *testing.T) {
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
			e := NewExtAuthZFilter(&configv1.Config{AllowUnmatchedRequests: tt.allow})
			got, err := e.Check(context.Background(), &envoy.CheckRequest{})
			require.NoError(t, err)
			require.Equal(t, int32(tt.want), got.Status.Code)
		})
	}
}

func TestFiltersMatch(t *testing.T) {
	tests := []struct {
		name    string
		filters []*configv1.Filter
		want    codes.Code
	}{
		{"no-filters", nil, codes.OK},
		{"all-filters-match", []*configv1.Filter{mock(true), mock(true)}, codes.OK},
		{"one-filter-deny", []*configv1.Filter{mock(true), mock(false)}, codes.PermissionDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &configv1.Config{Chains: []*configv1.FilterChain{{Filters: tt.filters}}}
			e := NewExtAuthZFilter(cfg)

			got, err := e.Check(context.Background(), &envoy.CheckRequest{})
			require.NoError(t, err)
			require.Equal(t, int32(tt.want), got.Status.Code)
		})
	}
}

func TestUseFirstMatchingChain(t *testing.T) {
	cfg := &configv1.Config{
		Chains: []*configv1.FilterChain{
			{
				// Chain to be ignored
				Match:   eq("no-match"),
				Filters: []*configv1.Filter{mock(false)},
			},
			{
				// Chain to be used
				Match:   eq("match"),
				Filters: []*configv1.Filter{mock(true)},
			},
			{
				// Always matches but should not be used as the previous
				// chain already matched
				Filters: []*configv1.Filter{mock(false)},
			},
		},
	}

	e := NewExtAuthZFilter(cfg)

	got, err := e.Check(context.Background(), header("match"))
	require.NoError(t, err)
	require.Equal(t, int32(codes.OK), got.Status.Code)
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name  string
		match *configv1.Match
		req   *envoy.CheckRequest
		want  bool
	}{
		{"no-headers", eq("test"), &envoy.CheckRequest{}, false},
		{"no-match-condition", nil, &envoy.CheckRequest{}, true},
		{"equality-match", eq("test"), header("test"), true},
		{"equality-no-match", eq("test"), header("no-match"), false},
		{"prefix-match", prefix("test"), header("test-123"), true},
		{"prefix-no-match", prefix("test"), header("no-match"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, matches(tt.match, tt.req))
		})
	}
}

func TestGrpcNoChainsMatched(t *testing.T) {
	e := NewExtAuthZFilter(&configv1.Config{})
	s := NewTestServer(e.Register)
	go func() { require.NoError(t, s.Start()) }()
	t.Cleanup(s.Stop)

	conn, err := s.GRPCConn()
	require.NoError(t, err)
	client := envoy.NewAuthorizationClient(conn)

	ok, err := client.Check(context.Background(), &envoy.CheckRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(codes.PermissionDenied), ok.Status.Code)
}

func mock(allow bool) *configv1.Filter {
	return &configv1.Filter{
		Type: &configv1.Filter_Mock{
			Mock: &mockv1.MockConfig{
				Allow: allow,
			},
		},
	}
}

func eq(value string) *configv1.Match {
	return &configv1.Match{
		Header: "X-Test-Headers",
		Criteria: &configv1.Match_Equality{
			Equality: value,
		},
	}
}

func prefix(value string) *configv1.Match {
	return &configv1.Match{
		Header: "X-Test-Headers",
		Criteria: &configv1.Match_Prefix{
			Prefix: value,
		},
	}
}

func header(value string) *envoy.CheckRequest {
	return &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-test-headers": value,
					},
				},
			},
		},
	}
}
