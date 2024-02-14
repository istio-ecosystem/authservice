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
	"github.com/tetratelabs/telemetry"
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
			e := NewExtAuthZFilter(&configv1.Config{AllowUnmatchedRequests: tt.allow}, nil, nil)
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
			e := NewExtAuthZFilter(cfg, nil, nil)

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

	e := NewExtAuthZFilter(cfg, nil, nil)

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
	e := NewExtAuthZFilter(&configv1.Config{}, nil, nil)
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

func TestStringMatch(t *testing.T) {
	tests := []struct {
		name  string
		match *configv1.StringMatch
		path  string
		want  bool
	}{
		{"no-match", nil, "", false},
		{"equality-match", stringExact("test"), "test", true},
		{"equality-no-match", stringExact("test"), "no-match", false},
		{"prefix-match", stringPrefix("test"), "test-123", true},
		{"prefix-no-match", stringPrefix("test"), "no-match", false},
		{"suffix-match", stringSuffix("test"), "123-test", true},
		{"suffix-no-match", stringSuffix("test"), "no-match", false},
		{"regex-match", stringRegex(".*st"), "test", true},
		{"regex-no-match", stringRegex(".*st"), "no-match", false},
		{"regex-invalid", stringRegex("["), "no-match", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, stringMatch(telemetry.NoopLogger(), tt.match, tt.path))
		})
	}
}

func TestMatchTriggerRule(t *testing.T) {
	tests := []struct {
		name string
		rule *configv1.TriggerRule
		path string
		want bool
	}{
		{"no-rule", nil, "/path", false},
		{"no-path", &configv1.TriggerRule{}, "", true},
		{"empty-rule", &configv1.TriggerRule{}, "/path", true},
		{"excluded-path-match", &configv1.TriggerRule{ExcludedPaths: []*configv1.StringMatch{stringExact("/path")}}, "/path", false},
		{"excluded-path-no-match", &configv1.TriggerRule{ExcludedPaths: []*configv1.StringMatch{stringExact("/path")}}, "/no-match", true},
		{"included-path-match", &configv1.TriggerRule{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}}, "/path", true},
		{"included-path-no-match", &configv1.TriggerRule{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}}, "/no-match", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, matchTriggerRule(telemetry.NoopLogger(), tt.rule, tt.path))
		})
	}

}

func TestMustTriggerCheck(t *testing.T) {
	test := []struct {
		name  string
		rules []*configv1.TriggerRule
		path  string
		want  bool
	}{
		{"no-rules", nil, "/path", true},
		{"no-path", nil, "", true},
		{"empty-rules", []*configv1.TriggerRule{}, "/path", true},
		{"inclusions-match", []*configv1.TriggerRule{{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}}}, "/path", true},
		{"inclusions-no-match", []*configv1.TriggerRule{{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}}}, "/no-match", false},
		{"exclusions-match", []*configv1.TriggerRule{{ExcludedPaths: []*configv1.StringMatch{stringExact("/path")}}}, "/path", false},
		{"exclusions-no-match", []*configv1.TriggerRule{{ExcludedPaths: []*configv1.StringMatch{stringExact("/path")}}}, "/no-match", true},
		{"multiple-rules-no-match", []*configv1.TriggerRule{
			{ExcludedPaths: []*configv1.StringMatch{stringExact("/ex-path")}},
			{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}},
		}, "/ex-path", false},
		{"multiple-rules-match", []*configv1.TriggerRule{
			{ExcludedPaths: []*configv1.StringMatch{stringExact("/no-path")}},
			{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}},
		}, "/path", true},
		{"inverse-order-multiple-rules-no-match", []*configv1.TriggerRule{
			{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}},
			{ExcludedPaths: []*configv1.StringMatch{stringExact("/ex-path")}},
		}, "/ex-path", false},
		{"inverse-order-multiple-rules-match", []*configv1.TriggerRule{
			{IncludedPaths: []*configv1.StringMatch{stringExact("/path")}},
			{ExcludedPaths: []*configv1.StringMatch{stringExact("/no-path")}},
		}, "/path", true},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			req := &envoy.CheckRequest{
				Attributes: &envoy.AttributeContext{
					Request: &envoy.AttributeContext_Request{
						Http: &envoy.AttributeContext_HttpRequest{
							Path: tt.path,
						},
					},
				},
			}
			require.Equal(t, tt.want, mustTriggerCheck(telemetry.NoopLogger(), tt.rules, req))
		})
	}
}

func TestCheckTriggerRules(t *testing.T) {
	tests := []struct {
		name   string
		config *configv1.Config
		path   string
		want   codes.Code
	}{
		{
			"no-rules-triggers-check",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{mock(false)}}},
			},
			"/path", codes.PermissionDenied,
		},
		{
			"rules-inclusions-matching-triggers-check",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{mock(false)}}},
				TriggerRules: []*configv1.TriggerRule{
					{
						IncludedPaths: []*configv1.StringMatch{stringExact("/path")},
					},
				},
			},
			"/path", codes.PermissionDenied},
		{
			"rules-inclusions-no-match-does-not-trigger-check",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{mock(false)}}},
				TriggerRules: []*configv1.TriggerRule{
					{
						IncludedPaths: []*configv1.StringMatch{stringExact("/path")},
					},
				},
			},
			"/no-path", codes.OK, // it does not reach mock(allow=false), so it returns OK
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewExtAuthZFilter(tt.config, nil, nil)
			req := &envoy.CheckRequest{
				Attributes: &envoy.AttributeContext{
					Request: &envoy.AttributeContext_Request{
						Http: &envoy.AttributeContext_HttpRequest{
							Path: tt.path,
						},
					},
				},
			}
			got, err := e.Check(context.Background(), req)
			require.NoError(t, err)
			require.Equal(t, int32(tt.want), got.Status.Code)
		})
	}
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

func stringExact(s string) *configv1.StringMatch {
	return &configv1.StringMatch{
		MatchType: &configv1.StringMatch_Exact{
			Exact: s,
		},
	}
}

func stringPrefix(s string) *configv1.StringMatch {
	return &configv1.StringMatch{
		MatchType: &configv1.StringMatch_Prefix{
			Prefix: s,
		},
	}
}

func stringSuffix(s string) *configv1.StringMatch {
	return &configv1.StringMatch{
		MatchType: &configv1.StringMatch_Suffix{
			Suffix: s,
		},
	}
}

func stringRegex(s string) *configv1.StringMatch {
	return &configv1.StringMatch{
		MatchType: &configv1.StringMatch_Regex{
			Regex: s,
		},
	}
}
