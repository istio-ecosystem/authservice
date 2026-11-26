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
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
	"google.golang.org/grpc/codes"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	mockv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/mock"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	inthttp "github.com/istio-ecosystem/authservice/internal/http"
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
			e := NewExtAuthZFilter(&configv1.Config{AllowUnmatchedRequests: tt.allow}, nil, nil, nil)
			got, err := e.Check(t.Context(), &envoy.CheckRequest{})
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
			e := NewExtAuthZFilter(cfg, nil, nil, nil)

			got, err := e.Check(t.Context(), &envoy.CheckRequest{})
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

	e := NewExtAuthZFilter(cfg, nil, nil, nil)

	got, err := e.Check(t.Context(), header("match"))
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
	e := NewExtAuthZFilter(&configv1.Config{}, nil, nil, nil)
	s := NewTestServer(e.Register)
	go func() { require.NoError(t, s.Start()) }()
	t.Cleanup(s.Stop)

	conn, err := s.GRPCConn()
	require.NoError(t, err)
	client := envoy.NewAuthorizationClient(conn)

	ok, err := client.Check(t.Context(), header("test"))
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
			require.Equal(t, tt.want, matchForms(telemetry.NoopLogger(), tt.match, []string{tt.path}, false))
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
			require.Equal(t, tt.want, matchTriggerRule(telemetry.NoopLogger(), tt.rule, []string{tt.path}))
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

		// Rules are matched against the path both with and without its query string and fragment,
		// resolving towards authentication.
		{"included-exact-query", includeRule(stringExact("/admin")), "/admin?x=1", true},
		{"included-exact-fragment", includeRule(stringExact("/admin")), "/admin#x", true},
		{"included-exact-query-fragment", includeRule(stringExact("/admin")), "/admin?x=1#y", true},
		{"included-exact-empty-query", includeRule(stringExact("/admin")), "/admin?", true},
		{"included-prefix-query", includeRule(stringPrefix("/admin")), "/admin/users?x=1", true},
		{"included-suffix-query", includeRule(stringSuffix("/secret")), "/admin/secret?x=1", true},
		{"included-regex-query", includeRule(stringRegex("^/api/[a-z]+$")), "/api/users?x", true},
		{"included-regex-fragment", includeRule(stringRegex("^/api/[a-z]+$")), "/api/users#x", true},
		{"included-exact-query-other-path", includeRule(stringExact("/admin")), "/public?p=/admin", false},
		{"excluded-exact-query", excludeRule(stringExact("/health")), "/health?x=1", true},
		{"excluded-prefix-query", excludeRule(stringPrefix("/static/")), "/admin?r=/static/", true},
		{"excluded-suffix-query", excludeRule(stringSuffix(".css")), "/admin/secret?a=.css", true},
		{"excluded-suffix-fragment", excludeRule(stringSuffix(".css")), "/admin/secret#.css", true},
		{"excluded-suffix-real-asset-query", excludeRule(stringSuffix(".css")), "/static/site.css?v=2", true},
		{"excluded-regex-query", excludeRule(stringRegex(`\.(css|js)$`)), "/admin?.js", true},
		{"excluded-regex-real-asset-query", excludeRule(stringRegex(`\.(css|js)$`)), "/app.js?v=2", true},
		{"included-exact-repeated-query", includeRule(stringExact("/admin")), "/admin?a?b", true},
		{"only-query", excludeRule(stringSuffix(".css")), "?a=.css", true},
		{"only-fragment", excludeRule(stringSuffix(".css")), "#.css", true},
		// An exclude-only rule matches an empty path anyway, so use include rules to exercise the empty-path check.
		{"only-query-include", includeRule(stringExact("/admin")), "?x", true},
		{"only-fragment-include", includeRule(stringExact("/admin")), "#x", true},
		{"excluded-exact-root-query", excludeRule(stringExact("/")), "/?rest_route=/users", true},
		{"excluded-exact-root", excludeRule(stringExact("/")), "/", false},
		{"excluded-suffix-real-asset", excludeRule(stringSuffix(".css")), "/static/site.css", false},
		{"included-regex-query-only", includeRule(stringRegex(`\?debug=1`)), "/app?debug=1", true},
		{"included-exact-query-value", includeRule(stringExact("/app?debug=1")), "/app?debug=1", true},
		{"excluded-exact-query-value", excludeRule(stringExact("/health?ready")), "/health?ready", true},

		// Regex exclusions must match the whole path. Regex inclusions may match anywhere in it.
		{"excluded-regex-partial-extension", excludeRule(stringRegex(`.*\.(css|js)`)), "/api/secrets.json", true},
		{"excluded-regex-whole-extension", excludeRule(stringRegex(`.*\.(css|js)`)), "/app.js", false},
		{"excluded-regex-partial-segment", excludeRule(stringRegex("/healthz")), "/admin/healthz-dump", true},
		{"excluded-regex-whole-segment", excludeRule(stringRegex("/healthz")), "/healthz", false},
		{"excluded-regex-end-anchored-only", excludeRule(stringRegex(`\.(css|js)$`)), "/app.js", true},
		{"excluded-regex-fully-anchored", excludeRule(stringRegex(`^/static/.*\.(css|js)$`)), "/static/app.js", false},
		{"excluded-regex-alternation", excludeRule(stringRegex("/a|/b")), "/b", false},
		{"excluded-regex-alternation-partial", excludeRule(stringRegex("/a|/b")), "/admin", true},
		{"excluded-regex-invalid", excludeRule(stringRegex("/a)|(/b")), "/ab", true},
		{"excluded-regex-partial-extension-query", excludeRule(stringRegex(`.*\.(css|js)`)), "/api/secrets.json?x=.js", true},
		{"excluded-regex-whole-extension-query", excludeRule(stringRegex(`.*\.(css|js)`)), "/app.js?v=2", true},
		{"excluded-regex-unterminated-quote", excludeRule(stringRegex(`\Q/healthz`)), "/admin", true},
		{"excluded-regex-unterminated-quote-whole", excludeRule(stringRegex(`\Q/healthz`)), "/healthz", false},
		{"excluded-regex-matches-empty", excludeRule(stringRegex("x*")), "/admin", true},
		{"excluded-regex-alternation-longest", excludeRule(stringRegex("/a|/ab")), "/ab", false},
		{"excluded-regex-case-insensitive", excludeRule(stringRegex("(?i)^/STATIC/.*")), "/static/a.css", false},
		{"excluded-prefix-real-asset-query", excludeRule(stringPrefix("/static/")), "/static/app.js?v=2", false},
		{"excluded-regex-prefix-real-asset-query", excludeRule(stringRegex("^/static/.*")), "/static/app.js?v=2", false},
		{"included-regex-partial", includeRule(stringRegex("admin")), "/x/admin/y", true},
		{"included-regex-invalid", includeRule(stringRegex("(")), "/admin", false},

		// ";" path parameters are matched like the query string.
		{"included-exact-params", includeRule(stringExact("/admin")), "/admin;x=1", true},
		{"included-exact-params-query-fragment", includeRule(stringExact("/admin")), "/admin;x=1?y#z", true},
		{"included-regex-params", includeRule(stringRegex("^/admin/secret$")), "/admin;a/secret;b", true},
		{"excluded-suffix-params", excludeRule(stringSuffix(".css")), "/admin/secret;.css", true},
		{"excluded-regex-params", excludeRule(stringRegex(`.*\.css`)), "/admin/x;.css", true},
		{"excluded-exact-params", excludeRule(stringExact("/health")), "/health;x", true},
		{"excluded-prefix-real-asset-params", excludeRule(stringPrefix("/static/")), "/static/app.js;v=2", false},
		{"excluded-param-value", excludeRule(stringExact("/a;b")), "/a;b", true},
		{"included-param-value-query", includeRule(stringExact("/a;b")), "/a;b?x", true},
		{"only-params", excludeRule(stringSuffix(".css")), ";x.css", true},
		{"only-params-include", includeRule(stringExact("/admin")), ";x", true},

		// Segments left behind by ";" parameters are resolved, as backends that drop parameters do.
		{"included-exact-dot-segment-params", includeRule(stringExact("/admin")), "/public/..;/admin", true},
		{"included-prefix-dot-segment-params", includeRule(stringPrefix("/admin")), "/public/..;/admin/x", true},
		{"excluded-prefix-dot-segment-params", excludeRule(stringPrefix("/public/")), "/public/..;/admin", true},
		{"excluded-prefix-dot-segment", excludeRule(stringPrefix("/static/")), "/static/../admin", true},
		{"included-exact-empty-segment-params", includeRule(stringExact("/admin")), "/;x/admin", true},
		{"included-exact-inner-empty-segment-params", includeRule(stringExact("/admin/secret")), "/admin/;x/secret", true},
		{"excluded-exact-trailing-slash", excludeRule(stringExact("/static/")), "/static/", false},
		{"excluded-prefix-repeated-slash", excludeRule(stringPrefix("/static/")), "/static//a.css", false},
		{"included-exact-final-dot-params", includeRule(stringExact("/admin/")), "/admin/.;", true},
		{"included-prefix-final-dot-params", includeRule(stringPrefix("/admin/")), "/x/..;/admin/.;", true},
		{"included-prefix-params-before-dot-segment", includeRule(stringPrefix("/admin/")), "/admin;x/../y", true},

		// Percent-encoded unreserved characters are decoded; "%2F" is not.
		{"excluded-prefix-encoded-dot-segment-params", excludeRule(stringPrefix("/public/")), "/public/%2e%2e;/admin", true},
		{"included-exact-encoded-dot-segment-params", includeRule(stringExact("/admin")), "/public/%2e%2e;/admin", true},
		{"included-exact-encoded-dot-segment", includeRule(stringExact("/admin")), "/public/%2E%2E/admin", true},
		{"included-exact-encoded-letter", includeRule(stringExact("/admin")), "/%61dmin", true},
		{"excluded-prefix-encoded-slash", excludeRule(stringPrefix("/static/")), "/static/%2Fx", false},
		{"excluded-prefix-encoded-letter", excludeRule(stringPrefix("/static/")), "/static/%61pp.js", false},
		{"excluded-exact-encoded-slash", excludeRule(stringExact("/files/a%2Fb")), "/files/a%2Fb", false},
		{"included-exact-encoded-tilde", includeRule(stringExact("/~admin")), "/%7Eadmin", true},
		{"included-exact-encoded-upper", includeRule(stringExact("/Admin")), "/%41dmin", true},
		{"included-exact-encoded-digit", includeRule(stringExact("/1")), "/%31", true},
		{"included-exact-half-valid-escape", includeRule(stringExact("/p")), "/%7z", false},
		{"included-exact-trailing-partial-escape", includeRule(stringExact("/a%6")), "/a%6", true},
		{"included-exact-final-encoded-dot", includeRule(stringExact("/admin/")), "/admin/%2e", true},
		{"included-exact-final-dot-dot-params", includeRule(stringExact("/admin/")), "/admin/x/..;", true},

		// Both trailing-slash readings of a final dot segment, and resolution with ";" parameters kept.
		{"included-exact-final-dot-bare", includeRule(stringExact("/admin")), "/admin/.", true},
		{"included-exact-final-dot-dot-bare", includeRule(stringExact("/admin")), "/admin/x/..", true},
		{"included-exact-final-dot-params-bare", includeRule(stringExact("/admin")), "/admin/.;", true},
		{"included-prefix-undecoded-resolved", includeRule(stringPrefix("/%7Euser/")), "/a/../%7Euser/x", true},
		{"included-prefix-params-kept-resolved", includeRule(stringPrefix("/admin/")), "/./admin/;x/..", true},
		{"excluded-prefix-params-kept-resolved", excludeRule(stringPrefix("/static/")), "/static/../admin/;x/../static/", true},
		{"included-exact-params-repeated-slash-query", includeRule(stringExact("/a;x//b")), "/a;x//b?q", true},
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

// TestTriggerRulesNeverCheckLess checks that a request is still checked if the matching before query handling
// was added (regexes unanchored) checks it, or would check any one of its path forms sent on its own.
func TestTriggerRulesNeverCheckLess(t *testing.T) {
	legacyMatch := func(m *configv1.StringMatch, path string) bool {
		switch v := m.GetMatchType().(type) {
		case *configv1.StringMatch_Exact:
			return v.Exact == path
		case *configv1.StringMatch_Prefix:
			return strings.HasPrefix(path, v.Prefix)
		case *configv1.StringMatch_Suffix:
			return strings.HasSuffix(path, v.Suffix)
		case *configv1.StringMatch_Regex:
			ok, _ := regexp.MatchString(v.Regex, path)
			return ok
		}
		return false
	}
	legacy := func(rules []*configv1.TriggerRule, path string) bool {
		if path == "" {
			return true
		}
		for _, rule := range rules {
			excluded := slices.ContainsFunc(rule.GetExcludedPaths(), func(m *configv1.StringMatch) bool { return legacyMatch(m, path) })
			included := len(rule.GetIncludedPaths()) == 0 ||
				slices.ContainsFunc(rule.GetIncludedPaths(), func(m *configv1.StringMatch) bool { return legacyMatch(m, path) })
			if !excluded && included {
				return true
			}
		}
		return false
	}

	matches := []*configv1.StringMatch{
		stringExact("/admin"), stringExact("/"), stringExact("/health?ready"), stringExact("/a;b"),
		stringPrefix("/admin"), stringPrefix("/static/"), stringPrefix("/app?"),
		stringSuffix(".css"), stringSuffix("/secret"), stringSuffix("?ready"),
		stringRegex(`\.(css|js)$`), stringRegex(`.*\.(css|js)`), stringRegex("/healthz"), stringRegex(`\?debug=1`),
		stringRegex("^/api/[a-z]+$"), stringRegex("/a|/b"), stringRegex("/a)|(/b"), stringRegex("("),
		stringRegex(`\Q/healthz`), stringRegex("^/static/"), stringRegex("x*"), stringRegex("(?i)^/STATIC/.*"),
		stringPrefix("/admin/"), stringExact("/admin/"), stringPrefix("/public/"),
	}
	paths := []string{
		"/", "/admin", "/admin?x=1", "/admin#x", "/admin?x#y", "/admin;x=1", "/admin/secret", "/admin/secret?a=.css",
		"/admin/secret;.css", "/static/site.css", "/static/site.css?v=2", "/static/site.css;v=2", "/api/secrets.json",
		"/app.js", "/app?debug=1", "/ab", "/a;b", "/admin/healthz-dump", "/healthz", "/health?ready", "/api/users",
		"/api/users?x", "/?rest_route=/users", "?x", "#x", ";x", "/public/..;/admin", "/;x/admin", "/static/../admin",
		"/static//site.css", "/static/", "/admin/.;", "/x/..;/admin/.;", "/public/%2e%2e;/admin", "/%61dmin",
		"/public/%2e%2e/admin", "/static/%2Fx", "/admin;x/../y", "/a/%2E/b", "admin/../x", "/admin/.", "/admin/x/..",
		"/./admin/;x/..", "/static/../admin/;x/../static/", "/a/../%7Euser/x", "/admin/%2e", "/a%6", "/%7z",
	}

	ruleSets := make([][]*configv1.TriggerRule, 0, (2+2*len(matches))*len(matches))
	for _, a := range matches {
		ruleSets = append(ruleSets, includeRule(a), excludeRule(a))
		for _, b := range matches {
			ruleSets = append(ruleSets,
				[]*configv1.TriggerRule{{ExcludedPaths: []*configv1.StringMatch{a}, IncludedPaths: []*configv1.StringMatch{b}}},
				append(excludeRule(a), includeRule(b)...))
		}
	}

	// forms is an independent copy of the path forms the matcher uses, so the property covers each of them.
	escape := regexp.MustCompile("%[0-9a-fA-F]{2}")
	forms := func(raw string) []string {
		stripped, _, _ := inthttp.GetPathQueryFragment(raw)
		segments := strings.Split(stripped, "/")
		for i, segment := range segments {
			segments[i], _, _ = strings.Cut(segment, ";")
		}
		noParams := strings.Join(segments, "/")
		decode := func(p string) string {
			return escape.ReplaceAllStringFunc(p, func(e string) string {
				c, _ := strconv.ParseUint(e[1:], 16, 8)
				if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", rune(c)) {
					return string(rune(c))
				}
				return e
			})
		}
		// RFC 3986 dot-segment removal with empty segments dropped as merged slashes, returning the form that
		// keeps a trailing slash after a final "", "." or ".." segment and, for a final dot segment, the form
		// that does not.
		resolve := func(p string) (string, string) {
			var kept []string
			segments := strings.Split(p, "/")
			for _, segment := range segments {
				switch segment {
				case "", ".":
				case "..":
					if len(kept) > 0 {
						kept = kept[:len(kept)-1]
					}
				default:
					kept = append(kept, segment)
				}
			}
			bare := strings.Join(kept, "/")
			if strings.HasPrefix(p, "/") {
				bare = "/" + bare
			} else if bare == "" {
				bare = "."
			}
			last := segments[len(segments)-1]
			directory := bare
			if (last == "" || last == "." || last == "..") && bare != "/" {
				directory += "/"
			}
			// Only a final dot segment is read both ways; a path ending in "/" keeps its slash.
			if last != "." && last != ".." {
				bare = directory
			}
			return directory, bare
		}
		if noParams == "" {
			return []string{raw, stripped, noParams}
		}
		all := []string{raw, stripped, noParams}
		for _, base := range []string{noParams, stripped} {
			for _, p := range []string{base, decode(base)} {
				directory, bare := resolve(p)
				all = append(all, directory, bare)
			}
		}
		return all
	}

	log := telemetry.NoopLogger()
	for _, rules := range ruleSets {
		for _, p := range paths {
			if !slices.ContainsFunc(forms(p), func(f string) bool { return legacy(rules, f) }) {
				continue
			}
			req := &envoy.CheckRequest{Attributes: &envoy.AttributeContext{Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{Path: p},
			}}}
			require.True(t, mustTriggerCheck(log, rules, req), "rules %v, path %q", rules, p)
		}
	}
}

func TestLogTriggerRuleWarnings(t *testing.T) {
	var logs []string
	log := function.NewLogger(func(level telemetry.Level, msg string, err error, values function.Values) {
		logs = append(logs, fmt.Sprint(level, " ", msg, err, values))
	})

	LogTriggerRuleWarnings(log, []*configv1.TriggerRule{{
		ExcludedPaths: []*configv1.StringMatch{
			stringExact("/health?ready"),
			stringPrefix("/static#"),
			stringPrefix("/static;"),
			stringSuffix(".css"),
			stringRegex(`\.(css|js)$`),
			stringRegex(`^/static/.*\.css$`),
			stringRegex(`.*\.css`),
			stringRegex("^/static/"),
			stringRegex("^/health$|/metrics$"),
			stringRegex("(^/a$|^/b$)"),
			stringRegex(".*"),
			stringRegex(`\Q/healthz`),
			stringRegex("x*/static/.*"),
			stringRegex(`^/health\?ready$`),
			stringRegex(".*;jsessionid=.*"),
			stringRegex(`^/health(\?.*)?$`),
			stringRegex(".{1,}/x.{0,}"),
			stringRegex("^/pets/(.*?)?"),
			stringRegex(".+/static/.+"),
			stringRegex(".*/a^"),
			stringRegex("$.*"),
			stringPrefix("/proxy/https://"),
			stringExact("/a/./b"),
			stringExact("/static/%2e"),
			stringExact("/static/.."),
			stringPrefix("/static/."),
			stringRegex("^/a[;#]b$"),
			stringRegex(`^/a(?:\?|#)b$`),
			stringRegex(`^/x(\?y)+$`),
			stringRegex(`^/x(\?y){0,2}$`),
			stringRegex(`^/(a\?|b)$`),
			stringRegex(`^/x(\?y)*$`),
			stringRegex(".{0,5}/a$"),
			stringRegex(`(.{2,})?/x\.css$`),
			stringRegex("^/x[;a]$"),
			stringExact("/a/../b"),
			stringExact("/static/."),
			stringSuffix("/."),
			stringRegex("^/static/%7E.*$"),
			stringRegex(`^/a/\.\./b$`),
			stringRegex(`^/static/\.$`),
			stringRegex("^/proxy/https?://.*$"),
			stringRegex("/proxy/https?://"),
			stringRegex(".{2,}/a$"),
			stringRegex(`^/\.(well-known|acme)/.*$`),
			stringRegex(`^/static/\..+$`),
			stringRegex("(.{1,})?/a$"),
			stringRegex("^("),
		},
		IncludedPaths: []*configv1.StringMatch{
			stringExact("/app?debug=1"),
			stringRegex("admin"),
			stringRegex("["),
		},
	}})

	const (
		separator = "exclusion contains '?', '#', ';', '//'"
		whole     = "exclusion regex must now match the whole request path"
		requires  = "exclusion regex requires '?', '#', ';', '//'"
		invalid   = "regex does not compile"
	)
	want := []struct{ msg, value string }{
		{separator, "/health?ready"},
		{separator, "/static#"},
		{separator, "/static;"},
		{whole, `previous .*(?:\.(css|js)$)`},
		{whole, `previous (?:.*\.css).*`},
		{whole, `previous (?:^/static/).*`},
		{whole, `previous .*(?:^/health$|/metrics$)`},
		{whole, `previous .*(?:\Q/healthz\E).*`},
		{whole, `previous .*(?:x*/static/.*)`},
		{requires, `^/health\?ready$`},
		{requires, ".*;jsessionid=.*"},
		{whole, `previous (?:.*/a^).*`},
		{whole, `previous .*(?:$.*)`},
		{separator, "/proxy/https://"},
		{separator, "/a/./b"},
		{separator, "/static/%2e"},
		{separator, "/static/.."},
		{requires, "^/a[;#]b$"},
		{requires, `^/a(?:\?|#)b$`},
		{requires, `^/x(\?y)+$`},
		{whole, `previous .*(?:.{0,5}/a$)`},
		{whole, `previous .*(?:(.{2,})?/x\.css$)`},
		{separator, "/a/../b"},
		{separator, "/static/."},
		{separator, "value /."},
		{requires, "^/static/%7E.*$"},
		{requires, `^/a/\.\./b$`},
		{requires, `^/static/\.$`},
		{requires, "^/proxy/https?://.*$"},
		{requires, "regex /proxy/https?://]"},
		{invalid, "^("},
		{invalid, "["},
	}
	require.Len(t, logs, len(want), "%q", logs)
	for i, w := range want {
		require.True(t, strings.HasPrefix(logs[i], telemetry.LevelError.String()+" "), logs[i])
		require.Contains(t, logs[i], w.msg)
		require.Contains(t, logs[i], w.value)
		switch w.msg {
		case separator, requires:
			require.Contains(t, logs[i], errExclusionNeverApplies.Error())
		case whole:
			require.Contains(t, logs[i], errExclusionNarrowed.Error())
		}
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
		{
			"rules-inclusions-query-string-triggers-check",
			&configv1.Config{
				Chains:       []*configv1.FilterChain{{Filters: []*configv1.Filter{mock(false)}}},
				TriggerRules: includeRule(stringExact("/admin")),
			},
			"/admin?x=1", codes.PermissionDenied,
		},
		{
			"rules-exclusions-query-string-triggers-check",
			&configv1.Config{
				Chains:       []*configv1.FilterChain{{Filters: []*configv1.Filter{mock(false)}}},
				TriggerRules: excludeRule(stringSuffix(".css")),
			},
			"/admin/secret?a=.css", codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewExtAuthZFilter(tt.config, nil, nil, nil)
			req := &envoy.CheckRequest{
				Attributes: &envoy.AttributeContext{
					Request: &envoy.AttributeContext_Request{
						Http: &envoy.AttributeContext_HttpRequest{
							Path: tt.path,
						},
					},
				},
			}
			got, err := e.Check(t.Context(), req)
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
						"x-request-id":   "test-request-id",
						"x-test-headers": value,
					},
				},
			},
		},
	}
}

func includeRule(m *configv1.StringMatch) []*configv1.TriggerRule {
	return []*configv1.TriggerRule{{IncludedPaths: []*configv1.StringMatch{m}}}
}

func excludeRule(m *configv1.StringMatch) []*configv1.TriggerRule {
	return []*configv1.TriggerRule{{ExcludedPaths: []*configv1.StringMatch{m}}}
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

func TestCheckCancelsDiscovery(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	idp := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		close(started)
		<-req.Context().Done()
		close(stopped)
	}))
	defer idp.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := &configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{{
		Type: &configv1.Filter_Oidc{Oidc: &oidcv1.OIDCConfig{ConfigurationUri: idp.URL}},
	}}}}}
	pool := inthttp.NewTLSConfigPool(nil)
	filter := NewExtAuthZFilter(cfg, pool, nil, nil)
	done := make(chan error, 1)
	go func() {
		response, err := filter.Check(ctx, &envoy.CheckRequest{})
		if response != nil {
			done <- errors.New("discovery failure produced an auth verdict")
			return
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Check ignored cancellation")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery continued after Check cancellation")
	}
}
