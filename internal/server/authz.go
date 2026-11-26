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
	gopath "path"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	"github.com/istio-ecosystem/authservice/internal"
	"github.com/istio-ecosystem/authservice/internal/authz"
	inthttp "github.com/istio-ecosystem/authservice/internal/http"
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
	tlsPool  inthttp.TLSConfigPool
	jwks     oidc.JWKSProvider
	sessions oidc.SessionStoreFactory
}

// NewExtAuthZFilter creates a new ExtAuthZFilter.
func NewExtAuthZFilter(cfg *configv1.Config, tlsPool inthttp.TLSConfigPool, jwks oidc.JWKSProvider, sessions oidc.SessionStoreFactory) *ExtAuthZFilter {
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
		log.Debug("no matching trigger rule, allowing request without authentication")
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
				if h, err = authz.NewOIDCHandler(ctx, ft.Oidc, e.tlsPool, e.jwks, e.sessions, oidc.Clock{}, oidc.NewRandomGenerator()); err != nil {
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
	if len(rules) == 0 {
		return true
	}

	forms := requestPathForms(req.GetAttributes().GetRequest().GetHttp().GetPath())
	// If the path is empty (unlikely, e.g. a bare "?x"), there is nothing to match, so trigger the checks.
	if forms == nil {
		return true
	}

	for i, rule := range rules {
		l := log.With("rule-index", i)
		if matchTriggerRule(l, rule, forms) {
			return true
		}
	}
	return false
}

// requestPathForms returns the distinct forms of the request path that trigger rules are matched against: the
// path as Envoy sent it, the path without its query string and fragment, that path without ";" parameters in
// its segments, and resolved variants of the last two. It returns nil if the path without parameters is empty,
// as it is for an empty path.
//
// Envoy sends the path with the query string attached but routes on the path alone, and backends normalize what
// is left in different ways before routing: some drop ";" parameters, most decode escapes and resolve dot
// segments. Matching only the raw value lets a client append "?x" or ";x" to fall out of an exact include, write
// "/public/%2e%2e;/admin" for "/admin", or add "?.css" to land in a suffix exclusion, and skip authentication.
// Matching only one normalized path would change which requests existing rules cover. So rules are matched
// against every form, resolving towards authentication. Other normalization, such as "%2F" or backslashes, is
// left to Envoy's path normalization settings.
func requestPathForms(rawPath string) []string {
	path, _, _ := inthttp.GetPathQueryFragment(rawPath)
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i], _, _ = strings.Cut(segment, ";")
	}
	noParams := strings.Join(segments, "/")
	if noParams == "" {
		return nil
	}

	forms := []string{rawPath}
	add := func(f string) {
		if !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	add(path)
	add(noParams)
	// Each resolution is taken with and without ";" parameters, and with and without decoding percent-encoded
	// unreserved characters, as backends do either. A final "." or ".." segment leaves a directory under RFC 3986
	// dot-segment removal ("/admin/." is "/admin/"), while path.Clean-style resolution drops the slash, so both
	// are forms.
	for _, base := range []string{noParams, path} {
		for _, p := range []string{base, decodeUnreserved(base)} {
			resolved := gopath.Clean(p)
			last := p[strings.LastIndex(p, "/")+1:]
			directory := resolved
			if (last == "" || last == "." || last == "..") && resolved != "/" {
				directory += "/"
			}
			add(directory)
			if last == "." || last == ".." {
				add(resolved)
			}
		}
	}
	return forms
}

// decodeUnreserved decodes percent-encoded unreserved characters (RFC 3986 section 2.3), which do not change
// what a URI identifies. Other escapes, "%2F" in particular, are kept as they are.
func decodeUnreserved(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}
	decoded := make([]byte, 0, len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+2 < len(path) {
			if c, ok := unhex(path[i+1], path[i+2]); ok && isUnreserved(c) {
				decoded = append(decoded, c)
				i += 2
				continue
			}
		}
		decoded = append(decoded, path[i])
	}
	return string(decoded)
}

func unhex(hi, lo byte) (byte, bool) {
	h, okH := hexValue(hi)
	l, okL := hexValue(lo)
	return h<<4 | l, okH && okL
}

func hexValue(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// matchTriggerRule reports whether the rule requires the request to be checked, given the forms of the request
// path from requestPathForms. An exclusion applies only if it matches every form, and a regex exclusion must
// match the whole of each. An inclusion applies if it matches any form. Either way, a request that some
// reading of the rule says to check gets checked.
func matchTriggerRule(log telemetry.Logger, rule *configv1.TriggerRule, forms []string) bool {
	if rule == nil {
		return false
	}

	// if any of the excluded paths match, this rule doesn't match
	for i, match := range rule.GetExcludedPaths() {
		l := log.With("excluded-match-index", i)
		if matchForms(l, match, forms, true) {
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
		if matchForms(l, match, forms, false) {
			return true
		}
	}

	// if none of the included paths match, this rule doesn't match
	return false
}

// matchForms reports whether match matches the forms of a request path. For an exclusion it must match every
// form, and a regex must match the whole form. For an inclusion it must match any form, and a regex may match
// any part of it.
func matchForms(log telemetry.Logger, match *configv1.StringMatch, forms []string, exclusion bool) bool {
	var matches func(string) bool
	switch m := match.GetMatchType().(type) {
	case *configv1.StringMatch_Exact:
		matches = func(s string) bool { return s == m.Exact }
	case *configv1.StringMatch_Prefix:
		matches = func(s string) bool { return strings.HasPrefix(s, m.Prefix) }
	case *configv1.StringMatch_Suffix:
		matches = func(s string) bool { return strings.HasSuffix(s, m.Suffix) }
	case *configv1.StringMatch_Regex:
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			log.Error("error matching regex", err, "regex", m.Regex, "match", false)
			return false
		}
		matches = re.MatchString
		if exclusion {
			// Leftmost-longest matching finds a match spanning the whole form whenever one exists. Wrapping the
			// pattern as ^(?:...)$ instead would break patterns that compile on their own, such as "\Q/x".
			re.Longest()
			matches = func(s string) bool {
				loc := re.FindStringIndex(s)
				return loc != nil && loc[0] == 0 && loc[1] == len(s)
			}
		}
	default:
		return false
	}

	for _, f := range forms {
		ok := matches(f)
		if exclusion && !ok {
			return false
		}
		if !exclusion && ok {
			return true
		}
	}
	return exclusion
}

// Startup errors for exclusions that no longer behave as they did before path forms were matched. They are logged
// as errors so that they show at every log level: each one can change which requests need authentication.
var (
	errExclusionNeverApplies = errors.New("trigger rule exclusion never applies")
	errExclusionNarrowed     = errors.New("trigger rule exclusion covers fewer paths than before")
)

// LogTriggerRuleWarnings logs trigger rule settings that may not behave as the operator expects.
func LogTriggerRuleWarnings(log telemetry.Logger, rules []*configv1.TriggerRule) {
	for i, rule := range rules {
		for j, match := range rule.GetExcludedPaths() {
			l := log.With("rule-index", i, "excluded-match-index", j)
			var value string
			atEnd := false
			switch m := match.GetMatchType().(type) {
			case *configv1.StringMatch_Exact:
				value, atEnd = m.Exact, true
			case *configv1.StringMatch_Prefix:
				value = m.Prefix
			case *configv1.StringMatch_Suffix:
				value, atEnd = m.Suffix, true
			case *configv1.StringMatch_Regex:
				logRegexExclusion(l, m.Regex)
			}
			if value != "" && neverInResolvedPath(value, atEnd) {
				l.Error("trigger rule exclusion contains '?', '#', ';', '//', a '.' or '..' segment, or a "+
					"percent-encoded unreserved character, and never applies: exclusions must also match the "+
					"request path without its query string, fragment and ';' parameters, decoded and resolved",
					errExclusionNeverApplies, "value", value)
			}
		}
		for j, match := range rule.GetIncludedPaths() {
			if m, ok := match.GetMatchType().(*configv1.StringMatch_Regex); ok {
				if _, err := regexp.Compile(m.Regex); err != nil {
					log.Error("trigger rule regex does not compile and never matches", err, "rule-index", i,
						"included-match-index", j, "regex", m.Regex)
				}
			}
		}
	}
}

// logRegexExclusion logs an exclusion regex that does not compile, that can never apply, or that covers fewer
// paths now that it has to match the whole path. The last message includes a pattern that matches what the
// regex matched before, so the operator can see what changed and choose.
func logRegexExclusion(log telemetry.Logger, re string) {
	parsed, err := syntax.Parse(re, syntax.Perl)
	if err != nil {
		log.Error("trigger rule regex does not compile and never matches", err, "regex", re)
		return
	}
	if regexRequiresUnresolved(parsed) {
		log.Error("trigger rule exclusion regex requires '?', '#', ';', '//', a '.' or '..' segment, or a "+
			"percent-encoded unreserved character, and never applies: exclusions must also match the request "+
			"path without its query string, fragment and ';' parameters, decoded and resolved",
			errExclusionNeverApplies, "regex", re)
		return
	}
	start, end := regexAnchored(parsed, true), regexAnchored(parsed, false)
	if start && end {
		return
	}
	inner := re
	if _, err := regexp.Compile("(?:" + inner + ")"); err != nil {
		// An unterminated \Q quotes up to the end of the pattern, so close it before wrapping.
		inner += `\E`
	}
	previous := "(?:" + inner + ")"
	if !start {
		previous = ".*" + previous
	}
	if !end {
		previous += ".*"
	}
	log.Error("trigger rule exclusion regex must now match the whole request path, so it excludes fewer requests "+
		"than before; check it covers the paths you mean ('previous' matches what it did before)",
		errExclusionNarrowed, "regex", re, "previous", previous)
}

// regexAnchored reports whether every match of the regex already starts at the beginning of the text (start) or
// ends at its end (!start), or can be extended there by a leading or trailing ".*", ".+" or "(.*)?". Requiring
// a whole path match then changes nothing on that side.
func regexAnchored(re *syntax.Regexp, start bool) bool {
	switch re.Op {
	case syntax.OpBeginText:
		return start
	case syntax.OpEndText:
		return !start
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return regexMatchesAnyRun(re, false)
	case syntax.OpCapture:
		return regexAnchored(re.Sub[0], start)
	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			return false
		}
		if start {
			return regexAnchored(re.Sub[0], start)
		}
		return regexAnchored(re.Sub[len(re.Sub)-1], start)
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !regexAnchored(sub, start) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// regexMatchesAnyRun reports whether the regex is a repetition of any character with no upper bound, such as
// ".*", ".+", ".{2,}" or "(.*)?", which can absorb whatever comes before or after the rest of a match. Inside an
// optional group the repetition must also be able to absorb a single character, which "(.{2,})?" cannot.
func regexMatchesAnyRun(re *syntax.Regexp, optional bool) bool {
	switch re.Op {
	case syntax.OpCapture:
		return regexMatchesAnyRun(re.Sub[0], optional)
	case syntax.OpQuest:
		return regexMatchesAnyRun(re.Sub[0], true)
	case syntax.OpStar, syntax.OpPlus:
	case syntax.OpRepeat:
		if re.Max != -1 || optional && re.Min > 1 {
			return false
		}
	default:
		return false
	}
	return re.Sub[0].Op == syntax.OpAnyChar || re.Sub[0].Op == syntax.OpAnyCharNotNL
}

// regexRequiresUnresolved reports whether every match of the regex contains a literal that no resolved form of a
// request path contains (see neverInResolvedPath), or a character class of only '?', '#' and ';'. Such an
// exclusion never applies. It only inspects literals as the parser groups them, so it can miss a requirement
// split across groups.
func regexRequiresUnresolved(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		return neverInResolvedPath(string(re.Rune), false)
	case syntax.OpCharClass:
		// Rune holds inclusive ranges as pairs; the class requires a separator if it holds nothing else.
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if !isSeparator(r) {
					return false
				}
			}
		}
		return len(re.Rune) > 0
	case syntax.OpCapture, syntax.OpPlus:
		return regexRequiresUnresolved(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min > 0 && regexRequiresUnresolved(re.Sub[0])
	case syntax.OpConcat:
		for i, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				atEnd := i+1 < len(re.Sub) && re.Sub[i+1].Op == syntax.OpEndText
				if neverInResolvedPath(string(sub.Rune), atEnd) {
					return true
				}
				continue
			}
			if regexRequiresUnresolved(sub) {
				return true
			}
		}
		return false
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !regexRequiresUnresolved(sub) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isSeparator(r rune) bool {
	return r == '?' || r == '#' || r == ';'
}

// neverInResolvedPath reports whether text can never appear in the decoded, parameter-free resolved form of a
// request path: it contains '?', '#', ';', "//", a "." or ".." segment, or a percent-encoded unreserved
// character. With atEnd set, the text must end the path, so a trailing "/." or "/.." also counts. An exclusion
// whose value requires such text never applies.
func neverInResolvedPath(text string, atEnd bool) bool {
	if strings.ContainsAny(text, "?#;") || strings.Contains(text, "//") || strings.Contains(text, "/./") ||
		strings.Contains(text, "/../") || decodeUnreserved(text) != text {
		return true
	}
	return atEnd && (strings.HasSuffix(text, "/.") || strings.HasSuffix(text, "/.."))
}
