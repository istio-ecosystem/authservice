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

package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
)

func TestLogFormat(t *testing.T) {
	for _, format := range []string{"", "text", "logfmt", "json"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			var textMessages []string
			text := function.NewLogger(func(_ telemetry.Level, msg string, _ error, values function.Values) {
				textMessages = append(textMessages, msg)
				if msg == "request" {
					require.Equal(t, []any{"x-request-id", "public-request", "scope", IDP, "operation", "discovery", "duration_ms", 12.5}, values.FromMethod)
				}
			})
			cfg := &configv1.Config{}
			log := newFormatLogger(text, cfg, &out).Clone().With("scope", IDP)
			// Scopes are initialized before the configuration file is loaded.
			cfg.LogFormat = format
			ctx := telemetry.KeyValuesToContext(t.Context(), "x-request-id", "public-request")
			log = log.Context(ctx)
			log.Debug("hidden")
			log.Info("request", "operation", "discovery", "duration_ms", 12.5)
			log.Error("failure\nwith quotes \"", errors.New("safe failure"))
			if format != "json" {
				require.Equal(t, []string{"request", "failure\nwith quotes \""}, textMessages)
				require.Empty(t, out.String())
				return
			}
			require.Empty(t, textMessages)
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			require.Len(t, lines, 2)
			for i, line := range lines {
				var record map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				_, err := time.Parse(time.RFC3339Nano, record["time"].(string))
				require.NoError(t, err)
				require.Equal(t, IDP, record["scope"])
				require.Equal(t, "public-request", record["x-request-id"])
				if i == 0 {
					require.Equal(t, "INFO", record["level"])
					require.Equal(t, "discovery", record["operation"])
					require.Equal(t, 12.5, record["duration_ms"])
				} else {
					require.Equal(t, "ERROR", record["level"])
					require.Equal(t, "safe failure", record["error"])
				}
			}
		})
	}
}

func TestJSONLogKeysAreUnique(t *testing.T) {
	var out bytes.Buffer
	log := newFormatLogger(telemetry.NoopLogger(), &configv1.Config{LogFormat: "json"}, &out)
	ctx := telemetry.KeyValuesToContext(t.Context(), "scope", "context")
	log.Context(ctx).With("scope", "logger").Error("failure", errors.New("safe failure"),
		"scope", "method", "msg", "reserved", "error", "overridden")
	line := out.String()
	require.Equal(t, 1, strings.Count(line, `"scope":`))
	require.Equal(t, 1, strings.Count(line, `"msg":`))
	require.Equal(t, 1, strings.Count(line, `"error":`))
	require.Contains(t, line, `"scope":"method"`)
	require.Contains(t, line, `"msg":"failure"`)
	require.Contains(t, line, `"error":"safe failure"`)
}

func TestInvalidLogFormat(t *testing.T) {
	logging := &setupLogging{cfg: &configv1.Config{LogFormat: "xml"}}
	require.ErrorIs(t, logging.PreRun(), ErrInvalidLogFormat)
}

func TestLogFormatValidation(t *testing.T) {
	for _, format := range []string{"", "text", "logfmt", "json", "xml"} {
		t.Run(format, func(t *testing.T) {
			cfg := &configv1.Config{
				Chains:        []*configv1.FilterChain{{Name: "example", Filters: []*configv1.Filter{{Type: &configv1.Filter_Mock{}}}}},
				ListenAddress: "127.0.0.1", ListenPort: 10003, Threads: 1, LogLevel: "info", LogFormat: format,
			}
			if format == "xml" {
				require.Error(t, cfg.ValidateAll())
			} else {
				require.NoError(t, cfg.ValidateAll())
			}
		})
	}
}

func TestLogRequestError(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "caller"}[canceled], func(t *testing.T) {
			var out bytes.Buffer
			log := newFormatLogger(telemetry.NoopLogger(), &configv1.Config{LogFormat: "json"}, &out)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			original := errors.New("https://user:password@example.com/?token=secret")
			if canceled {
				cancel()
				original = ctx.Err()
			}
			err := LogRequestError(ctx, log, "request failed", original)
			require.ErrorIs(t, err, original)
			_ = LogRequestError(ctx, log, "outer request failed", err)
			if canceled {
				require.Empty(t, out.String())
			} else {
				require.Equal(t, 1, strings.Count(out.String(), "\n"))
				require.Contains(t, out.String(), `"level":"ERROR"`)
				require.NotContains(t, out.String(), "password")
				require.NotContains(t, out.String(), "secret")
			}
		})
	}
}

func TestLogRequestErrorRedactsURLAndCause(t *testing.T) {
	const endpoint = "https://private-user:private-password@example.com/private-path?code=private-query#private-fragment"
	var value int
	syntaxErr := json.Unmarshal([]byte("{private-field"), &value)
	typeErr := json.Unmarshal([]byte(`"private-value"`), &value)
	signed, err := jws.Sign([]byte("private-payload"), jws.WithKey(jwa.HS256, []byte("private-signing-key")))
	require.NoError(t, err)
	_, signatureErr := jws.Verify(signed, jws.WithKey(jwa.HS256, []byte("private-other-key")))
	require.True(t, jws.IsVerificationError(signatureErr))

	for _, tc := range []struct {
		name   string
		err    error
		reason string
		detail string
	}{
		{"network", fmt.Errorf("private-outer: %w", syscall.ECONNREFUSED), "network", "connection refused"},
		{"deadline", context.DeadlineExceeded, "deadline_exceeded", "context deadline exceeded"},
		{"dns", &net.DNSError{Err: "private-error", Name: "private-lookup"}, "dns", ""},
		{"eof", io.EOF, "network", "EOF"},
		{"truncated", io.ErrUnexpectedEOF, "network", "unexpected EOF"},
		{"json-syntax", syntaxErr, "network", "invalid JSON at byte 2"},
		{"json-type", typeErr, "network", "unexpected JSON value type at byte 15"},
		{"base64", base64.CorruptInputError(2), "network", "illegal base64 data at input byte 2"},
		{"signature", signatureErr, "network", "no signature matched the available keys"},
		{"wrong-redis-password", redisReplyError("WRONGPASS private-password"), "network", "Redis authentication failed (WRONGPASS)"},
		{"no-redis-password", redisReplyError("NOAUTH private-password"), "network", "Redis authentication required (NOAUTH)"},
		{"untrusted", errors.New("private-response"), "network", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			log := newFormatLogger(telemetry.NoopLogger(), &configv1.Config{LogFormat: "json"}, &out)
			cause := &url.Error{Op: "Post", URL: endpoint, Err: tc.err}
			wrapped := fmt.Errorf("private-wrapper: %w", cause)
			err := LogRequestError(t.Context(), log, "request failed", wrapped)
			require.ErrorIs(t, err, tc.err)
			want := strings.TrimSpace("Post example.com " + tc.detail)
			require.Contains(t, out.String(), fmt.Sprintf(`"error":%q`, want))
			require.Contains(t, out.String(), fmt.Sprintf(`"reason":%q`, tc.reason))
			require.NotContains(t, out.String(), "private-")
		})
	}
}

type redisReplyError string

func (e redisReplyError) Error() string { return string(e) }
func (redisReplyError) RedisError()     {}

func TestLogFormatFromConfigFile(t *testing.T) {
	original, err := os.ReadFile("testdata/mock.json")
	require.NoError(t, err)
	for _, format := range []string{"json", "logfmt", "text", "xml"} {
		t.Run(format, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.json")
			data := strings.Replace(string(original), "{", fmt.Sprintf(`{"log_format":%q,`, format), 1)
			require.NoError(t, os.WriteFile(file, []byte(data), 0600))
			config := &LocalConfigFile{path: file}
			err := config.Validate()
			if format == "xml" {
				require.ErrorContains(t, err, "LogFormat")
			} else {
				require.NoError(t, err)
				require.Equal(t, format, config.Config.GetLogFormat())
			}
		})
	}
}
