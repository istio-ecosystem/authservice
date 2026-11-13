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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			text := function.NewLogger(func(_ telemetry.Level, msg string, _ error, _ function.Values) {
				textMessages = append(textMessages, msg)
			})
			cfg := &configv1.Config{}
			log := newFormatLogger(text, cfg, &out).Clone().With("scope", IDP)
			// Scopes are initialized before the configuration file is loaded.
			cfg.LogFormat = format
			ctx := telemetry.KeyValuesToContext(t.Context(), "x-request-id", "public-request")
			log = log.Context(ctx)
			log.Debug("hidden")
			log.Info("request", "operation", "discovery")
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
				} else {
					require.Equal(t, "ERROR", record["level"])
					require.Equal(t, "safe failure", record["error"])
				}
			}
		})
	}
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
