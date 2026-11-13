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

package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
)

func TestLoggingRoundTripper(t *testing.T) {
	for _, test := range []struct {
		name         string
		level        telemetry.Level
		fail, cancel bool
		count        int
	}{
		{"info-success", telemetry.LevelInfo, false, false, 0},
		{"debug-success", telemetry.LevelDebug, false, false, 2},
		{"info-failure", telemetry.LevelInfo, true, false, 1},
		{"caller-cancel", telemetry.LevelInfo, true, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs []string
			var levels []telemetry.Level
			log := function.NewLogger(func(level telemetry.Level, msg string, err error, values function.Values) {
				levels = append(levels, level)
				logs = append(logs, fmt.Sprint(msg, err, values))
			})
			log.SetLevel(test.level)
			ctx, cancel := context.WithCancel(telemetry.KeyValuesToContext(t.Context(), "x-request-id", "public-request"))
			defer cancel()
			secret := "private-credential"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				"https://user:"+secret+"@example.com/"+secret+"?code="+secret, strings.NewReader(secret))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+secret)
			req.Header.Set("Cookie", "session="+secret)
			original := errors.New(secret)
			if test.cancel {
				cancel()
				original = context.Canceled
			}
			lrt := LoggingRoundTripper{Log: log, Delegate: roundTripperFunc(func(got *http.Request) (*http.Response, error) {
				body, readErr := io.ReadAll(got.Body)
				require.NoError(t, readErr)
				require.Equal(t, secret, string(body))
				require.Equal(t, "Bearer "+secret, got.Header.Get("Authorization"))
				if test.fail {
					return nil, original
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(secret))}, nil
			})}
			res, err := lrt.RoundTrip(req)
			if test.fail {
				require.ErrorIs(t, err, original)
			} else {
				require.NoError(t, err)
				body, readErr := io.ReadAll(res.Body)
				require.NoError(t, readErr)
				require.Equal(t, secret, string(body))
				require.NoError(t, res.Body.Close())
			}
			require.Len(t, logs, test.count)
			if len(logs) > 0 {
				rendered := strings.Join(logs, "\n")
				require.Contains(t, rendered, "public-request")
				require.Contains(t, rendered, "example.com")
				require.Contains(t, rendered, "duration")
				require.NotContains(t, rendered, secret)
			}
			if test.fail && !test.cancel {
				require.Equal(t, []telemetry.Level{telemetry.LevelError}, levels)
			}
		})
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }
