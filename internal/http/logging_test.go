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

// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

package http

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
)

const (
	request  = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nreq body"
	response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nresp body"
)

func TestLoggingRoundTripper(t *testing.T) {
	var (
		rt  = &recordedRoundTrip{logs: make([]logEntry, 0)}
		lrt = LoggingRoundTripper{
			Log: function.NewLogger(rt.log),
			Delegate: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return http.ReadResponse(bufio.NewReader(strings.NewReader(response)), req)
			}),
		}
	)

	tests := []struct {
		name  string
		level telemetry.Level
		want  []logEntry
	}{
		{"no-debug", telemetry.LevelInfo, []logEntry{}},
		{"debug", telemetry.LevelDebug, []logEntry{
			{
				level:  telemetry.LevelDebug,
				msg:    "request",
				values: []any{"data", request},
			},
			{
				level:  telemetry.LevelDebug,
				msg:    "response",
				values: []any{"data", response},
			},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lrt.Log.SetLevel(tt.level)
			req, err := http.NewRequest("POST", "http://example.com", strings.NewReader("req body"))
			require.NoError(t, err)

			_, err = lrt.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, tt.want, rt.logs)
		})
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type recordedRoundTrip struct {
	logs []logEntry
}

type logEntry struct {
	level  telemetry.Level
	msg    string
	values []any
}

func (r *recordedRoundTrip) log(level telemetry.Level, msg string, _ error, values function.Values) {
	r.logs = append(r.logs, logEntry{
		level:  level,
		msg:    msg,
		values: values.FromMethod,
	})
}
