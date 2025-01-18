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

// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

package http

import (
	"net/http"
	"net/http/httputil"

	"github.com/tetratelabs/telemetry"
)

// LoggingRoundTripper is a http.RoundTripper that logs requests and responses.
type LoggingRoundTripper struct {
	Log      telemetry.Logger
	Delegate http.RoundTripper
}

// RoundTrip logs all the requests and responses using the configured settings.
func (l LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.Log.Level() < telemetry.LevelDebug {
		return l.Delegate.RoundTrip(req)
	}

	if dump, derr := httputil.DumpRequest(req, true); derr == nil {
		l.Log.Debug("request", "data", string(dump))
	}

	res, err := l.Delegate.RoundTrip(req)

	if err == nil {
		if dump, derr := httputil.DumpResponse(res, true); derr == nil {
			l.Log.Debug("response", "data", string(dump))
		}
	}

	return res, err
}
