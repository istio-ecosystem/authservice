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
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
)

// newFormatLogger selects the format at emission time because configuration is loaded
// after the scopes are registered. The configuration is fixed before serving requests.
func newFormatLogger(text telemetry.Logger, cfg *configv1.Config, out io.Writer) telemetry.Logger {
	text = text.Clone()
	text.SetLevel(telemetry.LevelDebug)
	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})
	return function.NewLogger(func(level telemetry.Level, msg string, err error, values function.Values) {
		kvs := make([]any, 0, len(values.FromContext)+len(values.FromLogger)+len(values.FromMethod))
		kvs = append(kvs, values.FromContext...)
		kvs = append(kvs, values.FromLogger...)
		kvs = append(kvs, values.FromMethod...)
		if cfg.GetLogFormat() != "json" {
			switch level {
			case telemetry.LevelDebug:
				text.Debug(msg, kvs...)
			case telemetry.LevelInfo:
				text.Info(msg, kvs...)
			case telemetry.LevelError:
				text.Error(msg, err, kvs...)
			}
			return
		}
		var jsonLevel slog.Level
		switch level {
		case telemetry.LevelDebug:
			jsonLevel = slog.LevelDebug
		case telemetry.LevelError:
			jsonLevel = slog.LevelError
		default:
			jsonLevel = slog.LevelInfo
		}
		record := slog.NewRecord(time.Now(), jsonLevel, msg, 0)
		record.Add(kvs...)
		if err != nil {
			record.Add("error", err.Error())
		}
		_ = handler.Handle(context.Background(), record)
	})
}
