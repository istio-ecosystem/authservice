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
	"github.com/go-logr/logr"
	"github.com/tetratelabs/telemetry"
)

var _ logr.LogSink = (*logrAdapter)(nil)

const debugLevelThreshold = 5

// logrAdapter is a type that adapts the log.Logger interface so it can be used with our loggers
type logrAdapter struct {
	scope telemetry.Logger
	kvs   []any
}

// NewLogrAdapter creates a new logger to bridge the logr.Logger to our logging system
func NewLogrAdapter(s telemetry.Logger) logr.Logger {
	k := logrAdapter{scope: s}
	return logr.New(&k)
}

func (l *logrAdapter) Init(_ logr.RuntimeInfo) {}

func (l *logrAdapter) Enabled(level int) bool {
	switch l.scope.Level() {
	case telemetry.LevelDebug:
		return true
	case telemetry.LevelInfo | telemetry.LevelError:
		return level < debugLevelThreshold
	default: // telemetry.LevelNone
		return false
	}
}

func (l *logrAdapter) Info(level int, msg string, kvs ...interface{}) {
	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}

	if level >= debugLevelThreshold {
		l.scope.Debug(msg, append(l.kvs, kvs...)...)
	} else {
		l.scope.Info(msg, append(l.kvs, kvs...)...)
	}
}

func (l *logrAdapter) Error(err error, msg string, kvs ...interface{}) {
	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}
	l.scope.Error(msg, err, append(l.kvs, kvs...)...)
}

func (l *logrAdapter) WithName(string) logr.LogSink { return l }

func (l *logrAdapter) WithValues(kvs ...interface{}) logr.LogSink {
	if len(kvs) == 0 {
		return l
	}
	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}
	return &logrAdapter{
		scope: l.scope,
		kvs:   append(l.kvs, kvs...),
	}
}
