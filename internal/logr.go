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
	kvs   map[string]interface{}
}

// NewLogrAdapter creates a new logger to bridge the logr.Logger to our logging system
func NewLogrAdapter(s telemetry.Logger) logr.Logger {
	k := logrAdapter{scope: s}
	return logr.New(&k)
}

func (l *logrAdapter) Init(_ logr.RuntimeInfo) {}

func (l *logrAdapter) Enabled(level int) bool {
	return int(l.scope.Level()) >= level
}

func (l *logrAdapter) Info(_ int, msg string, kvs ...interface{}) {
	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}
	logger := l.scope.With(kvs...)

	if l.scope.Level() > debugLevelThreshold {
		logger.Debug(msg)
	} else {
		logger.Info(msg)
	}
}

func (l *logrAdapter) Error(err error, msg string, kvs ...interface{}) {
	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}
	logger := l.scope.With(kvs...)
	logger.Error(msg, err)
}

func (l *logrAdapter) WithName(string) logr.LogSink { return l }

func (l *logrAdapter) WithValues(kvs ...interface{}) logr.LogSink {
	if len(kvs) == 0 {
		return l
	}

	if len(kvs)%2 != 0 {
		kvs = append(kvs, "(MISSING)")
	}
	all := make(map[string]interface{}, len(l.kvs)+len(kvs)/2)
	for k, v := range l.kvs {
		all[k] = v
	}
	for i := 0; i < len(kvs); i += 2 {
		all[kvs[i].(string)] = kvs[i+1]
	}
	return &logrAdapter{
		scope: l.scope,
		kvs:   all,
	}
}
