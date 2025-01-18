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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
)

func TestGetLogger(t *testing.T) {
	var (
		logger1Name = "l1"
		// do not reuse this name in other tests, otherwise multiple runs of the test may fail due find it registered
		noLoggerName = "lnoop"
	)
	l1 := scope.Register(logger1Name, "test logger one")

	NewLogSystem(telemetry.NoopLogger(), nil)

	require.Equal(t, l1, Logger(logger1Name))
	require.Equal(t, telemetry.NoopLogger(), Logger(noLoggerName))
}

func TestLoggingSetup(t *testing.T) {
	l1 := scope.Register("l1", "test logger one")
	l2 := scope.Register("l2", "test logger two")

	tests := []struct {
		levels    string
		l1        telemetry.Level
		l2        telemetry.Level
		expectErr bool
	}{
		// backwards compat log levels
		{"trace", telemetry.LevelDebug, telemetry.LevelDebug, false},
		{"critical", telemetry.LevelError, telemetry.LevelError, false},
		{"all:trace", telemetry.LevelDebug, telemetry.LevelDebug, false},
		{"all:critical", telemetry.LevelError, telemetry.LevelError, false},
		{"l1:trace,l2:critical", telemetry.LevelDebug, telemetry.LevelError, false},
		// telemetry log levels
		{"l1:debug", telemetry.LevelDebug, telemetry.LevelInfo, false},
		{"l1:debug,l2:debug", telemetry.LevelDebug, telemetry.LevelDebug, false},
		{"invalid:debug,l2:error", telemetry.LevelInfo, telemetry.LevelError, false},
		{"all:none,l1:debug", telemetry.LevelDebug, telemetry.LevelNone, false},
		{"", telemetry.LevelInfo, telemetry.LevelInfo, false},
		{",", telemetry.LevelInfo, telemetry.LevelInfo, true},
		{":", telemetry.LevelInfo, telemetry.LevelInfo, true},
		{"invalid", telemetry.LevelInfo, telemetry.LevelInfo, true},
		{"l1:,l2:info", telemetry.LevelInfo, telemetry.LevelInfo, true},
		{"l1:debug,l2:invalid", telemetry.LevelInfo, telemetry.LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.levels, func(t *testing.T) {
			g := run.Group{Logger: telemetry.NoopLogger()}
			g.Register(NewLogSystem(telemetry.NoopLogger(), &configv1.Config{LogLevel: tt.levels}))
			require.Equal(t, tt.expectErr, g.Run() != nil)

			require.Equal(t, tt.l1, l1.Level())
			require.Equal(t, tt.l2, l2.Level())
		})
	}
}
