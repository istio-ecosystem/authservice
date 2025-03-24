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
	"errors"
	"io"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/log"
	"github.com/tetratelabs/telemetry"
)

func TestWithValues(t *testing.T) {
	var a logr.LogSink = &logrAdapter{}
	a = a.WithValues("one", 1, "two", 2)
	a = a.WithValues("three")
	a = a.WithValues()

	require.Equal(t, []any{"one", 1, "two", 2, "three", "(MISSING)"}, a.(*logrAdapter).kvs)
}

func TestWithName(t *testing.T) {
	var a logr.LogSink = &logrAdapter{}
	n := a.WithName("test")

	require.Equal(t, a, n)
}

func TestEnable(t *testing.T) {
	logger := log.New()
	a := logrAdapter{scope: logger}

	logger.SetLevel(telemetry.LevelInfo)
	require.False(t, a.Enabled(debugLevelThreshold))
	require.True(t, a.Enabled(debugLevelThreshold-1))

	logger.SetLevel(telemetry.LevelDebug)
	require.True(t, a.Enabled(debugLevelThreshold))
	require.True(t, a.Enabled(debugLevelThreshold-1))
}

func TestInfo(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := log.New()
	logger.SetLevel(telemetry.LevelInfo)
	a := logrAdapter{
		scope: logger,
	}

	a.Info(0, "test", "one", 1, "two", 2)

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	require.Contains(t, string(out), "level=info msg=\"test\" one=1 two=2")
}

func TestDebug(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := log.New()
	logger.SetLevel(telemetry.LevelDebug)
	a := logrAdapter{
		scope: logger,
	}

	a.Info(debugLevelThreshold, "test", "one", 1, "two", 2)

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	require.Contains(t, string(out), "level=debug msg=\"test\" one=1 two=2")
}

func TestError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := log.New()
	logger.SetLevel(telemetry.LevelError)
	a := logrAdapter{
		scope: logger,
	}

	a.Error(errors.New("error"), "test", "one", 1, "two", 2)

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	require.Contains(t, string(out), "level=error msg=\"test\" one=1 two=2 error=\"error\"")
}

func TestMissingKV(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := log.New()
	logger.SetLevel(telemetry.LevelInfo)
	a := logrAdapter{
		scope: logger,
	}

	a.Info(0, "test", "one", 1, "two")
	a.Error(errors.New("failed"), "got an error", "last")

	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	require.Contains(t, string(out), "level=info msg=\"test\" one=1 two=\"(MISSING)\"")
	require.Contains(t, string(out), "level=error msg=\"got an error\" last=\"(MISSING)\" error=\"failed\"")
}
