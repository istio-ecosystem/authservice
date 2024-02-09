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
	"errors"
	"fmt"
	"strings"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"
)

const (
	Default  = "default"
	Requests = "requests"
	Server   = "server"
)

// scopes contains the list of all logging scopes
var scopes = map[string]string{
	Default:  "Default",
	Requests: "Logs all requests and responses received by the server",
	Server:   "Server request handling messages",
}

// Logger gets the given logging scope, or return the Noop logger if no scope
// has been registered with the given name.
func Logger(name string) telemetry.Logger {
	s, ok := scope.Find(name)
	if !ok {
		return telemetry.NoopLogger()
	}
	return s
}

var (
	_ run.Config    = (*setupLogging)(nil)
	_ run.PreRunner = (*setupLogging)(nil)
)

// setupLogging is a run.Config that sets up the logging system.
type setupLogging struct {
	logger      telemetry.Logger
	logLevels   string
	logLevelMap map[string]telemetry.Level
}

// NewLogSystem returns a new run.Unit that sets up the logging system.
func NewLogSystem(log telemetry.Logger) run.Unit {
	// Set the defaults in the constructor to make sure this runs as early as possible,
	// not even as part of hte run.Group phases
	scope.UseLogger(log)
	scope.SetAllScopes(telemetry.LevelInfo)
	for name, description := range scopes {
		scope.Register(name, description)
	}
	return &setupLogging{
		logger: Logger(Server),
	}
}

// Name returns the name of the run.Unit.
func (s *setupLogging) Name() string { return "Logging" }

// FlagSet returns a new flag.FlagSet configured with the flags for the run.Unit.
func (s *setupLogging) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("Logging flags")
	flags.StringVar(&s.logLevels, "log-levels", "all:info", "log levels in the format: <logger>:<level>,<logger>:<level>,...")
	return flags
}

// Validate the run.Unit's configuration.
func (s *setupLogging) Validate() (err error) {
	if s.logLevels == "" {
		return errors.New("log levels must be specified")
	}
	s.logLevelMap, err = ParseLogLevels(s.logLevels)
	return
}

// PreRun initializes the logging system.
func (s *setupLogging) PreRun() error {
	SetLogLevels(s.logger, s.logLevelMap)
	return nil
}

// ParseLogLevels reads the given string and configures the log levels accordingly.
// The string must have the format: "logger:level,logger,level,..." where "logger'
// is the name of an existing logger, such as 'pdp', and level is one of the values
// supported in the `log.Level` type.
// In addition to specific logger names, the "all" keyword can be used to configure all
// registered loggers to the configured level. For example: "all:debug".
func ParseLogLevels(logLevels string) (map[string]telemetry.Level, error) {
	res := map[string]telemetry.Level{}
	levels := strings.Split(logLevels, ",")

	for _, l := range levels {
		parts := strings.Split(l, ":")
		if len(parts) != 2 {
			return res, errors.New("must be in the form of <logger>:<level>")
		}

		logger := strings.TrimSpace(parts[0])
		level := strings.TrimSpace(parts[1])

		if logger == "" {
			return res, errors.New("logger must be specified")
		}

		if level == "" {
			return res, errors.New("level must be specified")
		}

		lvl, ok := telemetry.FromLevel(level)
		if !ok {
			return res, fmt.Errorf("%q is not a valid log level", level)
		}

		res[logger] = lvl
	}

	return res, nil
}

// SetLogLevels sets the log levels for the given loggers.
func SetLogLevels(log telemetry.Logger, logLevelMap map[string]telemetry.Level) {
	if level, ok := logLevelMap["all"]; ok {
		for _, logger := range scope.List() {
			logger.SetLevel(level)
		}
	} else {
		for k, l := range logLevelMap {
			logger, ok := scope.Find(k)
			if ok {
				logger.SetLevel(l)
			} else {
				log.Info("invalid logger", "logger", k)
			}
		}
	}
}
