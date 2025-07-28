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
	"fmt"
	"strings"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"
	ctrl "sigs.k8s.io/controller-runtime"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
)

const (
	Authz    = "authz"
	Config   = "config"
	Default  = "default"
	Health   = "health"
	IDP      = "idp"
	JWKS     = "jwks"
	Requests = "requests"
	Server   = "server"
	Session  = "session"
	K8s      = "k8s"
	Secrets  = "secrets"
	Watch    = "watch"
)

// scopes contains the list of all logging scopes
var scopes = map[string]string{
	Authz:    "Envoy ext-authz filter implementation messages",
	Config:   "Configuration messages",
	Default:  "Default",
	Health:   "Health server messages",
	IDP:      "Identity provider requests/responses",
	JWKS:     "JWKS update and parse messages",
	Requests: "Logs all requests and responses received by the server",
	Server:   "Server request handling messages",
	Session:  "Session store messages",
	K8s:      "Kubernetes controller messages",
	Secrets:  "Kubernetes secrets controller messages",
	Watch:    "Filie watcher messages",
}

// ErrInvalidLogLevel is returned when the configured log level is invalid.
var ErrInvalidLogLevel = errors.New("invalid log level")

// Logger gets the given logging scope, or return the Noop logger if no scope
// has been registered with the given name.
func Logger(name string) telemetry.Logger {
	s, ok := scope.Find(name)
	if !ok {
		return telemetry.NoopLogger()
	}
	return s
}

var _ run.PreRunner = (*setupLogging)(nil)

// setupLogging is a run.Config that sets up the logging system.
type setupLogging struct {
	logger telemetry.Logger
	cfg    *configv1.Config
}

// NewLogSystem returns a new run.Unit that sets up the logging system.
func NewLogSystem(log telemetry.Logger, cfg *configv1.Config) run.Unit {
	// Set the defaults in the constructor to make sure this runs as early as possible,
	// not even as part of hte run.Group phases
	scope.UseLogger(log)
	scope.SetAllScopes(telemetry.LevelInfo)
	for name, description := range scopes {
		scope.Register(name, description)
	}
	return &setupLogging{
		logger: Logger(Server),
		cfg:    cfg,
	}
}

// Name returns the name of the run.Unit.
func (s *setupLogging) Name() string { return "Logging" }

// PreRun initializes the logging system.
func (s *setupLogging) PreRun() error {
	if s.cfg.LogLevel == "" {
		s.cfg.LogLevel = "info"
	}
	levels, err := parseLogLevels(s.cfg.LogLevel)
	if err != nil {
		return err
	}
	ctrl.SetLogger(NewLogrAdapter(Logger(K8s)))
	setLogLevels(s.logger, levels)
	return nil
}

// parseLogLevels reads the given string and configures the log levels accordingly.
// The string must have the format: "logger:level,logger,level,..." where "logger'
// is the name of an existing logger, such as 'pdp', and level is one of the values
// supported in the `log.Level` type.
// In addition to specific logger names, the "all" keyword can be used to configure all
// registered loggers to the configured level. For example: "all:debug".
func parseLogLevels(logLevels string) (map[string]telemetry.Level, error) {
	res := map[string]telemetry.Level{}
	levels := strings.Split(logLevels, ",")
	singleLevel := len(levels) == 1

	for _, l := range levels {
		parts := strings.Split(l, ":")
		if len(parts) == 1 && singleLevel { // Assume we're setting the level globally
			lvl, err := readLogLevel(parts[0])
			if err != nil {
				return nil, err
			}
			return map[string]telemetry.Level{"all": lvl}, nil
		}

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

		lvl, err := readLogLevel(parts[1])
		if err != nil {
			return nil, err
		}

		res[logger] = lvl
	}

	return res, nil
}

// setLogLevels sets the log levels for the given loggers.
func setLogLevels(log telemetry.Logger, logLevelMap map[string]telemetry.Level) {
	if level, ok := logLevelMap["all"]; ok {
		for _, logger := range scope.List() {
			logger.SetLevel(level)
		}
		delete(logLevelMap, "all")
	}

	for k, l := range logLevelMap {
		logger, ok := scope.Find(k)
		if ok {
			logger.SetLevel(l)
		} else {
			log.Info("invalid logger", "logger", k)
		}
	}
}

// readLogLevel parses the log level and adapts the legacy loggers from the original
// auth service project to the new telemetry logger supported levels.
func readLogLevel(level string) (telemetry.Level, error) {
	switch level {
	case "trace":
		return telemetry.LevelDebug, nil
	case "critical":
		return telemetry.LevelError, nil
	default:
		l, ok := telemetry.FromLevel(level)
		if !ok {
			return telemetry.LevelNone, fmt.Errorf("%w: %s", ErrInvalidLogLevel, level)
		}
		return l, nil
	}
}
