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
	"os"

	"github.com/tetratelabs/run"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
)

var _ run.Config = (*LocalConfigFile)(nil)

// ErrInvalidPath is returned when the configuration file path is invalid.
var ErrInvalidPath = errors.New("invalid path")

// LocalConfigFile is a run.Config that loads the configuration file.
type LocalConfigFile struct {
	path string
	// Config is the loaded configuration.
	Config configv1.Config
}

// Name returns the name of the unit in the run.Group.
func (l *LocalConfigFile) Name() string { return "Local configuration file" }

// FlagSet returns the flags used to customize the config file location.
func (l *LocalConfigFile) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("Local Config File flags")
	flags.StringVar(&l.path, "config-path", "/etc/authservice/config.json", "configuration file path")
	return flags
}

// Validate and load the configuration file.
func (l *LocalConfigFile) Validate() error {
	if l.path == "" {
		return ErrInvalidPath
	}

	content, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}

	return protojson.Unmarshal(content, &l.Config)
}
