// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

package internal

import (
	"errors"
	"os"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetratelabs/run"
	"google.golang.org/protobuf/proto"
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

	return proto.Unmarshal(content, &l.Config)
}
