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

// Copyright (c) Tetrate, Inc 2025 All Rights Reserved.

package watch

import (
	"context"
	"errors"
	"time"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	"github.com/istio-ecosystem/authservice/internal"
)

var (
	_ run.Config         = (*FileWatcherService)(nil)
	_ run.PreRunner      = (*FileWatcherService)(nil)
	_ run.ServiceContext = (*FileWatcherService)(nil)
	_ Callbacker         = (*FileWatcherService)(nil)

	// ErrNotInitialized is returned when the file watcher service is not initialized and
	// an operation is attempted that requires it to be initialized.
	ErrNotInitialized = errors.New("file watcher service not initialized")
)

// FileWatcherService is a run.Unit that watches for changes in files.
type FileWatcherService struct {
	log                    telemetry.Logger
	w                      Watcher
	periodicReloadInterval time.Duration
}

// Name implements run.Unit.
func (f *FileWatcherService) Name() string { return "File watcher" }

// FlagSet returns the flags used to customize the config file location.
func (f *FileWatcherService) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("File watcher flags")
	flags.DurationVar(&f.periodicReloadInterval, "periodic-reload-interval", 0,
		"Interval for periodic reload of watched files. A value of 0 disables periodic reload.")
	return flags
}

// Validate and load the configuration file.
func (f *FileWatcherService) Validate() error { return nil }

// PreRun initializes the file watcher with the specified options.
func (f *FileWatcherService) PreRun() error {
	f.log = internal.Logger(internal.Watch)

	var opts []OptionFunc
	if f.periodicReloadInterval > 0 {
		f.log.Info("configuring file watcher with periodic reload", "interval", f.periodicReloadInterval)
		opts = append(opts, WithFallbackInterval(f.periodicReloadInterval))
	} else {
		f.log.Info("configuring file watcher without periodic reload")
		opts = append(opts, WithSkipFallback())
	}
	f.w = NewFileWatcher(NewOpts(opts...))

	return nil
}

// ServeContext starts the file watchers.
func (f *FileWatcherService) ServeContext(ctx context.Context) error {
	if err := f.w.Start(ctx.Done()); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// Watch implements the Callbacker interface.
func (f *FileWatcherService) Watch(s string, callback ...Callback) error {
	if f.w == nil {
		return ErrNotInitialized
	}
	return f.w.Watch(s, callback...)
}
