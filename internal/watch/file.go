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

package watch

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tetratelabs/telemetry"

	"github.com/istio-ecosystem/authservice/internal"
)

var _ Watcher = (*fileWatcher)(nil)

type (
	// fileWatcher is a watcher implementation that watches a single or multiple files or directories.
	fileWatcher struct {
		FileWatcherOptions
		WithCallbacks

		log       telemetry.Logger
		notifiers map[string]*notifier
		isRunning atomic.Bool
		stop      <-chan struct{}
	}

	// FileWatcherOptions defines the options for file watcher.
	FileWatcherOptions struct {
		fallbackTimeout time.Duration
		checkInterval   time.Duration
		firstTimeRead   bool
		skipFallback    bool
		forceWatchDir   bool
	}

	// OptionFunc modifies the file watcher options.
	OptionFunc func(FileWatcherOptions) FileWatcherOptions

	// FileValue holds the data stored in a file.
	// It is the struct that will be passed to the callback.
	FileValue struct {
		Name string
		Data []byte
	}
)

// NewFileWatcher returns a new Watcher implementation thaw watches a single or multiple files or directories.
func NewFileWatcher(options FileWatcherOptions) Watcher {
	return &fileWatcher{
		FileWatcherOptions: options,
		log:                internal.Logger(internal.Watch),
		notifiers:          make(map[string]*notifier),
	}
}

// Watch binds file or directory name with callbacks to be notified on changes.
// This will watch for changes even if the watchers is already started.
func (w *fileWatcher) Watch(name string, callbacks ...Callback) error {
	not, err := newNotifier(w.log, name, w.FileWatcherOptions, callbacks...)
	if err != nil {
		return err
	}

	w.Lock()
	w.notifiers[name] = not
	w.Unlock()

	// If the watcher is already running, we need to trigger the notifier manually, and return only after it is started.
	if w.isRunning.Load() {
		notifyStarted := &sync.WaitGroup{}
		notifyStarted.Add(1)
		go not.start(notifyStarted, w.stop)
		notifyStarted.Wait()
	}
	return nil
}

// Start starts the file watcher.
// Waits for all watchers to be started in new goroutines before returning.
func (w *fileWatcher) Start(stop <-chan struct{}) error {
	w.stop = stop

	// Take a copy to perform the active wait, for better concurrency with the watcher registration
	notifiers := make(map[string]*notifier)
	w.RLock()
	maps.Copy(notifiers, w.notifiers)

	// save isRunning state after the watchers copy since it won't be read anymore,
	// so the new Watch() method will need to start the notifyChanges after the registration
	w.isRunning.Store(true)
	w.RUnlock()

	w.log.Info("starting file watcher", "files", slices.Collect(maps.Keys(notifiers)))
	notifyStarted := &sync.WaitGroup{}
	notifyStarted.Add(len(notifiers))
	for _, not := range notifiers {
		go not.start(notifyStarted, stop)
	}
	notifyStarted.Wait()
	return nil
}

// OnChange allows to manually trigger the OnChange callback.
func (w *fileWatcher) OnChange(name interface{}) {
	w.RLock()
	not := w.notifiers[name.(string)]
	w.RUnlock()
	not.notifyChange()
}

// OnError allows to manually trigger the OnError callback.
func (w *fileWatcher) OnError(name string, err error) {
	w.RLock()
	not := w.notifiers[name]
	w.RUnlock()
	not.OnError(name, err)
}

// notifier watches for changes on a single file or directory and notifies the callbacks.
type notifier struct {
	log               telemetry.Logger
	name              string
	fsWatcher         *fsnotify.Watcher
	options           FileWatcherOptions
	watchingDirectory bool
	WithCallbacks
}

// newNotifier returns a new notifier instance, watching for changes on the given file or directory.
func newNotifier(log telemetry.Logger, name string, options FileWatcherOptions, callbacks ...Callback) (*notifier, error) {
	isDir, err := ensureWatchedExists(name, options.forceWatchDir)
	if err != nil {
		return nil, err
	}

	// Create the underlying fsnotify watcher.
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err = fsWatcher.Add(name); err != nil {
		return nil, err
	}

	not := &notifier{
		log:               log.With("file", name),
		name:              name,
		fsWatcher:         fsWatcher,
		options:           options,
		watchingDirectory: isDir,
	}

	// Register the callbacks to be notified on changes or errors.
	if err = not.WithCallbacks.Watch(name, callbacks...); err != nil {
		return nil, err
	}

	return not, nil
}

// start starts the notifier watch loop.
// After this method is called, the notifier will notify the callbacks on changes.
func (n *notifier) start(notifyStarted *sync.WaitGroup, stop <-chan struct{}) {
	n.log.Debug("watching file")

	// If the first time read is enabled, we must notify the changes.
	if n.options.firstTimeRead {
		n.notifyChange()
	}

	ticker := time.NewTicker(n.options.checkInterval)
	defer ticker.Stop()

	var (
		mustNotify bool
		fallback   time.Time
	)

	// Closer to the event listener loop, we can notify the caller that the watcher is started.
	notifyStarted.Done()
	for {
		select {
		case evt := <-n.fsWatcher.Events:
			n.log.Debug("received event", "event", evt)
			// If we receive a write or create event, we must notify the changes on the next tick.
			if evt.Op.Has(fsnotify.Write) || evt.Op.Has(fsnotify.Create) {
				mustNotify = true
			}
		case <-ticker.C:
			// If fallback is enabled, and we waited for too long, we must notify the changes.
			if !n.options.skipFallback && time.Now().After(fallback) {
				mustNotify = true
			}

			// invoke the on change callback and reset the fallback.
			if mustNotify {
				mustNotify = false
				n.notifyChange()
				fallback = time.Now().Add(n.options.fallbackTimeout)
			}
		case err := <-n.fsWatcher.Errors:
			n.log.Debug("watcher error", err)
			if err != nil {
				n.OnError(n.name, err)
			}
		case <-stop:
			n.log.Debug("stopping watcher")
			_ = n.fsWatcher.Close()
			return
		}
	}
}

// notifyChange notifies the callbacks that a change is detected.
func (n *notifier) notifyChange() {
	n.log.Debug("change detected")
	for _, callback := range n.Callbacks[n.name] {
		if n.watchingDirectory {
			// Only top level files for now.
			files, err := os.ReadDir(n.name)
			if err != nil {
				callback(Data{FileValue{n.name, nil}, err})
				continue
			}

			for _, file := range files {
				if file.IsDir() {
					continue
				}
				callback(readFile(filepath.Join(n.name, file.Name())))
			}

		} else {
			callback(readFile(n.name))
		}
	}
}

func readFile(name string) Data {
	bytes, err := os.ReadFile(filepath.Clean(name))
	return Data{FileValue{name, bytes}, err}
}

func ensureWatchedExists(name string, forceWatchDir bool) (bool, error) {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		if !forceWatchDir {
			return false, err
		}

		// If the file does not exist, we should try to watch it as a directory.
		if err := os.MkdirAll(name, os.ModePerm); err != nil {
			return false, err
		}
		info, _ = os.Stat(name)
	}
	isDir := info.IsDir()
	if isDir && !forceWatchDir {
		return isDir, errors.New("watched name is a directory")
	}
	return isDir, nil
}

// NewOpts returns a new file watcher options configured with the given options.
func NewOpts(options ...OptionFunc) FileWatcherOptions {
	o := FileWatcherOptions{
		fallbackTimeout: time.Minute,
		checkInterval:   time.Second,
		firstTimeRead:   false,
		skipFallback:    false,
		forceWatchDir:   false,
	}
	for _, opt := range options {
		o = opt(o)
	}
	return o
}

// With returns a new file watcher options modified with the given options.
func (o FileWatcherOptions) With(options ...OptionFunc) FileWatcherOptions {
	for _, opt := range options {
		o = opt(o)
	}
	return o
}

// WithFallbackInterval sets the time the watcher will notify for changes even if no change event is received.
// Default is 1 minute.
func WithFallbackInterval(timeout time.Duration) OptionFunc {
	return func(m FileWatcherOptions) FileWatcherOptions {
		m.fallbackTimeout = timeout
		return m
	}
}

// WithCheckInterval sets the interval between two checks for changes.
// Default is 1 second.
func WithCheckInterval(interval time.Duration) OptionFunc {
	return func(m FileWatcherOptions) FileWatcherOptions {
		m.checkInterval = interval
		return m
	}
}

// WithFirstTimeRead sets the watcher to notify the changes on the first time it is started,
// without waiting for a change event.
// Default is disabled.
func WithFirstTimeRead() OptionFunc {
	return func(m FileWatcherOptions) FileWatcherOptions {
		m.firstTimeRead = true
		return m
	}
}

// WithSkipFallback sets the watcher to not notify the changes after the fallback timeout,
// meaning it will only notify when a change event is received.
// Default is disabled.
func WithSkipFallback() OptionFunc {
	return func(m FileWatcherOptions) FileWatcherOptions {
		m.skipFallback = true
		return m
	}
}

// WithForceWatchDir sets the watcher to watch a directory and even create it if it does not exist.
// Default is disabled.
func WithForceWatchDir() OptionFunc {
	return func(m FileWatcherOptions) FileWatcherOptions {
		m.forceWatchDir = true
		return m
	}
}
