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
	"context"
	"os"
	"sync"
	"time"

	"github.com/tetratelabs/telemetry"
)

type (
	// FileWatcher watches multiple files for changes and calls a callback when the file changes.
	// It is safe to call WatchFile concurrently.
	// To stop watching the files, cancel the context passed to NewFileWatcher.
	FileWatcher struct {
		ctx context.Context
		log telemetry.Logger

		mu       sync.Mutex
		watchers map[string]*watcher
	}

	// watcher watches a file for changes and calls a callback when the file changes.
	watcher struct {
		ctx    context.Context
		cancel context.CancelFunc

		log      telemetry.Logger
		interval time.Duration
		callback func([]byte)
		reader   Reader
		data     []byte
	}

	// Reader is an interface to read the content of a file.
	Reader interface {
		// ID returns a unique identifier for the file.
		ID() string
		// Read reads the content of the file.
		Read() ([]byte, error)
	}
)

// NewFileWatcher creates a new FileWatcher.
func NewFileWatcher(ctx context.Context) *FileWatcher {
	return &FileWatcher{
		ctx:      ctx,
		log:      Logger(Config),
		watchers: map[string]*watcher{},
	}
}

// WatchFile watches a file for changes and calls the callback when the file changes.
// It returns the content of the file and an error if the file cannot be read.
// The callback function is called with the new content of the file.
// If the file is already being watched, the previous watcher is stopped and the new one is started.
func (f *FileWatcher) WatchFile(reader Reader, interval time.Duration, callback func([]byte)) ([]byte, error) {
	id := reader.ID()

	f.mu.Lock()
	if old, ok := f.watchers[id]; ok {
		// stop the current watcher
		old.cancel()
	}
	f.mu.Unlock()

	log := f.log.With("file", id)

	// Load the file data
	data, err := reader.Read()
	if err != nil {
		log.Error("error reading file", err)
		return nil, err
	}

	// Non-positive interval means no watching for file.
	if interval <= 0 {
		return data, nil
	}

	// Create a new watcher
	f.mu.Lock()
	ctx, cancel := context.WithCancel(f.ctx)
	w := &watcher{
		ctx:      ctx,
		cancel:   cancel,
		log:      log,
		interval: interval,
		callback: callback,
		reader:   reader,
		data:     data,
	}
	f.watchers[id] = w
	f.mu.Unlock()

	// Start watching the file
	w.start()
	return data, nil
}

func (w *watcher) start() {
	go func() {
		w.log.Info("start file watcher")

		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-w.ctx.Done():
				w.log.Info("stop file watcher")
				return

			case <-ticker.C:
				data, err := w.reader.Read()
				if err != nil {
					w.log.Error("error reading file", err)
					continue
				}
				if string(data) != string(w.data) {
					w.log.Info("file changed, invoking callback")
					w.data = data
					go w.callback(data)
				}
			}
		}
	}()
}

var _ Reader = (*FileReader)(nil)

// FileReader is a Reader that reads the content of a file given its path.
type FileReader struct {
	filePath string
}

// NewFileReader creates a new FileReader.
func NewFileReader(filePath string) *FileReader {
	return &FileReader{filePath: filePath}
}

// ID returns the file path.
func (f *FileReader) ID() string {
	return f.filePath
}

// Read reads the content of the file.
func (f *FileReader) Read() ([]byte, error) {
	return os.ReadFile(f.filePath)
}
