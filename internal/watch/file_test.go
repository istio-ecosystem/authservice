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

package watcher

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const maxFileWatcherTestFiles = 10

func TestFileWatcher(t *testing.T) {
	testCases := []struct {
		desc       string
		numFiles   int
		skipModify bool
		opts       FileWatcherOptions
	}{
		{desc: "watch single file", numFiles: 1, opts: NewOpts(WithSkipFallback())},
		{desc: "watch single file", numFiles: 1, opts: NewOpts(WithSkipFallback(), WithCheckInterval(time.Millisecond))},
		{desc: "watch multiple files", numFiles: 50, opts: NewOpts(WithSkipFallback(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with single file", numFiles: 1, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with multiple files", numFiles: 50, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithCheckInterval(time.Millisecond))},
		{desc: "watch single file but do not trigger modify",
			numFiles: 1, opts: NewOpts(WithFallbackInterval(time.Millisecond), WithCheckInterval(time.Millisecond)), skipModify: true},
		{desc: "watch multiple files but do not trigger modify",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithFallbackInterval(time.Millisecond), WithCheckInterval(time.Millisecond)), skipModify: true},
		{desc: "watch file and notify on first time read",
			numFiles: 1, opts: NewOpts(WithSkipFallback(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch multiple files and notify on first time read",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithSkipFallback(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with single file and notify on first time read",
			numFiles: 1, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with multiple files and notify on first time read",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// set up the test
			var (
				dir           = t.TempDir()
				files         = make([]string, tc.numFiles)
				expectedFiles = make(map[string]bool, tc.numFiles)
				toVerify      = make(chan Data, len(files))
			)

			// create the files
			for i := 0; i < tc.numFiles; i++ {
				name := filepath.Join(dir, "test-file-"+strconv.Itoa(i)+".txt")
				files[i] = name
				expectedFiles[name] = true
				require.NoError(t, modifyFile(name, "ok"))
			}

			// create the watcher
			stop := make(chan struct{})
			w := NewFileWatcher(tc.opts)

			// register the watch for the dir or the rest of the files
			if tc.opts.forceWatchDir {
				require.NoError(t, w.Watch(dir, sendToVerify(toVerify)))
			} else {
				for _, f := range files {
					require.NoError(t, w.Watch(f, sendToVerify(toVerify)))
				}
			}

			// start the watcher
			require.NoError(t, w.Start(stop))

			// trigger file events
			if !tc.skipModify {
				for _, test := range files {
					require.NoError(t, modifyFile(test, "ok"))
				}
			}

			dataToVerify := make(map[string]Data)
			func() { // need to make this a func to easily break out of the loop.
				ticker := time.NewTicker(5 * time.Second)
				for {
					select {
					case data := <-toVerify:
						dataToVerify[data.Value.(FileValue).Name] = data
						if len(dataToVerify) == len(files) {
							close(stop)
							return
						}
					case <-ticker.C:
						t.Fatal("timeout while waiting for all files to be notified for changes (5s)")
					}
				}
			}()

			// verify the data
			registeredFiles := make(map[string]bool)
			for _, f := range files {
				registeredFiles[f] = true
			}

			for _, got := range dataToVerify {
				require.NoError(t, got.Err)
				fileGot := got.Value.(FileValue)
				require.True(t, registeredFiles[fileGot.Name], "file %s was not registered", fileGot.Name)
				require.Equal(t, []byte("ok"), fileGot.Data, "not updated file %s", fileGot.Name)
			}
		})
	}
}

func TestRegisterFilesAfterStart(t *testing.T) {
	testCases := []struct {
		desc       string
		numFiles   int
		skipModify bool
		opts       FileWatcherOptions
	}{
		{desc: "watch single file", numFiles: 1, opts: NewOpts(WithSkipFallback(), WithCheckInterval(time.Millisecond))},
		{desc: "watch multiple files", numFiles: 50, opts: NewOpts(WithSkipFallback(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with single file", numFiles: 1, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with multiple files", numFiles: 50, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithCheckInterval(time.Millisecond))},
		{desc: "watch single file but do not trigger modify",
			numFiles: 1, opts: NewOpts(WithFallbackInterval(time.Millisecond), WithCheckInterval(time.Millisecond)), skipModify: true},
		{desc: "watch multiple files but do not trigger modify",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithFallbackInterval(time.Millisecond), WithCheckInterval(time.Millisecond)), skipModify: true},
		{desc: "watch file and notify on first time read",
			numFiles: 1, opts: NewOpts(WithSkipFallback(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch multiple files and notify on first time read",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithSkipFallback(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with single file and notify on first time read",
			numFiles: 1, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
		{desc: "watch dir with multiple files and notify on first time read",
			numFiles: maxFileWatcherTestFiles, opts: NewOpts(WithSkipFallback(), WithForceWatchDir(), WithFirstTimeRead(), WithCheckInterval(time.Millisecond))},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// set up the test
			var (
				dir           = t.TempDir()
				files         = make([]string, tc.numFiles)
				expectedFiles = make(map[string]bool, tc.numFiles)
				toVerify      = make(chan Data, len(files))
			)

			for i := 0; i < tc.numFiles; i++ {
				name := filepath.Join(dir, "test-file-"+strconv.Itoa(i)+".txt")
				files[i] = name
				expectedFiles[name] = true
			}

			// create the first 2 files (if test is multiple files) or none (if test is single file) before starting the watcher.
			firstFileIndex := 0
			if tc.numFiles > 2 {
				firstFileIndex = 2
			}
			for _, f := range files {
				err := modifyFile(f, "ok")
				require.NoError(t, err)
			}

			// create the watcher
			stop := make(chan struct{})
			w := NewFileWatcher(tc.opts)

			if !tc.opts.forceWatchDir {
				// register the first 2 files before starting the watcher
				for _, f := range files[:firstFileIndex] {
					require.NoError(t, w.Watch(f, sendToVerify(toVerify)))
				}
			}

			// start the watcher
			require.NoError(t, w.Start(stop))

			// register the watch for the dir or the rest of the files
			if tc.opts.forceWatchDir {
				require.NoError(t, w.Watch(dir, sendToVerify(toVerify)))
			} else {
				for _, f := range files[firstFileIndex:] {
					require.NoError(t, w.Watch(f, sendToVerify(toVerify)))
				}
			}

			// trigger file events
			if !tc.skipModify {
				for _, test := range files {
					require.NoError(t, modifyFile(test, "ok"))
				}
			}

			dataToVerify := make(map[string]Data)
			func() { // need to make this a func to easily break out of the loop.
				ticker := time.NewTicker(5 * time.Second)
				for {
					select {
					case data := <-toVerify:
						dataToVerify[data.Value.(FileValue).Name] = data
						if len(dataToVerify) == len(files) {
							close(stop)
							return
						}
					case <-ticker.C:
						t.Fatal("timeout while waiting for all files to be notified for changes (5s)")
					}
				}
			}()

			// verify the data
			registeredFiles := make(map[string]bool)
			for _, f := range files {
				registeredFiles[f] = true
			}

			for _, got := range dataToVerify {
				require.NoError(t, got.Err)
				fileGot := got.Value.(FileValue)
				require.True(t, registeredFiles[fileGot.Name], "file %s was not registered", fileGot.Name)
				require.Equal(t, []byte("ok"), fileGot.Data, "not updated file %s", fileGot.Name)
			}
		})
	}
}

func sendToVerify(verifyChan chan Data) func(data Data) {
	return func(data Data) {
		// Tests use a low interval to check for changes, so it's possible to receive a create or chmod event with no changes on file content.
		// If so, let's ignore it and wait for the next event (write).
		if len(data.Value.(FileValue).Data) == 0 {
			return
		}
		verifyChan <- data
	}
}

func TestFailedToWatch(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWatcher(NewOpts(WithSkipFallback()))
	require.Error(t, w.Watch(filepath.Join(dir, "not-exist"), func(_ Data) {}))
	require.Error(t, w.Watch(dir, func(_ Data) {}))
}

func TestOnError(t *testing.T) {
	testCases := []struct {
		name    string
		onEvent func(Watcher, string)
	}{
		{"on-error", func(w Watcher, name string) {
			w.OnError(name, errors.New("error"))
		}},
		{"on-change", func(w Watcher, name string) {
			// Remove the watched file.
			_ = os.Remove(name)
			w.OnChange(name)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			test := filepath.Join(dir, tc.name+".txt")
			err := modifyFile(test, "start")
			require.NoError(t, err)
			stop := make(chan struct{})
			w := NewFileWatcher(NewOpts(WithSkipFallback()))
			err = w.Watch(test, func(data Data) {
				require.Error(t, data.Err)
				if data.Value != nil {
					require.Empty(t, data.Value.(FileValue).Data)
				}
				close(stop)
			})
			require.NoError(t, err)

			err = w.Start(stop)
			require.NoError(t, err)
			tc.onEvent(w, test)
			<-stop
		})
	}
}

func modifyFile(name, data string) error {
	return os.WriteFile(name, []byte(data), os.ModePerm)
}
