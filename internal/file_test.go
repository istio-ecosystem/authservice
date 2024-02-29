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
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFileWatcher_WatchFile(t *testing.T) {
	const watcherInterval = 500 * time.Millisecond

	tests := []struct {
		name       string
		fileReader *mockReader
		genUpdates func(reader *mockReader)
		interval   time.Duration

		wantCallbacks int
		want          string
		wantUpdates   []string
		wantErr       bool
	}{
		{
			name:          "no updates happening",
			fileReader:    newMockReader("test", "original", nil),
			interval:      watcherInterval,
			wantCallbacks: 0,
			want:          "original",
		},
		{
			name:       "all updates notified",
			fileReader: newMockReader("test", "original", nil),
			genUpdates: func(reader *mockReader) {
				reader.setData([]byte("update 1"))
				reader.waitForRead()
				reader.setData([]byte("update 2"))
				reader.waitForRead()
			},
			interval:      watcherInterval,
			wantCallbacks: 2,
			want:          "original",
			wantUpdates:   []string{"update 1", "update 2"},
		},
		{
			name:       "no content changes don't notify",
			fileReader: newMockReader("test", "original", nil),
			genUpdates: func(reader *mockReader) {
				reader.setData([]byte("update 1"))
				reader.waitForRead()
				reader.setData([]byte("update 2"))
				reader.waitForRead()
				reader.setData([]byte("update 2"))
				reader.waitForRead()
				reader.setData([]byte("update 2"))
				reader.waitForRead()
			},
			interval:      watcherInterval,
			wantCallbacks: 2,
			want:          "original",
			wantUpdates:   []string{"update 1", "update 2"},
		},
		{
			name:       "missed update due to slow interval",
			fileReader: newMockReader("test", "original", nil),
			genUpdates: func(reader *mockReader) {
				reader.setData([]byte("update 1"))
				// no waiting for the read to happen and performing next update
				// reader.waitForRead()
				reader.setData([]byte("update 2"))
				reader.waitForRead()
			},
			interval:      watcherInterval,
			wantCallbacks: 1,
			want:          "original",
			wantUpdates:   []string{"update 2"},
		},
		{
			name:       "error reading file at start",
			fileReader: newMockReader("test", "original", errors.New("error reading file")),
			interval:   watcherInterval,
			wantErr:    true,
		},
		{
			name:       "error reading file after start",
			fileReader: newMockReader("test", "original", nil),
			genUpdates: func(reader *mockReader) {
				reader.setData([]byte("update 1"))
				reader.waitForRead()
				reader.setErr(errors.New("error reading file"))
				reader.waitForRead()
				// stop error
				reader.setErr(nil)
				// even if an error happens, next updates should be notified
				reader.setData([]byte("update 2"))
				reader.waitForRead()
			},
			interval:      watcherInterval,
			wantCallbacks: 2,
			want:          "original",
			wantUpdates:   []string{"update 1", "update 2"},
		},
		{
			name:       "no interval",
			fileReader: newMockReader("test", "original", nil),
			genUpdates: func(reader *mockReader) {
				reader.setData([]byte("update 1"))
				reader.setData([]byte("update 2"))
			},
			interval: 0,
			want:     "original",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			fw := NewFileWatcher(ctx)

			mu := sync.Mutex{}
			var gotUpdates []string

			wg := sync.WaitGroup{}
			wg.Add(tt.wantCallbacks)

			got, err := fw.WatchFile(tt.fileReader, tt.interval, func(data []byte) {
				defer wg.Done()
				mu.Lock()
				gotUpdates = append(gotUpdates, string(data))
				mu.Unlock()
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			if tt.interval <= 0 {
				// if no interval configured, the watcher shouldn't be registered
				_, ok := fw.watchers[tt.fileReader.ID()]
				require.False(t, ok)
			}

			tt.fileReader.waitForRead() // Wait for the first read to happen, the one synchronous
			require.Equal(t, tt.want, string(got))
			require.NoError(t, err)

			if tt.genUpdates != nil {
				tt.genUpdates(tt.fileReader)
			}

			// ensure no more updates are notified before verifying the results
			cancel()

			wg.Wait() // Wait for all callbacks to be notified
			require.Equal(t, tt.wantUpdates, gotUpdates)
		})
	}

	// This test is to ensure that the file watcher can handle multiple files being watched and
	// each callback is notified only for the file it's watching.
	t.Run("multiple files watched", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		fw := NewFileWatcher(ctx)

		mu1 := sync.Mutex{}
		gotUpdates1 := make([]string, 0)
		mu2 := sync.Mutex{}
		gotUpdates2 := make([]string, 0)

		wg1 := sync.WaitGroup{}
		wg1.Add(2) // 2 callbacks to be notified
		wg2 := sync.WaitGroup{}
		wg2.Add(1) // 1 callback to be notified

		file1 := newMockReader("test1", "original1", nil)
		got1, err := fw.WatchFile(file1, watcherInterval, func(data []byte) {
			defer wg1.Done()
			mu1.Lock()
			gotUpdates1 = append(gotUpdates1, string(data))
			mu1.Unlock()
		})
		require.NoError(t, err)
		file1.waitForRead() // Wait for the first read to happen

		file2 := newMockReader("test2", "original2", nil)
		got2, err := fw.WatchFile(file2, watcherInterval, func(data []byte) {
			defer wg2.Done()
			mu2.Lock()
			gotUpdates2 = append(gotUpdates2, string(data))
			mu2.Unlock()
		})
		require.NoError(t, err)
		file2.waitForRead() // Wait for the first read to happen

		file1.setData([]byte("update 1-1"))
		file1.waitForRead()
		file2.setData([]byte("update 2-1"))
		file2.waitForRead()
		file1.setData([]byte("update 1-2"))
		file1.waitForRead()

		// ensure no more updates are notified before verifying the results
		cancel()

		wg1.Wait() // Wait for all callbacks to be notified
		wg2.Wait() // Wait for all callbacks to be notified

		require.Equal(t, "original1", string(got1))
		require.Equal(t, "original2", string(got2))
		require.Equal(t, []string{"update 1-1", "update 1-2"}, gotUpdates1)
		require.Equal(t, []string{"update 2-1"}, gotUpdates2)
	})

	// This test is to ensure that the callback is overridden when a new file is watched
	// The first WatchFile sets a callback, that will only receive the first update happening at the WatchFile call.
	// Then the second WatchFile sets a new callback, that will receive all updates happening after the WatchFile call.
	t.Run("override file watcher overrides callback too", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		fw := NewFileWatcher(ctx)

		muU := sync.Mutex{}
		gotUpdates := make([]string, 0)
		muO := sync.Mutex{}
		gotOverride := make([]string, 0)

		file1 := newMockReader("test1", "original", nil)
		got, err := fw.WatchFile(file1, watcherInterval, func(data []byte) {
			muU.Lock()
			gotUpdates = append(gotUpdates, string(data))
			muU.Unlock()
		})
		require.NoError(t, err)
		file1.waitForRead() // Wait for the first read to happen

		wg := sync.WaitGroup{}
		wg.Add(2) // 2 callbacks to be notified

		file1.setData([]byte("override"))
		gotOvrr, err := fw.WatchFile(file1, watcherInterval/2, func(data []byte) {
			defer wg.Done()
			muO.Lock()
			gotOverride = append(gotOverride, string(data))
			muO.Unlock()
		})
		require.NoError(t, err)
		file1.waitForRead() // Wait for the first read to happen again

		file1.setData([]byte("update 1"))
		file1.waitForRead()
		file1.setData([]byte("update 2"))
		file1.waitForRead()

		// ensure no more updates are notified before verifying the results
		cancel()

		wg.Wait() // Wait for all callbacks to be notified

		require.Equal(t, "original", string(got))
		require.Equal(t, "override", string(gotOvrr))
		require.Equal(t, []string{}, gotUpdates)
		require.Equal(t, []string{"update 1", "update 2"}, gotOverride)
	})
}

var _ Reader = (*mockReader)(nil)

type mockReader struct {
	id  string
	err error

	m        sync.Mutex
	fileData []byte

	// reads is used to signal that a read happened, it should be buffered to avoid deadlocks.
	// It is used to know if a read happened but there's no need to block reads happening if no one is waiting for them.
	reads chan struct{}
}

func newMockReader(id, data string, err error) *mockReader {
	return &mockReader{
		id:       id,
		fileData: []byte(data),
		err:      err,
		reads:    make(chan struct{}, 50),
	}
}

func (m *mockReader) ID() string {
	return m.id
}

func (m *mockReader) Read() ([]byte, error) {
	// Notify that a read happened
	defer func() { m.reads <- struct{}{} }()

	m.m.Lock()
	defer m.m.Unlock()

	if m.err != nil {
		return nil, m.err
	}

	return m.fileData, nil
}

func (m *mockReader) setData(data []byte) {
	m.m.Lock()
	defer m.m.Unlock()
	m.fileData = data
}

func (m *mockReader) setErr(err error) {
	m.m.Lock()
	defer m.m.Unlock()
	m.err = err
}

func (m *mockReader) waitForRead() {
	<-m.reads
}
