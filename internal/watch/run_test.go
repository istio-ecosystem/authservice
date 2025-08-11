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
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	runtest "github.com/tetratelabs/run/pkg/test"
)

func TestFileWatcherServiceConfig(t *testing.T) {
	var (
		g   run.Group
		irq = runtest.NewIRQService(func() {})
		fws = new(FileWatcherService)
	)
	g.Register(irq, fws)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		require.NoError(t, g.Run("--periodic-reload-interval", "5s"))
	}()

	require.NoError(t, irq.Close())
	wg.Wait()

	require.Equal(t, 5*time.Second, fws.periodicReloadInterval)
}

func TestFileWatcherServiceLifeCycle(t *testing.T) {
	var (
		fws      = new(FileWatcherService)
		f        = t.TempDir() + "/testfile"
		changes  atomic.Int32
		callback = func(Data) { changes.Add(1) }
	)

	// Early access to the watcher should return an error if the watcher is not initialized.
	require.NoError(t, os.WriteFile(f, []byte("test"), 0600))
	require.ErrorIs(t, fws.Watch(f, callback), ErrNotInitialized)

	require.NoError(t, fws.PreRun())
	require.NoError(t, fws.Watch(f, callback))

	ctx, cancel := context.WithCancel(t.Context())
	go func() { require.NoError(t, fws.ServeContext(ctx)) }()

	// Verify that the watcher is notifying while the service is running.
	require.NoError(t, os.WriteFile(f, []byte("updated"), 0600))
	require.Eventually(t, func() bool { return changes.Load() > 0 }, 5*time.Second, 20*time.Millisecond)

	// Verify that the watcher stops when the service is stopped.
	cancel()
	require.NoError(t, os.WriteFile(f, []byte("updated after stop"), 0600))
	require.Never(t, func() bool { return changes.Load() > 1 }, 5*time.Second, 20*time.Millisecond)
}
