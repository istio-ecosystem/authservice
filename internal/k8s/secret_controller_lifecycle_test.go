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

package k8s

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	runtest "github.com/tetratelabs/run/pkg/test"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/scope"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/tetrateio/authservice-go/internal"
)

const (
	defaultWait      = time.Second * 10
	defaultTick      = time.Millisecond * 20
	defaultNamespace = "default"
)

func TestErrorLoadingConfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "non-existent-file")
	sc := NewSecretController(loadTestConf(t, "testdata/oidc-with-secret-ref.json"))
	sc.namespace = defaultNamespace

	require.ErrorIs(t, sc.PreRun(), ErrLoadingConfig)
}

func TestManagerStarts(t *testing.T) {
	scope.UseLogger(telemetry.NoopLogger())
	ctrl.SetLogger(internal.NewLogrAdapter(telemetry.NoopLogger()))

	var (
		g run.Group

		irq        = runtest.NewIRQService(func() {})
		cfg        = internal.LocalConfigFile{}
		controller = NewSecretController(&cfg.Config)
	)

	manual := &manualPreRun{
		preRunStarted: new(atomic.Bool),
		finishPreRun:  make(chan struct{}),
	}

	controller.restConf = startEnv(t)
	controller.namespace = defaultNamespace
	g.Register(irq, &cfg, controller, manual)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := g.Run("", "--config-path", "testdata/oidc-with-secret-ref.json")
		require.NoError(t, err)
	}()

	// eventually, the controller's PreRun should be done
	require.Eventually(t, func() bool { return manual.preRunStarted.Load() },
		defaultWait, defaultTick, "controller PreRun not done")

	// once preRun is done, the manager should initialize, and we can add our own test manager.Runnable
	mgrStarted := &atomic.Bool{}
	err := controller.manager.Add(manager.RunnableFunc(func(ctx context.Context) error {
		mgrStarted.Store(true)
		<-ctx.Done()
		return nil
	}))
	require.NoError(t, err)

	// signale the prerun phase to complete
	close(manual.finishPreRun)

	// at some point of serve phase, the manager should be started
	t.Run("manager is started", func(t *testing.T) {
		require.Eventually(t, func() bool { return mgrStarted.Load() },
			defaultWait, defaultTick, "manager not started")
	})

	// signal group termination and wait for it
	require.NoError(t, irq.Close())
	wg.Wait()
}

func TestManagerNotInitializedIfNothingToWatch(t *testing.T) {
	scope.UseLogger(telemetry.NoopLogger())
	ctrl.SetLogger(internal.NewLogrAdapter(telemetry.NoopLogger()))

	var (
		g run.Group

		irq        = runtest.NewIRQService(func() {})
		cfg        = internal.LocalConfigFile{}
		controller = NewSecretController(&cfg.Config)
	)

	manual := &manualService{
		serveStarted: new(atomic.Bool),
	}

	controller.restConf = startEnv(t)
	controller.namespace = defaultNamespace
	g.Register(irq, &cfg, controller, manual)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = g.Run("", "--config-path", "testdata/oidc-without-secret-ref-in.json")
	}()

	// wait for the run group to be fully started
	require.Eventually(t, func() bool { return manual.serveStarted.Load() },
		defaultWait, defaultTick, "run group not fully started")

	// signal group termination and wait for it
	require.NoError(t, irq.Close())
	wg.Wait()

	// Verify that the manager was not set
	require.Nil(t, controller.manager)
}

func startEnv(t *testing.T) *rest.Config {
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, env.Stop())
	})
	return cfg
}

var (
	_ run.PreRunner      = (*manualPreRun)(nil)
	_ run.ServiceContext = (*manualService)(nil)
)

type (
	manualPreRun struct {
		preRunStarted *atomic.Bool
		finishPreRun  chan struct{}
	}

	manualService struct {
		serveStarted *atomic.Bool
	}
)

func (l *manualPreRun) Name() string {
	return "manual preRun"
}

func (l *manualPreRun) PreRun() error {
	l.preRunStarted.Store(true)
	<-l.finishPreRun
	return nil
}

func (l *manualService) Name() string {
	return "manual service"
}

func (l *manualService) ServeContext(ctx context.Context) error {
	l.serveStarted.Store(true)
	<-ctx.Done()
	return ctx.Err()
}
