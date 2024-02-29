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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	runtest "github.com/tetratelabs/run/pkg/test"
	"github.com/tetratelabs/telemetry"
	"k8s.io/client-go/rest"
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
	var (
		g = run.Group{Logger: telemetry.NoopLogger()}

		irq        = runtest.NewIRQService(func() {})
		cfg        = internal.LocalConfigFile{}
		logging    = internal.NewLogSystem(telemetry.NoopLogger(), &cfg.Config)
		controller = NewSecretController(&cfg.Config)
	)

	controller.restConf = startEnv(t)
	controller.namespace = defaultNamespace
	g.Register(irq, &cfg, logging, controller)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := g.Run("", "--config-path", "testdata/oidc-with-secret-ref.json")
		require.NoError(t, err)
	}()

	t.Run("controller is setup at preRun", func(t *testing.T) {
		require.Eventually(t, func() bool {
			return controller.k8sClient != nil
		}, defaultWait, defaultTick, "Controller manager is not setup")
	})

	mgrStarted := false
	err := controller.manager.Add(manager.RunnableFunc(func(ctx context.Context) error {
		mgrStarted = true
		<-ctx.Done()
		return ctx.Err()
	}))
	require.NoError(t, err)

	t.Run("manager is started", func(t *testing.T) {
		require.Eventually(t, func() bool { return mgrStarted },
			defaultWait, defaultTick, "manager not started")
	})

	// signal group termination and wait for it
	require.NoError(t, irq.Close())
	wg.Wait()
}

func TestManagerNotInitializedIfNothingToWatch(t *testing.T) {
	var (
		g = run.Group{Logger: telemetry.NoopLogger()}

		irq        = runtest.NewIRQService(func() {})
		cfg        = internal.LocalConfigFile{}
		logging    = internal.NewLogSystem(telemetry.NoopLogger(), &cfg.Config)
		controller = NewSecretController(&cfg.Config)
	)

	controller.restConf = startEnv(t)
	controller.namespace = defaultNamespace
	g.Register(irq, &cfg, logging, controller)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := g.Run("", "--config-path", "testdata/oidc-without-secret-ref-in.json")
		require.NoError(t, err)
	}()

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
