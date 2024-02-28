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
	"github.com/tetratelabs/log"
	"github.com/tetratelabs/run"
	runtest "github.com/tetratelabs/run/pkg/test"
	"github.com/tetratelabs/telemetry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/tetrateio/authservice-go/internal"
)

const (
	defaultWait = time.Second * 10
	defaultTick = time.Millisecond * 20
)

func TestController(t *testing.T) {
	var (
		g = run.Group{Logger: telemetry.NoopLogger()}

		irq        = runtest.NewIRQService(func() {})
		cfg        = internal.LocalConfigFile{}
		logging    = internal.NewLogSystem(log.New(), &cfg.Config)
		controller = NewSecretController(&cfg.Config)
	)

	controller.restConf = startEnv(t)
	controller.namespace = "default"
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

	t.Run("controller is ready", func(t *testing.T) {
		require.Eventually(t, func() bool {
			err := controller.k8sClient.Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
			})
			return err == nil
		}, defaultWait, defaultTick, "create secret failed")
	})

	// signal group termination and wait for it
	require.NoError(t, irq.Close())
	wg.Wait()
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
