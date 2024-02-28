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

package main

import (
	"fmt"
	"os"

	"github.com/tetratelabs/log"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/run/pkg/signal"
	"github.com/tetratelabs/telemetry"

	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/k8s"
	"github.com/tetrateio/authservice-go/internal/oidc"
	"github.com/tetrateio/authservice-go/internal/server"
)

func main() {
	var (
		lifecycle   = run.NewLifecycle()
		configFile  = &internal.LocalConfigFile{}
		logging     = internal.NewLogSystem(log.New(), &configFile.Config)
		tlsPool     = internal.NewTLSConfigPool(lifecycle.Context())
		jwks        = oidc.NewJWKSProvider(tlsPool)
		sessions    = oidc.NewSessionStoreFactory(&configFile.Config)
		envoyAuthz  = server.NewExtAuthZFilter(&configFile.Config, tlsPool, jwks, sessions)
		authzServer = server.New(&configFile.Config, envoyAuthz.Register)
		healthz     = server.NewHealthServer(&configFile.Config)
		secretCtrl  = k8s.NewSecretController(&configFile.Config)
	)

	configLog := run.NewPreRunner("config-log", func() error {
		cfgLog := internal.Logger(internal.Config)
		if cfgLog.Level() == telemetry.LevelDebug {
			cfgLog.Debug("configuration loaded", "config", internal.ConfigToJSONString(&configFile.Config))
		}
		return nil
	})

	g := run.Group{Logger: internal.Logger(internal.Default)}

	g.Register(
		lifecycle,         // manage the lifecycle of the run.Services
		configFile,        // load the configuration
		logging,           // Set up the logging system
		secretCtrl,        // watch for secret updates and update the configuration
		configLog,         // log the configuration
		jwks,              // start the JWKS provider
		sessions,          // start the session store
		authzServer,       // start the server
		healthz,           // start the health server
		&signal.Handler{}, // handle graceful termination
	)

	if err := g.Run(); err != nil {
		fmt.Printf("Unexpected exit: %v\n", err)
		os.Exit(-1)
	}
}
