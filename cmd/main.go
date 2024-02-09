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

	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/server"
)

func main() {
	var (
		configFile  = &internal.LocalConfigFile{}
		logging     = internal.NewLogSystem(log.New(), &configFile.Config)
		authz       = server.NewExtAuthZFilter(&configFile.Config)
		authzServer = server.New(&configFile.Config, authz.Register)
	)

	g := run.Group{Logger: internal.Logger(internal.Default)}

	g.Register(
		configFile,        // load the configuration
		logging,           // set up the logging system
		authzServer,       // start the server
		&signal.Handler{}, // handle graceful termination
	)

	if err := g.Run(); err != nil {
		fmt.Printf("Unexpected exit: %v\n", err)
		os.Exit(-1)
	}
}
