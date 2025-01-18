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

package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	"github.com/istio-ecosystem/authservice/internal"
)

const (
	HealthzPath = "/healthz"
	HealthzPort = 10004
)

var (
	_ http.Handler = (*healthServer)(nil)
	_ run.Service  = (*healthServer)(nil)
)

type healthServer struct {
	log    telemetry.Logger
	config *configv1.Config
	server *http.Server

	// Listen allows overriding the default listener. It is meant to
	// be used in tests.
	l net.Listener
}

// NewHealthServer creates a new health server.
func NewHealthServer(config *configv1.Config) run.Unit {
	hs := &healthServer{
		log:    internal.Logger(internal.Health),
		config: config,
	}
	httpServer := &http.Server{Handler: hs}
	hs.server = httpServer
	return hs
}

// Name implements run.Unit.
func (hs *healthServer) Name() string {
	return "Health Server"
}

// Serve implements run.Service.
func (hs *healthServer) Serve() error {
	// use test listener if set
	if hs.l == nil {
		var err error
		hs.l, err = net.Listen("tcp", hs.getAddressAndPort())
		if err != nil {
			return err
		}
	}

	hs.log.Info("starting health server", "addr", hs.l.Addr(), "path", hs.getPath())
	return hs.server.Serve(hs.l)
}

// GracefulStop implements run.Service.
func (hs *healthServer) GracefulStop() {
	hs.log.Info("stopping health server")
	_ = hs.server.Close()
}

func (hs *healthServer) getAddressAndPort() string {
	addr := hs.config.GetHealthListenAddress()
	if addr == "" {
		addr = hs.config.GetListenAddress()
	}

	port := hs.config.GetHealthListenPort()
	if port == 0 {
		port = HealthzPort
	}

	return fmt.Sprintf("%s:%d", addr, port)
}

func (hs *healthServer) getPath() string {
	path := hs.config.GetHealthListenPath()
	if path != "" {
		return path
	}
	return HealthzPath
}

// ServeHTTP implements http.Handler.
func (hs *healthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := hs.log.With("method", r.Method, "path", r.URL.Path)
	listenPath := hs.getPath()

	if r.Method != http.MethodGet || r.URL.Path != listenPath {
		log.Debug("invalid request")
		http.Error(w, fmt.Sprintf("only GET %s is allowed", listenPath), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
