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

package server

import (
	"fmt"
	"net"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetrateio/authservice-go/internal"
)

// RegisterGrpc is an interface for registering gRPC registerHandlers.
type RegisterGrpc interface {
	// Register a gRPC handler in the given server.
	Register(s *grpc.Server)
}

var (
	_ run.PreRunner = (*Server)(nil)
	_ run.Service   = (*Server)(nil)
)

// Server that runs as a unit in a run.Group.
type Server struct {
	log telemetry.Logger
	cfg *configv1.Config

	server           *grpc.Server
	registerHandlers []func(s *grpc.Server)

	// Listen allows overriding the default listener. It is meant to
	// be used in tests.
	Listen func() (net.Listener, error)
}

// New creates a new dual gRPC server.
func New(cfg *configv1.Config, registerHandlers ...func(s *grpc.Server)) *Server {
	return &Server{
		log:              internal.Logger(internal.Server),
		cfg:              cfg,
		registerHandlers: registerHandlers,
	}
}

// Name returns the name of the unit in the run.Group.
func (s *Server) Name() string { return "gRPC Server" }

// PreRun registers the server registerHandlers
func (s *Server) PreRun() error {
	if s.Listen == nil {
		s.Listen = func() (net.Listener, error) {
			return net.Listen("tcp", fmt.Sprintf("%s:%d", s.cfg.ListenAddress, s.cfg.ListenPort))
		}
	}

	logMiddleware := NewLogMiddleware()

	// Initialize the gRPC server
	s.server = grpc.NewServer( // TODO(nacx): Expose the right flags for secure connections
		grpc.ChainUnaryInterceptor(logMiddleware.UnaryServerInterceptor),
		grpc.ChainStreamInterceptor(logMiddleware.StreamInterceptor),
	)

	for _, h := range s.registerHandlers {
		h(s.server)
	}

	return nil
}

// Serve starts the gRPC server.
func (s *Server) Serve() error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	s.log.Info("starting gRPC server", "addr", l.Addr())
	return s.server.Serve(l)
}

// GracefulStop stops the server.
func (s *Server) GracefulStop() {
	s.log.Info("stopping gRPC server")
	if s.server != nil {
		s.server.GracefulStop()
	}
}
