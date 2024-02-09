// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

package server

import (
	"errors"
	"fmt"
	"net"

	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"
)

// RegisterGrpc is an interface for registering gRPC registerHandlers.
type RegisterGrpc interface {
	// Register a gRPC handler in the given server.
	Register(s *grpc.Server)
}

var (
	_ run.Initializer = (*Server)(nil)
	_ run.Config      = (*Server)(nil)
	_ run.PreRunner   = (*Server)(nil)
	_ run.Service     = (*Server)(nil)
)

var ErrInvalidAddress = errors.New("invalid address")

// Server that runs as a unit in a run.Group.
type Server struct {
	log  telemetry.Logger
	addr string

	server           *grpc.Server
	registerHandlers []func(s *grpc.Server)

	// Listen allows overriding the default listener. It is meant to
	// be used in tests.
	Listen func() (net.Listener, error)
}

// New creates a new dual gRPC server.
func New(registerHandlers ...func(s *grpc.Server)) *Server {
	return &Server{
		log:              internal.Logger(internal.Server),
		registerHandlers: registerHandlers,
	}
}

// Name returns the name of the unit in the run.Group.
func (s *Server) Name() string { return "gRPC Server" }

// FlagSet returns the flags used to customize the server.
func (s *Server) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("gRPC Server flags")
	flags.StringVar(&s.addr, "listen-address", ":9090", "listen address")
	return flags
}

// Validate the server configuration.
func (s *Server) Validate() error {
	if _, _, err := net.SplitHostPort(s.addr); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAddress, err)
	}
	return nil
}

// Initialize the server.
func (s *Server) Initialize() {
	if s.Listen == nil {
		s.Listen = func() (net.Listener, error) {
			return net.Listen("tcp", s.addr)
		}
	}
}

// PreRun registers the server registerHandlers
func (s *Server) PreRun() error {
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
	s.log.Info("starting gRPC server", "addr", s.addr)
	return s.server.Serve(l)
}

// GracefulStop stops the server.
func (s *Server) GracefulStop() {
	s.log.Info("stopping gRPC server")
	if s.server != nil {
		s.server.GracefulStop()
	}
}
