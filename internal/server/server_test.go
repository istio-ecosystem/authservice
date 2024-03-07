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
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/run/pkg/test"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	testgrpc "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/test/bufconn"
)

func TestGrpcServer(t *testing.T) {
	s := NewTestServer(func(s *grpc.Server) {
		testgrpc.RegisterTestServiceServer(s, interop.NewTestServer())
	})
	go func() { require.NoError(t, s.Start()) }()
	t.Cleanup(s.Stop)

	conn, err := s.GRPCConn()
	require.NoError(t, err)

	client := testgrpc.NewTestServiceClient(conn)
	interop.DoEmptyUnaryCall(context.Background(), client) // this method will panic if fails
}

func TestListenFails(t *testing.T) {
	err := errors.New("listen failed")
	s := New(nil)
	s.Listen = func() (net.Listener, error) { return nil, err }
	require.ErrorIs(t, s.Serve(), err)
}

// TestServer that uses an in-memory listener for connections.
type TestServer struct {
	g        run.Group
	l        *bufconn.Listener
	dialOpts []grpc.DialOption
	shutdown func()
}

// NewTestServer creates a new test server.
func NewTestServer(handlers ...func(s *grpc.Server)) *TestServer {
	var (
		g        = run.Group{Logger: telemetry.NoopLogger()}
		irq      = test.NewIRQService(func() {})
		l        = bufconn.Listen(1024)
		dialOpts = []grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}

		s = New(nil, handlers...)
	)

	s.Listen = func() (net.Listener, error) { return l, nil }
	g.Register(s, irq)

	return &TestServer{
		g:        g,
		l:        l,
		dialOpts: dialOpts,
		shutdown: func() { _ = irq.Close() },
	}
}

// GRPCConn returns a gRPC connection that connects to the test server.
func (s *TestServer) GRPCConn() (*grpc.ClientConn, error) {
	return grpc.Dial("bufnet", s.dialOpts...)
}

// Start starts the server. This blocks until the server is stopped.
func (s *TestServer) Start() error {
	return s.g.Run()
}

// Stop the test server.
func (s *TestServer) Stop() {
	s.shutdown()
}
