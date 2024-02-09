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
	"net"
	"sync"
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

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		addr string
		err  error
	}{
		{"empty", "", ErrInvalidAddress},
		{"no-port", "localhost", ErrInvalidAddress},
		{"invalid", "::9090", ErrInvalidAddress},
		{"ipv4", "1.2.3.4:9090", nil},
		{"ipv6", "[::1]:9090", nil},
		{"hostname", "localhost:9090", nil},
		{"any-addr", ":9090", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, (&Server{addr: tt.addr}).Validate(), tt.err)
		})
	}
}

func TestServer(t *testing.T) {
	var (
		g   = run.Group{Logger: telemetry.NoopLogger()}
		irq = test.NewIRQService(func() {})
		l   = bufconn.Listen(1024)
		s   = New(func(s *grpc.Server) {
			testgrpc.RegisterTestServiceServer(s, interop.NewTestServer())
		})
	)
	s.log = telemetry.NoopLogger()
	s.Listen = func() (net.Listener, error) { return l, nil }
	g.Register(s, irq)

	// Start the server
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		require.NoError(t, g.Run())
		wg.Done()
	}()

	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	client := testgrpc.NewTestServiceClient(conn)
	interop.DoEmptyUnaryCall(client) // this method will panic if fails

	// Signal server termination
	require.NoError(t, irq.Close())

	// Wait for the server to stop
	wg.Wait()
}
