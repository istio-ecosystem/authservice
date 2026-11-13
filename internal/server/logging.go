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
	"context"
	"time"

	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/istio-ecosystem/authservice/internal"
)

// LogMiddleware is a gRPC middleware that logs all the requests and responses.
type LogMiddleware struct {
	log telemetry.Logger
}

// NewLogMiddleware creates a new LogMiddleware that logs all gRPC requests and responses.
func NewLogMiddleware() LogMiddleware {
	return LogMiddleware{
		log: internal.Logger(internal.Requests),
	}
}

// UnaryServerInterceptor is a grpc.UnaryServerInterceptor that logs all the server requests and responses.
func (l LogMiddleware) UnaryServerInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log := l.log.Context(ctx)

	log.Debug("gRPC request", "method", info.FullMethod)
	start := time.Now()
	resp, err := handler(ctx, req)
	fields := []any{"method", info.FullMethod, "duration", time.Since(start), "code", status.Code(err).String()}
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument:
			log.Info("gRPC request rejected", fields...)
		default:
			_ = internal.LogRequestError(ctx, log, "gRPC request failed", err, fields...)
		}
	} else {
		log.Debug("gRPC response", fields...)
	}

	return resp, err
}
