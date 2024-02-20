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

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"
)

// PropagateRequestID is a gRPC middleware that propagates the request id from an Envoy CheckRequest
// to the logging context.
func PropagateRequestID(
	ctx context.Context,
	req interface{},
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	check, ok := req.(*envoy.CheckRequest)
	if !ok {
		return handler(ctx, req)
	}

	headers := check.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if headers == nil || headers[EnvoyXRequestID] == "" {
		return handler(ctx, req)
	}

	ctx = telemetry.KeyValuesToContext(ctx, EnvoyXRequestID, headers[EnvoyXRequestID])
	return handler(ctx, req)
}
