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
	"encoding/json"

	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/tetrateio/authservice-go/internal"
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

	log.Debug("request", "method", info.FullMethod, "data", toJSON(req))
	resp, err := handler(ctx, req)
	log.Debug("response", "method", info.FullMethod, "data", toJSON(resp), "error", err)

	return resp, err
}

func toJSON(obj interface{}) string {
	var data []byte
	message, ok := obj.(proto.Message)
	if !ok {
		data, _ = json.Marshal(obj)
	} else {
		data, _ = protojson.Marshal(message)
	}
	return string(data)
}
