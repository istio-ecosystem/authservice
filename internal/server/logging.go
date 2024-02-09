// Copyright (c) Tetrate, Inc 2024 All Rights Reserved.

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

	log.Debug("request", "side", "server", "method", info.FullMethod, "data", toJSON(req))
	resp, err := handler(ctx, req)
	log.Debug("response", "side", "server", "method", info.FullMethod, "data", toJSON(req), "error", err)

	return resp, err
}

// UnaryClientInterceptor is a rpc.UnaryClientInterceptor returns a client unary interceptor that logs
// all the client requests and responses.
func (l LogMiddleware) UnaryClientInterceptor(
	ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	log := l.log.Context(ctx)

	log.Debug("request", "side", "client", "method", method, "data", toJSON(req))
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Debug("response", "side", "server", "method", method, "data", toJSON(req), "error", err)

	return err
}

// StreamInterceptor is a returns a stream interceptor that logs all the requests and responses
func (l LogMiddleware) StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, recvWrapper{
		log:          l.log,
		method:       info.FullMethod,
		ServerStream: ss,
	})
}

type recvWrapper struct {
	log    telemetry.Logger
	method string
	grpc.ServerStream
}

func (s recvWrapper) RecvMsg(m interface{}) error {
	data, _ := json.Marshal(m)
	err := s.ServerStream.RecvMsg(m)
	s.log.Debug("stream message", "method", s.method, "data", string(data), "error", err)
	return err
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
