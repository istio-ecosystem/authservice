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

package internal

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/tetratelabs/telemetry"
)

type loggedError struct{ error }

func (e *loggedError) Unwrap() error { return e.error }

// LogRequestError logs service failures once, without rendering untrusted error text (which
// can contain URLs, credentials, or response bodies). It preserves the original error
// chain. Caller cancellations and expired caller deadlines are debug events.
func LogRequestError(ctx context.Context, log telemetry.Logger, msg string, err error, kvs ...any) error {
	if err == nil {
		return nil
	}
	var logged *loggedError
	if errors.As(err, &logged) {
		return err
	}
	kvs = append(kvs, "reason", requestErrorReason(err))
	if ctx.Err() != nil {
		log.Debug(msg, kvs...)
		return err
	}
	log.Error(msg, nil, kvs...)
	if log.Level() < telemetry.LevelError {
		return err
	}
	return &loggedError{err}
}

func requestErrorReason(err error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &cert):
		return "tls_certificate"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	case errors.As(err, &network):
		return "network"
	default:
		return "internal"
	}
}
