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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/telemetry"
)

type loggedError struct{ error }

func (e *loggedError) Unwrap() error { return e.error }

// LogRequestError logs service failures once with a category and any safe diagnostic detail.
// It preserves the original error chain. Caller cancellations and deadlines are debug events.
func LogRequestError(ctx context.Context, log telemetry.Logger, msg string, err error, kvs ...any) error {
	if err == nil {
		return nil
	}
	var logged *loggedError
	if errors.As(err, &logged) {
		return err
	}
	kvs = append(kvs, "reason", requestErrorReason(err))
	if detail := requestErrorDetail(err); detail != "" {
		kvs = append(kvs, "error", detail)
	}
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

func requestErrorDetail(err error) string {
	var httpErr *url.Error
	if !errors.As(err, &httpErr) {
		return requestErrorCause(err)
	}
	// A URL error can contain credentials, a sensitive path, or a query. Its cause
	// can also contain untrusted text (for example, a Location header or proxy response).
	parts := []string{httpErr.Op}
	if endpoint, parseErr := url.Parse(httpErr.URL); parseErr == nil && endpoint.Host != "" {
		parts = append(parts, endpoint.Host)
	}
	if cause := requestErrorCause(httpErr.Err); cause != "" {
		parts = append(parts, cause)
	}
	return strings.Join(parts, " ")
}

func requestErrorCause(err error) string {
	var errno syscall.Errno
	var syntax *json.SyntaxError
	var mismatch *json.UnmarshalTypeError
	var corrupt base64.CorruptInputError
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded.Error()
	case errors.Is(err, io.ErrUnexpectedEOF):
		return io.ErrUnexpectedEOF.Error()
	case errors.Is(err, io.EOF):
		return io.EOF.Error()
	case errors.As(err, &errno):
		return errno.Error()
	case errors.As(err, &syntax):
		return fmt.Sprintf("invalid JSON at byte %d", syntax.Offset)
	case errors.As(err, &mismatch):
		return fmt.Sprintf("unexpected JSON value type at byte %d", mismatch.Offset)
	case errors.As(err, &corrupt):
		return corrupt.Error()
	case errors.Is(err, jwt.ErrInvalidJWT()):
		return jwt.ErrInvalidJWT().Error()
	case jws.IsVerificationError(err):
		return "no signature matched the available keys"
	case redis.HasErrorPrefix(err, "WRONGPASS "):
		return "Redis authentication failed (WRONGPASS)"
	case redis.HasErrorPrefix(err, "NOAUTH "):
		return "Redis authentication required (NOAUTH)"
	default:
		return ""
	}
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
