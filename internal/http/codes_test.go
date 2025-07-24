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

package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestStatusToGrpcCode(t *testing.T) {
	tests := []struct {
		status int
		want   codes.Code
	}{
		{http.StatusOK, codes.OK},
		{499, codes.Canceled},
		{http.StatusInternalServerError, codes.Internal},
		{http.StatusBadRequest, codes.InvalidArgument},
		{http.StatusGatewayTimeout, codes.DeadlineExceeded},
		{http.StatusNotFound, codes.NotFound},
		{http.StatusConflict, codes.AlreadyExists},
		{http.StatusForbidden, codes.PermissionDenied},
		{http.StatusUnauthorized, codes.Unauthenticated},
		{http.StatusTooManyRequests, codes.ResourceExhausted},
		{http.StatusNotImplemented, codes.Unimplemented},
		{http.StatusServiceUnavailable, codes.Unavailable},
		{http.StatusContinue, codes.Unknown},
	}

	for _, tt := range tests {
		require.Equal(t, tt.want, StatusToGrpcCode(tt.status))
	}
}
