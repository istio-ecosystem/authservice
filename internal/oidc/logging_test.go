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

package oidc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"github.com/tetratelabs/telemetry/function"
)

func TestSessionLogRedaction(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			var logs []string
			log := function.NewLogger(func(_ telemetry.Level, msg string, err error, values function.Values) {
				logs = append(logs, fmt.Sprint(msg, err, values))
			})
			log.SetLevel(telemetry.LevelDebug)
			var store SessionStore
			if backend == "memory" {
				memory := NewMemoryStore(&Clock{}, 0, 0).(*memoryStore)
				memory.log = log
				store = memory
			} else {
				server := miniredis.RunT(t)
				client := redis.NewClient(&redis.Options{Addr: server.Addr()})
				defer func() { _ = client.Close() }()
				r, err := NewRedisStore(&Clock{}, client, 0, 0)
				require.NoError(t, err)
				r.(*redisStore).log = log
				store = r
			}
			ctx := t.Context()
			session := "private-session"
			require.NoError(t, store.SetTokenResponse(ctx, session, &TokenResponse{
				IDToken: "private-id-token", AccessToken: "private-access-token", RefreshToken: "private-refresh-token",
			}))
			_, err := store.GetTokenResponse(ctx, session)
			require.NoError(t, err)
			require.NoError(t, store.SetAuthorizationState(ctx, session, &AuthorizationState{
				State: "private-state", Nonce: "private-nonce", CodeVerifier: "private-verifier", RequestedURL: "https://example.com/?code=private-code",
			}))
			_, err = store.GetAuthorizationState(ctx, session)
			require.NoError(t, err)
			require.NotEmpty(t, logs)
			require.NotContains(t, strings.Join(logs, "\n"), "private-")
		})
	}
}
