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

package mock

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/istio-ecosystem/authservice/internal/oidc"
)

const redisURL = "redis://localhost:6379"

func TestRedisTokenResponse(t *testing.T) {
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(opts)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := context.Background()

	tr, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	require.Nil(t, tr)

	// Create a session and verify it's added and accessed time is set
	tr = &oidc.TokenResponse{
		IDToken:              newToken(),
		AccessToken:          newToken(),
		AccessTokenExpiresAt: time.Now().Add(30 * time.Minute),
	}
	require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))

	// Verify we can retrieve the token
	got, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	// The testify library doesn't properly compare times, so we need to do it manually
	// then set the times in the returned object so that we can compare the rest of the
	// fields normally
	require.True(t, tr.AccessTokenExpiresAt.Equal(got.AccessTokenExpiresAt))
	got.AccessTokenExpiresAt = tr.AccessTokenExpiresAt
	require.Equal(t, tr, got)

	// Verify that the token TTL has been set
	ttl := client.TTL(ctx, "s1").Val()
	require.Greater(t, ttl, time.Duration(0))
}

func TestRedisAuthorizationState(t *testing.T) {
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(opts)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := context.Background()

	as, err := store.GetAuthorizationState(ctx, "s1")
	require.NoError(t, err)
	require.Nil(t, as)

	// Create a session and verify it's added and accessed time is set
	as = &oidc.AuthorizationState{
		State:        "state",
		Nonce:        "nonce",
		RequestedURL: "https://example.com",
	}
	require.NoError(t, store.SetAuthorizationState(ctx, "s1", as))

	// Verify that the right state is returned
	got, err := store.GetAuthorizationState(ctx, "s1")
	require.NoError(t, err)
	require.Equal(t, as, got)

	// Verify that the token TTL has been set
	ttl := client.TTL(ctx, "s1").Val()
	require.Greater(t, ttl, time.Duration(0))
}

func TestSessionExpiration(t *testing.T) {
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(opts)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 2*time.Second, 0)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("expire-token", func(t *testing.T) {
		tr := &oidc.TokenResponse{
			IDToken:              newToken(),
			AccessToken:          newToken(),
			AccessTokenExpiresAt: time.Now().Add(30 * time.Minute),
		}
		require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))
		require.Eventually(t, func() bool {
			got, err := store.GetTokenResponse(ctx, "s1")
			return got == nil && err == nil
		}, 3*time.Second, 1*time.Second)
	})

	t.Run("expire-state", func(t *testing.T) {
		as := &oidc.AuthorizationState{
			State:        "state",
			Nonce:        "nonce",
			RequestedURL: "https://example.com",
		}
		require.NoError(t, store.SetAuthorizationState(ctx, "s1", as))
		require.Eventually(t, func() bool {
			got, err := store.GetAuthorizationState(ctx, "s1")
			return got == nil && err == nil
		}, 3*time.Second, 1*time.Second)
	})
}

func newToken() string {
	token, _ := jwt.NewBuilder().
		Issuer("authservice").
		Subject("user").
		Expiration(time.Now().Add(time.Hour)).
		Build()
	signed, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("key")))
	return string(signed)
}
