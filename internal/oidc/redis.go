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

package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/telemetry"

	"github.com/tetrateio/authservice-go/internal"
)

var (
	_ SessionStore = (*redisStore)(nil)

	ErrRedis = errors.New("redis error")
)

const (
	keyIDToken           = "id_token"
	keyAccessToken       = "access_token"
	keyAccessTokenExpiry = "access_token_expiry"
	keyRefreshToken      = "refresh_token"
	keyState             = "state"
	keyNonce             = "nonce"
	keyRequestedURL      = "requested_url"
	keyTimeAdded         = "time_added"
)

var (
	tokenResponseKeys      = []string{keyIDToken, keyAccessToken, keyRefreshToken, keyAccessTokenExpiry, keyTimeAdded}
	authorizationStateKeys = []string{keyState, keyNonce, keyRequestedURL, keyTimeAdded}
)

// redisStore is an in-memory implementation of the SessionStore interface that stores
// the session data in a given Redis server.
type redisStore struct {
	log                    telemetry.Logger
	clock                  *Clock
	client                 redis.Cmdable
	absoluteSessionTimeout time.Duration
	idleSessionTimeout     time.Duration
}

// NewRedisStore creates a new SessionStore that stores the session data in a given Redis server.
func NewRedisStore(clock *Clock, client redis.Cmdable, absoluteSessionTimeout, idleSessionTimeout time.Duration) (SessionStore, error) {
	if err := client.Ping(context.TODO()).Err(); err != nil {
		return nil, err
	}

	return &redisStore{
		log:                    internal.Logger(internal.Session).With("type", "redis"),
		clock:                  clock,
		client:                 client,
		absoluteSessionTimeout: absoluteSessionTimeout,
		idleSessionTimeout:     idleSessionTimeout,
	}, nil
}

func (r *redisStore) SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *TokenResponse) error {
	log := r.log.Context(ctx).With("session-id", sessionID)
	log.Debug("setting token response", "token_response", tokenResponse)

	if err := r.client.HSet(ctx, sessionID, keyIDToken, tokenResponse.IDToken).Err(); err != nil {
		return err
	}

	var keysToDelete []string

	if tokenResponse.AccessToken != "" {
		if err := r.client.HSet(ctx, sessionID, keyAccessToken, tokenResponse.AccessToken).Err(); err != nil {
			return err
		}
	} else {
		keysToDelete = append(keysToDelete, keyAccessToken)
	}

	if !tokenResponse.AccessTokenExpiresAt.IsZero() {
		if err := r.client.HSet(ctx, sessionID, keyAccessTokenExpiry, tokenResponse.AccessTokenExpiresAt).Err(); err != nil {
			return err
		}
	} else {
		keysToDelete = append(keysToDelete, keyAccessTokenExpiry)
	}

	if tokenResponse.RefreshToken != "" {
		if err := r.client.HSet(ctx, sessionID, keyRefreshToken, tokenResponse.RefreshToken).Err(); err != nil {
			return err
		}
	} else {
		keysToDelete = append(keysToDelete, keyRefreshToken)
	}

	if len(keysToDelete) > 0 {
		log.Debug("deleting stale keys", "keys", keysToDelete)

		if err := r.client.HDel(ctx, sessionID, keysToDelete...).Err(); err != nil {
			return err
		}
	}

	now := r.clock.Now()
	if err := r.client.HSetNX(ctx, sessionID, keyTimeAdded, now).Err(); err != nil {
		return err
	}

	return r.refreshExpiration(ctx, sessionID, now)
}

func (r *redisStore) GetTokenResponse(ctx context.Context, sessionID string) (*TokenResponse, error) {
	log := r.log.Context(ctx).With("session-id", sessionID)
	log.Debug("getting token response")

	res := r.client.HMGet(ctx, sessionID, tokenResponseKeys...)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var token redisToken
	if err := res.Scan(&token); err != nil {
		return nil, err
	}

	if token.IDToken == "" {
		log.Debug("id token not found")
		return nil, nil
	}

	tokenResponse := token.TokenResponse()
	if _, err := tokenResponse.ParseIDToken(); err != nil {
		log.Error("failed to parse id token", err, "token", token)
		return nil, nil
	}

	if err := r.refreshExpiration(ctx, sessionID, token.TimeAdded); err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func (r *redisStore) SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *AuthorizationState) error {
	log := r.log.Context(ctx).With("session-id", sessionID)
	log.Debug("setting authorization state", "state", authorizationState)

	state := map[string]any{
		keyState:        authorizationState.State,
		keyNonce:        authorizationState.Nonce,
		keyRequestedURL: authorizationState.RequestedURL,
	}

	if err := r.client.HMSet(ctx, sessionID, state).Err(); err != nil {
		return err
	}

	now := r.clock.Now()
	if err := r.client.HSetNX(ctx, sessionID, keyTimeAdded, now).Err(); err != nil {
		return err
	}

	return r.refreshExpiration(ctx, sessionID, now)
}

func (r *redisStore) GetAuthorizationState(ctx context.Context, sessionID string) (*AuthorizationState, error) {
	log := r.log.Context(ctx).With("session-id", sessionID)
	log.Debug("getting authorization state")

	res := r.client.HMGet(ctx, sessionID, authorizationStateKeys...)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var state redisAuthState
	if err := res.Scan(&state); err != nil {
		return nil, err
	}

	if state.State == "" || state.Nonce == "" || state.RequestedURL == "" {
		return nil, nil
	}

	if err := r.refreshExpiration(ctx, sessionID, state.TimeAdded); err != nil {
		return nil, err
	}

	return state.AuthorizationState(), nil
}

func (r *redisStore) ClearAuthorizationState(ctx context.Context, sessionID string) error {
	log := r.log.Context(ctx).With("session-id", sessionID)
	log.Debug("clearing authorization state")

	if err := r.client.HDel(ctx, sessionID, keyState, keyNonce, keyRequestedURL).Err(); err != nil {
		return err
	}

	return r.refreshExpiration(ctx, sessionID, time.Time{})
}

func (r *redisStore) RemoveSession(ctx context.Context, sessionID string) error {
	r.log.Context(ctx).With("session-id", sessionID).Debug("removing session")
	return r.client.Del(ctx, sessionID).Err()
}

func (r *redisStore) RemoveAllExpired(context.Context) error {
	// Sessions are automatically expired by Redis
	return nil
}

func (r *redisStore) refreshExpiration(ctx context.Context, sessionID string, timeAdded time.Time) error {
	log := r.log.Context(ctx).With("session-id", sessionID)

	if timeAdded.IsZero() {
		timeAdded, _ = r.client.HGet(ctx, sessionID, keyTimeAdded).Time()
	}

	if timeAdded.IsZero() {
		if err := r.client.Del(ctx, sessionID).Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: session did not contain creation timestamp", ErrRedis)
	}

	if r.absoluteSessionTimeout == 0 && r.idleSessionTimeout == 0 {
		return nil
	}

	var (
		now              = r.clock.Now()
		absoluteExpireAt = timeAdded.Add(r.absoluteSessionTimeout)
		idleExpireAt     = now.Add(r.idleSessionTimeout)
		expireAt         time.Time
	)

	if r.absoluteSessionTimeout == 0 {
		expireAt = idleExpireAt
	} else if r.idleSessionTimeout == 0 {
		expireAt = absoluteExpireAt
	} else {
		expireAt = absoluteExpireAt
		if idleExpireAt.Before(expireAt) {
			expireAt = idleExpireAt
		}
	}

	log.Debug("updating session expiration", "expire_at", expireAt)

	return r.client.ExpireAt(ctx, sessionID, expireAt).Err()
}

type (
	redisToken struct {
		IDToken              string    `redis:"id_token"`
		AccessToken          string    `redis:"access_token"`
		AccessTokenExpiresAt time.Time `redis:"access_token_expiry"`
		RefreshToken         string    `redis:"refresh_token"`
		TimeAdded            time.Time `redis:"time_added"`
	}

	redisAuthState struct {
		State        string    `redis:"state"`
		Nonce        string    `redis:"nonce"`
		RequestedURL string    `redis:"requested_url"`
		TimeAdded    time.Time `redis:"time_added"`
	}
)

func (r redisToken) TokenResponse() *TokenResponse {
	return &TokenResponse{
		IDToken:              r.IDToken,
		AccessToken:          r.AccessToken,
		AccessTokenExpiresAt: r.AccessTokenExpiresAt,
		RefreshToken:         r.RefreshToken,
	}
}

func (r redisAuthState) AuthorizationState() *AuthorizationState {
	return &AuthorizationState{
		State:        r.State,
		Nonce:        r.Nonce,
		RequestedURL: r.RequestedURL,
	}
}
