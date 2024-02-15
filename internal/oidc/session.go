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
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

// SessionStore is an interface for storing session data.
type SessionStore interface {
	SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *TokenResponse) error
	GetTokenResponse(ctx context.Context, sessionID string) (*TokenResponse, error)
	SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *AuthorizationState) error
	GetAuthorizationState(ctx context.Context, sessionID string) (*AuthorizationState, error)
	ClearAuthorizationState(ctx context.Context, sessionID string) error
	RemoveSession(ctx context.Context, sessionID string) error
	RemoveAllExpired(ctx context.Context) error
}

var _ run.PreRunner = (*SessionStoreFactory)(nil)

// SessionStoreFactory is a factory for creating session stores.
// It uses the OIDC configuration to determine which store to use.
type SessionStoreFactory struct {
	Config *configv1.Config

	log    telemetry.Logger
	redis  map[string]SessionStore
	memory SessionStore
}

// Name implements run.Unit.
func (s *SessionStoreFactory) Name() string { return "OIDC session store factory" }

// PreRun initializes the stores that are defined in the configuration
func (s *SessionStoreFactory) PreRun() error {
	s.log = internal.Logger(internal.Session)

	s.redis = make(map[string]SessionStore)
	clock := &Clock{}

	for _, fc := range s.Config.Chains {
		log := s.log.With("chain", fc.Name)

		for _, f := range fc.Filters {
			if f.GetOidc() == nil {
				continue
			}

			if redisServer := f.GetOidc().GetRedisSessionStoreConfig().GetServerUri(); redisServer != "" {
				log.Info("initializing redis session store", "redis-url", redisServer)
				// No need to check the errors here as it has already been validated when loading the configuration
				opts, _ := redis.ParseURL(redisServer)
				client := redis.NewClient(opts)
				r, err := NewRedisStore(clock, client,
					time.Duration(f.GetOidc().GetAbsoluteSessionTimeout()),
					time.Duration(f.GetOidc().GetIdleSessionTimeout()),
				)
				if err != nil {
					return err
				}
				s.redis[redisServer] = r
			} else if s.memory == nil { // Use a shared in-memory store for all OIDC configurations
				log.Info("initializing in-memory session store")
				s.memory = NewMemoryStore(clock,
					time.Duration(f.GetOidc().GetAbsoluteSessionTimeout()),
					time.Duration(f.GetOidc().GetIdleSessionTimeout()),
				)
			}
		}
	}

	return nil
}

// Get returns the appropriate session store for the given OIDC configuration.
func (s *SessionStoreFactory) Get(cfg *oidcv1.OIDCConfig) SessionStore {
	if cfg == nil {
		return nil
	}
	store, ok := s.redis[cfg.GetRedisSessionStoreConfig().GetServerUri()]
	if !ok {
		store = s.memory
	}
	return store
}
