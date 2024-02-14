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
	"time"

	"github.com/tetratelabs/run"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

// SessionStore is an interface for storing session data.
type SessionStore interface {
	SetTokenResponse(sessionID string, tokenResponse *TokenResponse)
	GetTokenResponse(sessionID string) *TokenResponse
	SetAuthorizationState(sessionID string, authorizationState *AuthorizationState)
	GetAuthorizationState(sessionID string) *AuthorizationState
	ClearAuthorizationState(sessionID string)
	RemoveSession(sessionID string)
	RemoveAllExpired()
}

var _ run.PreRunner = (*SessionStoreFactory)(nil)

// SessionStoreFactory is a factory for creating session stores.
// It uses the OIDC configuration to determine which store to use.
type SessionStoreFactory struct {
	Config *configv1.Config

	redis  map[string]SessionStore
	memory SessionStore
}

// Name implements run.Unit.
func (s *SessionStoreFactory) Name() string { return "OIDC session store factory" }

// PreRun initializes the stores that are defined in the configuration
func (s *SessionStoreFactory) PreRun() error {
	s.redis = make(map[string]SessionStore)

	for _, fc := range s.Config.Chains {
		for _, f := range fc.Filters {
			if f.GetOidc() == nil {
				continue
			}

			if redisServer := f.GetOidc().GetRedisSessionStoreConfig().GetServerUri(); redisServer != "" {
				// TODO(nacx): Initialize the Redis store
				s.redis[redisServer] = &redisStore{url: redisServer}
			} else if s.memory == nil { // Use a shared in-memory store for all OIDC configurations
				s.memory = NewMemoryStore(
					Clock{},
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
