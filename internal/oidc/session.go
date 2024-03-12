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
	"math/rand"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
)

type (
	// SessionStore is an interface for storing session data.
	SessionStore interface {
		SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *TokenResponse) error
		GetTokenResponse(ctx context.Context, sessionID string) (*TokenResponse, error)
		SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *AuthorizationState) error
		GetAuthorizationState(ctx context.Context, sessionID string) (*AuthorizationState, error)
		ClearAuthorizationState(ctx context.Context, sessionID string) error
		RemoveSession(ctx context.Context, sessionID string) error
		RemoveAllExpired(ctx context.Context) error
	}

	// SessionStoreFactory is a factory for managing multiple SessionStores.
	// It uses the OIDC configuration to determine which store to use.
	SessionStoreFactory interface {
		Get(cfg *oidcv1.OIDCConfig) SessionStore
	}

	// SessionStoreFactoryUnit is a combination of a run.PreRunner and a SessionStoreFactory.
	SessionStoreFactoryUnit interface {
		run.PreRunner
		SessionStoreFactory
	}
)

var (
	_ SessionStoreFactoryUnit = (*sessionStoreFactory)(nil)
)

// SessionStoreFactory is a factory for creating session stores.
// It uses the OIDC configuration to determine which store to use.
type sessionStoreFactory struct {
	Config *configv1.Config

	log    telemetry.Logger
	redis  map[string]SessionStore
	memory SessionStore
}

// NewSessionStoreFactory creates a factory for managing session stores.
// It uses the OIDC configuration to determine which store to use.
func NewSessionStoreFactory(cfg *configv1.Config) SessionStoreFactoryUnit {
	return &sessionStoreFactory{
		Config: cfg,
	}
}

// Name implements run.Unit.
func (s *sessionStoreFactory) Name() string { return "OIDC session store factory" }

// PreRun initializes the stores that are defined in the configuration
func (s *sessionStoreFactory) PreRun() error {
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
					time.Duration(f.GetOidc().GetAbsoluteSessionTimeout())*time.Second,
					time.Duration(f.GetOidc().GetIdleSessionTimeout())*time.Second,
				)
				if err != nil {
					return err
				}
				s.redis[redisServer] = r
			} else if s.memory == nil { // Use a shared in-memory store for all OIDC configurations
				log.Info("initializing in-memory session store")
				s.memory = NewMemoryStore(clock,
					time.Duration(f.GetOidc().GetAbsoluteSessionTimeout())*time.Second,
					time.Duration(f.GetOidc().GetIdleSessionTimeout())*time.Second,
				)
			}
		}
	}

	return nil
}

// Get returns the appropriate session store for the given OIDC configuration.
func (s *sessionStoreFactory) Get(cfg *oidcv1.OIDCConfig) SessionStore {
	if cfg == nil {
		return nil
	}
	store, ok := s.redis[cfg.GetRedisSessionStoreConfig().GetServerUri()]
	if !ok {
		store = s.memory
	}
	return store
}

// SessionGenerator is an interface for generating session data.
type SessionGenerator interface {
	GenerateSessionID() string
	GenerateNonce() string
	GenerateState() string
}

var (
	_ SessionGenerator = (*randomGenerator)(nil)
	_ SessionGenerator = (*staticGenerator)(nil)
)

type (
	// randomGenerator is a session generator that uses random strings.
	randomGenerator struct {
		rand *rand.Rand
	}

	// staticGenerator is a session generator that uses static strings.
	staticGenerator struct {
		sessionID string
		nonce     string
		state     string
	}
)

// NewRandomGenerator creates a new random session generator.
func NewRandomGenerator() SessionGenerator {
	return &randomGenerator{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (r randomGenerator) GenerateSessionID() string {
	return r.generate(64)
}

func (r randomGenerator) GenerateNonce() string {
	return r.generate(32)
}

func (r randomGenerator) GenerateState() string {
	return r.generate(32)
}

func (r *randomGenerator) generate(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.rand.Intn(len(charset))]
	}
	return string(b)
}

// NewStaticGenerator creates a new static session generator.
func NewStaticGenerator(sessionID, nonce, state string) SessionGenerator {
	return &staticGenerator{
		sessionID: sessionID,
		nonce:     nonce,
		state:     state,
	}
}

func (s staticGenerator) GenerateSessionID() string {
	return s.sessionID
}

func (s staticGenerator) GenerateNonce() string {
	return s.nonce
}

func (s staticGenerator) GenerateState() string {
	return s.state
}
