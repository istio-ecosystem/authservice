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
	"context"
	"sync"
	"time"

	"github.com/tetratelabs/telemetry"

	"github.com/istio-ecosystem/authservice/internal"
)

var _ SessionStore = (*memoryStore)(nil)

// memoryStore is an in-memory implementation of the SessionStore interface.
type memoryStore struct {
	log                    telemetry.Logger
	clock                  *Clock
	absoluteSessionTimeout time.Duration
	idleSessionTimeout     time.Duration

	mu       sync.Mutex
	sessions map[string]*session
}

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore(clock *Clock, absoluteSessionTimeout, idleSessionTimeout time.Duration) SessionStore {
	return &memoryStore{
		log:                    internal.Logger(internal.Session).With("type", "memory"),
		clock:                  clock,
		absoluteSessionTimeout: absoluteSessionTimeout,
		idleSessionTimeout:     idleSessionTimeout,
		sessions:               make(map[string]*session),
	}
}

func (m *memoryStore) SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *TokenResponse) error {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("setting token response", "token_response", tokenResponse)

	m.set(ctx, sessionID, func(s *session) {
		s.tokenResponse = tokenResponse
	})
	return nil
}

func (m *memoryStore) GetTokenResponse(ctx context.Context, sessionID string) (*TokenResponse, error) {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("getting token response")

	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s == nil {
		return nil, nil
	}

	log.Debug("token response", "token_response", s.tokenResponse)
	s.accessed = m.clock.Now()
	return s.tokenResponse, nil
}

func (m *memoryStore) SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *AuthorizationState) error {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("setting authorization state", "state", authorizationState)

	m.set(ctx, sessionID, func(s *session) {
		s.authorizationState = authorizationState
	})
	return nil
}

func (m *memoryStore) GetAuthorizationState(ctx context.Context, sessionID string) (*AuthorizationState, error) {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("getting authorization state")

	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s == nil {
		return nil, nil
	}

	log.Debug("authorization state", "state", s.authorizationState)
	s.accessed = m.clock.Now()
	return s.authorizationState, nil
}

func (m *memoryStore) ClearAuthorizationState(ctx context.Context, sessionID string) error {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("clearing authorization state")

	m.mu.Lock()
	defer m.mu.Unlock()

	if s := m.sessions[sessionID]; s != nil {
		s.accessed = m.clock.Now()
		s.authorizationState = nil
	}

	return nil
}

func (m *memoryStore) RemoveSession(ctx context.Context, sessionID string) error {
	log := m.log.Context(ctx).With("session-id", sessionID)
	log.Debug("removing session")

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)

	return nil
}

func (m *memoryStore) RemoveAllExpired(ctx context.Context) error {
	log := m.log.Context(ctx)
	log.Debug("removing expired sessions")

	var (
		earliestTimeAddedToKeep    = m.clock.Now().Add(-m.absoluteSessionTimeout)
		earliestTimeIdleToKeep     = m.clock.Now().Add(-m.idleSessionTimeout)
		shouldCheckAbsoluteTimeout = m.absoluteSessionTimeout > 0
		shouldCheckIdleTimeout     = m.idleSessionTimeout > 0
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	for sessionID, s := range m.sessions {
		expiredBasedOnTimeAdded := shouldCheckAbsoluteTimeout && s.added.Before(earliestTimeAddedToKeep)
		expiredBasedOnIdleTime := shouldCheckIdleTimeout && s.accessed.Before(earliestTimeIdleToKeep)

		if expiredBasedOnTimeAdded || expiredBasedOnIdleTime {
			log.Debug("removing expired session", "session-id", sessionID)
			delete(m.sessions, sessionID)
		}
	}

	return nil
}

// set the given session with the given setter function and record the access time.
func (m *memoryStore) set(ctx context.Context, sessionID string, setter func(s *session)) {
	log := m.log.Context(ctx).With("session-id", sessionID)

	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s != nil {
		s.accessed = m.clock.Now()
		setter(s)
	} else {
		s = newSession(m.clock.Now())
		setter(s)
		m.sessions[sessionID] = s
	}

	log.Debug("updating last access", "accessed", s.accessed)
}

// session holds the data of a session stored in the in-memory cache
type session struct {
	tokenResponse      *TokenResponse
	authorizationState *AuthorizationState
	added              time.Time
	accessed           time.Time
}

// newSession creates a new session with the given creation time.
func newSession(t time.Time) *session {
	return &session{
		added:    t,
		accessed: t,
	}
}
