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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"golang.org/x/oauth2"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
	watcher "github.com/istio-ecosystem/authservice/internal/watch"
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
		run.Config
		run.PreRunner
		run.ServiceContext
		SessionStoreFactory
	}
)

var _ SessionStoreFactoryUnit = (*sessionStoreFactory)(nil)

// SessionStoreFactory is a factory for creating session stores.
// It uses the OIDC configuration to determine which store to use.
type sessionStoreFactory struct {
	log           telemetry.Logger
	config        *configv1.Config
	clock         *Clock
	fallbackStore SessionStore

	fileWatcher            watcher.Watcher
	periodicReloadInterval time.Duration

	mu     sync.RWMutex
	stores map[string]SessionStore
}

// NewSessionStoreFactory creates a factory for managing session stores.
// It uses the OIDC configuration to determine which store to use.
func NewSessionStoreFactory(cfg *configv1.Config) SessionStoreFactoryUnit {
	clock := &Clock{}
	return &sessionStoreFactory{
		config:        cfg,
		clock:         clock,
		fallbackStore: NewMemoryStore(clock, 0, 0),
		stores:        make(map[string]SessionStore),
	}
}

// Name implements run.Unit.
func (s *sessionStoreFactory) Name() string { return "OIDC session store factory" }

// FlagSet returns the flags used to customize the config file location.
func (s *sessionStoreFactory) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("Session Store flags")
	flags.DurationVar(&s.periodicReloadInterval, "periodic-reload-interval", 0,
		"Interval for periodic reload of watched files. A value of 0 disables periodic reload.")
	return flags
}

// Validate and load the configuration file.
func (s *sessionStoreFactory) Validate() error { return nil }

// PreRun initializes the stores that are defined in the configuration
func (s *sessionStoreFactory) PreRun() error {
	s.log = internal.Logger(internal.Session)

	var opts []watcher.OptionFunc
	if s.periodicReloadInterval > 0 {
		opts = append(opts, watcher.WithFallbackTimeout(s.periodicReloadInterval))
	} else {
		opts = append(opts, watcher.WithSkipFallback())
	}
	s.fileWatcher = watcher.NewFileWatcher(watcher.NewOpts(opts...))

	for _, fc := range s.config.Chains {
		for _, f := range fc.Filters {
			if f.GetOidc() == nil {
				continue
			}

			if f.GetOidc().GetRedisSessionStoreConfig() != nil {
				if err := s.initializeRedisFileWatchers(f.GetOidc()); err != nil {
					return err
				}
				if err := s.loadRedisConfig(f.GetOidc()); err != nil {
					return err
				}
			} else {
				key := hashInMemoryConfig(f.GetOidc())
				s.log.Info("configuring in-memory session store", "key", key, "client-id", f.GetOidc().GetClientId())
				s.setSessionStore(key, NewMemoryStore(s.clock,
					time.Duration(f.GetOidc().GetAbsoluteSessionTimeout())*time.Second,
					time.Duration(f.GetOidc().GetIdleSessionTimeout())*time.Second,
				))
			}
		}
	}

	return nil
}

// ServeContext watches for configuration changes and updates the session stores accordingly.
func (s *sessionStoreFactory) ServeContext(ctx context.Context) error {
	if err := s.fileWatcher.Start(ctx.Done()); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// loadRedisConfig loads the Redis configuration from the OIDCConfig and initializes or updates
// the Redis session store.
func (s *sessionStoreFactory) loadRedisConfig(cfg *oidcv1.OIDCConfig) error {
	s.log.Info("configuring redis session store",
		"redis-url", cfg.GetRedisSessionStoreConfig().GetServerUri(),
		"client-id", cfg.GetClientId(),
	)
	client, err := NewRedisClient(cfg.GetRedisSessionStoreConfig())
	if err != nil {
		return err
	}
	r, err := NewRedisStore(s.clock, client,
		time.Duration(cfg.GetAbsoluteSessionTimeout())*time.Second,
		time.Duration(cfg.GetIdleSessionTimeout())*time.Second,
	)
	if err != nil {
		return err
	}
	s.setSessionStore(cfg.GetRedisSessionStoreConfig().GetServerUri(), r)
	return nil
}

// initializeRedisFileWatchers initializes the Redis configuration by reading the necessary files.
func (s *sessionStoreFactory) initializeRedisFileWatchers(cfg *oidcv1.OIDCConfig) error {
	var (
		errs     []error
		redisCfg = cfg.GetRedisSessionStoreConfig()
		log      = s.log.With("redis-url", redisCfg.GetServerUri())
	)

	if pf := redisCfg.GetPasswordFile(); pf != "" {
		password, err := os.ReadFile(pf)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read redis password file: %w", err))
		} else {
			callback := func(value []byte) {
				redisCfg.RedisPassword = &oidcv1.RedisConfig_Password{
					Password: string(value),
				}
			}
			callback(password) // Set the field immediately when initializing
			fl := log.With("field", "password")
			errs = append(errs, s.fileWatcher.Watch(pf, s.redisCallBack(fl, cfg, callback)))
		}
	}
	if cf := redisCfg.GetTlsConfig().GetClientCertFile(); cf != "" {
		clientCert, err := os.ReadFile(cf)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read redis client cert file: %w", err))
		} else {
			callback := func(value []byte) {
				redisCfg.TlsConfig.ClientCert = &oidcv1.RedisConfig_TLSConfig_ClientCertPem{
					ClientCertPem: string(value),
				}
			}
			callback(clientCert) // Set the field immediately when initializing
			fl := log.With("field", "client-cert")
			errs = append(errs, s.fileWatcher.Watch(cf, s.redisCallBack(fl, cfg, callback)))
		}
	}
	if kf := redisCfg.GetTlsConfig().GetClientKeyFile(); kf != "" {
		clientKey, err := os.ReadFile(kf)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read redis client key file: %w", err))
		} else {
			callback := func(value []byte) {
				redisCfg.TlsConfig.ClientKey = &oidcv1.RedisConfig_TLSConfig_ClientKeyPem{
					ClientKeyPem: string(value),
				}
			}
			callback(clientKey) // Set the field immediately when initializing
			fl := log.With("field", "client-cert")
			errs = append(errs, s.fileWatcher.Watch(kf, s.redisCallBack(fl, cfg, callback)))
		}
	}
	if caf := redisCfg.GetTlsConfig().GetTrustedCaFile(); caf != "" {
		trustedCA, err := os.ReadFile(caf)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read redis trusted CA file: %w", err))
		} else {
			callback := func(value []byte) {
				redisCfg.TlsConfig.Ca = &oidcv1.RedisConfig_TLSConfig_TrustedCaPem{
					TrustedCaPem: string(value),
				}
			}
			callback(trustedCA) // Set the field immediately when initializing
			fl := log.With("field", "ca")
			errs = append(errs, s.fileWatcher.Watch(caf, s.redisCallBack(fl, cfg, callback)))
		}
	}

	return errors.Join(errs...)
}

// redisCallBack returns a callback function that updates the Redis configuration
func (s *sessionStoreFactory) redisCallBack(log telemetry.Logger, cfg *oidcv1.OIDCConfig, update func(value []byte)) watcher.Callback {
	return func(data watcher.Data) {
		if data.Err != nil {
			log.Error("updating redis config", data.Err)
			return
		}
		update(data.Value.(watcher.FileValue).Data)
		if err := s.loadRedisConfig(cfg); err != nil {
			log.Error("reloading redis config", err)
		}
	}
}

// Get returns the appropriate session store for the given OIDC configuration.
func (s *sessionStoreFactory) Get(cfg *oidcv1.OIDCConfig) SessionStore {
	if cfg == nil {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := cfg.GetRedisSessionStoreConfig().GetServerUri()
	kind := "redis"
	if key == "" {
		key = hashInMemoryConfig(cfg)
		kind = "memory"
	}

	store, ok := s.stores[key]
	if !ok {
		s.log.Info("session store not available. using the fallback in-memory store", "key", key, "kind", kind)
		return s.fallbackStore
	}
	return store
}

// setSessionStore sets the session store for the given key.
func (s *sessionStoreFactory) setSessionStore(key string, store SessionStore) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stores[key] = store
}

// hashInMemoryConfig generates a hash for the in-memory session configuration.
// It takes the properties that define the session store so that in-memory configurations that
// are equivalent will use the same instance of the store.
func hashInMemoryConfig(cfg *oidcv1.OIDCConfig) string {
	buff := bytes.Buffer{}
	_, _ = buff.WriteString("memory")
	_, _ = buff.WriteString(fmt.Sprintf("%v", cfg.GetAbsoluteSessionTimeout()))
	_, _ = buff.WriteString(fmt.Sprintf("%v", cfg.GetIdleSessionTimeout()))

	hash := fnv.New64a()
	_, _ = hash.Write(buff.Bytes())
	out := hash.Sum(make([]byte, 0, 15))

	return hex.EncodeToString(out)
}

// SessionGenerator is an interface for generating session data.
type SessionGenerator interface {
	GenerateSessionID() string
	GenerateNonce() string
	GenerateState() string
	GenerateCodeVerifier() string
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
		sessionID    string
		nonce        string
		state        string
		codeVerifier string
	}
)

// NewRandomGenerator creates a new random session generator.
func NewRandomGenerator() SessionGenerator {
	return &randomGenerator{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (r *randomGenerator) GenerateSessionID() string {
	return r.generate(64)
}

func (r *randomGenerator) GenerateNonce() string {
	return r.generate(32)
}

func (r *randomGenerator) GenerateState() string {
	return r.generate(32)
}

func (r *randomGenerator) GenerateCodeVerifier() string {
	return oauth2.GenerateVerifier()
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
func NewStaticGenerator(sessionID, nonce, state, codeVerifier string) SessionGenerator {
	return &staticGenerator{
		sessionID:    sessionID,
		nonce:        nonce,
		state:        state,
		codeVerifier: codeVerifier,
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

func (s staticGenerator) GenerateCodeVerifier() string {
	return s.codeVerifier
}
