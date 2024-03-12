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
	"net/http"
	"time"

	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
)

var (
	// ErrJWKSParse is returned when the JWKS document cannot be parsed.
	ErrJWKSParse = errors.New("error parsing JWKS document")
	// ErrJWKSFetch is returned when the JWKS document cannot be fetched.
	ErrJWKSFetch = errors.New("error fetching JWKS document")

	_ run.ServiceContext = (*DefaultJWKSProvider)(nil)
)

// DefaultFetchInterval is the default interval to use when none is set.
const DefaultFetchInterval = 1200 * time.Second

// JWKSProvider provides a JWKS set for a given OIDC configuration.
type JWKSProvider interface {
	// Get the JWKS for the given OIDC configuration
	Get(context.Context, *oidcv1.OIDCConfig) (jwk.Set, error)
}

// DefaultJWKSProvider provides a JWKS set
type DefaultJWKSProvider struct {
	log     telemetry.Logger
	cache   *jwk.Cache
	config  *configv1.Config
	tlsPool internal.TLSConfigPool
	started chan struct{}
}

// NewJWKSProvider returns a new JWKSProvider.
func NewJWKSProvider(cfg *configv1.Config, tlsPool internal.TLSConfigPool) *DefaultJWKSProvider {
	return &DefaultJWKSProvider{
		log:     internal.Logger(internal.JWKS),
		config:  cfg,
		tlsPool: tlsPool,
		started: make(chan struct{}),
	}
}

// Name of the JWKSProvider run.Unit
func (j *DefaultJWKSProvider) Name() string { return "JWKS" }

func (j *DefaultJWKSProvider) ServeContext(ctx context.Context) error {
	errSink := httprc.ErrSinkFunc(func(err error) {
		j.log.Debug("jwks auto refresh error", "error", err)
	})
	j.cache = jwk.NewCache(ctx,
		jwk.WithErrSink(errSink),
		jwk.WithRefreshWindow(getRefreshWindow(j.config)),
	)

	close(j.started) // signal channel start
	<-ctx.Done()
	return nil
}

// Get the JWKS for the given OIDC configuration
func (j *DefaultJWKSProvider) Get(ctx context.Context, config *oidcv1.OIDCConfig) (jwk.Set, error) {
	if config.GetJwksFetcher() != nil {
		<-j.started // wait until the service is fully started
		return j.fetchDynamic(ctx, config)
	}
	return j.fetchStatic(config.GetJwks())
}

// fetchDynamic fetches the JWKS from the given URI. If the JWKS URI is already know, the JWKS will be returned from
// the cache. Otherwise, the JWKS will be fetched from the URI and the cache will be configured to periodically
// refresh the JWKS.
func (j *DefaultJWKSProvider) fetchDynamic(ctx context.Context, config *oidcv1.OIDCConfig) (jwk.Set, error) {
	log := j.log.Context(ctx)
	jwksConfig := config.GetJwksFetcher()

	if !j.cache.IsRegistered(jwksConfig.JwksUri) {
		transport := http.DefaultTransport.(*http.Transport).Clone()

		var err error
		if transport.TLSClientConfig, err = j.tlsPool.LoadTLSConfig(config); err != nil {
			return nil, fmt.Errorf("error loading TLS config: %w", err)
		}

		client := &http.Client{Transport: transport}
		refreshInterval := time.Duration(jwksConfig.PeriodicFetchIntervalSec) * time.Second
		if refreshInterval == 0 {
			refreshInterval = DefaultFetchInterval
		}

		log.Info("configuring JWKS auto refresh", "jwks", jwksConfig.JwksUri, "interval", refreshInterval, "skip_verify", config.GetSkipVerifyPeerCert())

		if err = j.cache.Register(jwksConfig.JwksUri,
			jwk.WithHTTPClient(client),
			jwk.WithRefreshInterval(refreshInterval),
		); err != nil {
			return nil, fmt.Errorf("error registering JWKS: %w", err)
		}
	}

	log.Debug("fetching JWKS", "jwks", jwksConfig.JwksUri)

	jwks, err := j.cache.Get(ctx, jwksConfig.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	return jwks, nil
}

// fetchStatic parses the given raw JWKS document.
func (j *DefaultJWKSProvider) fetchStatic(raw string) (jwk.Set, error) {
	j.log.Debug("parsing static JWKS", "jwks", raw)

	jwks, err := jwk.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSParse, err)
	}
	return jwks, nil
}

// getRefreshWindow returns the smallest refresh window for all the OIDC configurations.
// This is needed because the cache needs to be initialized with a default window small enough to
// accommodate all the configured intervals.
func getRefreshWindow(cfg *configv1.Config) time.Duration {
	refreshWindow := DefaultFetchInterval

	for _, fc := range cfg.Chains {
		for _, f := range fc.Filters {
			if f.GetOidc() == nil {
				continue
			}

			interval := time.Duration(f.GetOidc().GetJwksFetcher().GetPeriodicFetchIntervalSec()) * time.Second
			if interval > 0 && interval < refreshWindow {
				refreshWindow = interval
			}
		}
	}

	return refreshWindow
}
