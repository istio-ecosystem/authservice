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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
	inthttp "github.com/istio-ecosystem/authservice/internal/http"
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
	log            telemetry.Logger
	cache          *jwk.Cache
	config         *configv1.Config
	tlsPool        inthttp.TLSConfigPool
	started        chan struct{}
	serviceContext context.Context
}

// NewJWKSProvider returns a new JWKSProvider.
func NewJWKSProvider(cfg *configv1.Config, tlsPool inthttp.TLSConfigPool) *DefaultJWKSProvider {
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
	j.serviceContext = ctx
	errSink := httprc.ErrSinkFunc(func(err error) {
		log := j.log.With("operation", "jwks_refresh")
		var refresh *httprc.RefreshError
		if errors.As(err, &refresh) {
			if endpoint, parseErr := url.Parse(refresh.URL); parseErr == nil {
				log = log.With("dependency", endpoint.Host)
			}
			err = refresh.Err
		}
		_ = internal.LogRequestError(ctx, log, "JWKS auto refresh failed", err)
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
		select {
		case <-j.started: // wait until the service is fully started
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// The cache worker can stop before replying to a lookup during shutdown.
		// Let either the caller or the service release the waiting lookup.
		fetchContext, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(j.serviceContext, cancel)
		defer stop()
		defer cancel()
		return j.fetchDynamic(fetchContext, config)
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
		client, err := inthttp.NewHTTPClient(config, j.tlsPool, internal.Logger(internal.IDP))
		if err != nil {
			return nil, err
		}

		refreshInterval := time.Duration(jwksConfig.PeriodicFetchIntervalSec) * time.Second
		if refreshInterval == 0 {
			refreshInterval = DefaultFetchInterval
		}

		log.Info("configuring JWKS auto refresh", "interval", refreshInterval, "skip_verify", config.GetSkipVerifyPeerCert())

		if err = j.cache.Register(jwksConfig.JwksUri,
			jwk.WithHTTPClient(jwksHTTPClient{client: client, ctx: j.serviceContext}),
			jwk.WithRefreshInterval(refreshInterval),
		); err != nil {
			return nil, fmt.Errorf("error registering JWKS: %w", err)
		}
	}

	log.Debug("fetching JWKS")

	jwks, err := j.cache.Get(ctx, jwksConfig.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	return jwks, nil
}

// jwksHTTPClient supplies the service context to the cache library's Get calls.
// Shared fetches can outlive one caller, but must stop when the service stops.
type jwksHTTPClient struct {
	client *http.Client
	ctx    context.Context
}

func (c jwksHTTPClient) Get(uri string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

// fetchStatic parses the given raw JWKS document.
func (j *DefaultJWKSProvider) fetchStatic(raw string) (jwk.Set, error) {
	j.log.Debug("parsing static JWKS")

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
