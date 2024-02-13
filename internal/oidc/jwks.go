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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

var (
	// ErrJWKSParse is returned when the JWKS document cannot be parsed.
	ErrJWKSParse = errors.New("error parsing JWKS document")
	// ErrJWKSFetch is returned when the JWKS document cannot be fetched.
	ErrJWKSFetch = errors.New("error fetching JWKS document")

	_ run.Service = (*DefaultJWKSProvider)(nil)
)

// JWKSProvider provides a JWKS set for a given OIDC configuration.
type JWKSProvider interface {
	// Get the JWKS for the given OIDC configuration
	Get(context.Context, *oidcv1.OIDCConfig) (jwk.Set, error)
}

// DefaultJWKSProvider provides a JWKS set
type DefaultJWKSProvider struct {
	log      telemetry.Logger
	cache    *jwk.AutoRefresh
	shutdown context.CancelFunc
}

// NewJWKSProvider returns a new JWKSProvider.
func NewJWKSProvider() *DefaultJWKSProvider {
	return &DefaultJWKSProvider{
		log: internal.Logger(internal.JWKS),
	}
}

// Name of the JWKSProvider run.Unit
func (j *DefaultJWKSProvider) Name() string { return "JWKS" }

// Serve implements run.Service
func (j *DefaultJWKSProvider) Serve() error {
	ctx, cancel := context.WithCancel(context.Background())
	j.shutdown = cancel

	ch := make(chan jwk.AutoRefreshError)
	j.cache = jwk.NewAutoRefresh(ctx)
	j.cache.ErrorSink(ch)

	for {
		select {
		case err := <-ch:
			j.log.Debug("jwks auto refresh error", "error", err)
		case <-ctx.Done():
			return nil
		}
	}
}

// GracefulStop implements run.Service
func (j *DefaultJWKSProvider) GracefulStop() {
	if j.shutdown != nil {
		j.shutdown()
	}
}

// Get the JWKS for the given OIDC configuration
func (j *DefaultJWKSProvider) Get(ctx context.Context, config *oidcv1.OIDCConfig) (jwk.Set, error) {
	if config.GetJwksFetcher() != nil {
		return j.fetchDynamic(ctx, config.GetJwksFetcher())
	}
	return j.fetchStatic(config.GetJwks())
}

// fetchDynamic fetches the JWKS from the given URI. If the JWKS URI is already know, the JWKS will be returned from
// the cache. Otherwise, the JWKS will be fetched from the URI and the cache will be configured to periodically
// refresh the JWKS.
func (j *DefaultJWKSProvider) fetchDynamic(ctx context.Context, config *oidcv1.OIDCConfig_JwksFetcherConfig) (jwk.Set, error) {
	if !j.cache.IsRegistered(config.JwksUri) {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.SkipVerifyPeerCert}
		client := &http.Client{Transport: transport}
		refreshInterval := time.Duration(config.PeriodicFetchIntervalSec) * time.Second

		j.cache.Configure(config.JwksUri,
			jwk.WithHTTPClient(client),
			jwk.WithRefreshInterval(refreshInterval),
		)
	}

	jwks, err := j.cache.Fetch(ctx, config.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	return jwks, nil
}

// fetchStatic parses the given raw JWKS document.
func (*DefaultJWKSProvider) fetchStatic(raw string) (jwk.Set, error) {
	jwks, err := jwk.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSParse, err)
	}
	return jwks, nil
}
