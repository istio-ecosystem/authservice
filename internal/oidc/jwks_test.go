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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/types/known/structpb"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

// nolint: lll
var (
	keys = `
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
      "n":
      "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
      "n":
      "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    }
  ]
}
`

	singleKey = `
{
  "kty": "RSA",
  "alg": "RS256",
  "use": "sig",
  "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
  "n":
  "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
  "e": "AQAB"
}
`
)

func TestStaticJWKSProvider(t *testing.T) {
	tlsPool := internal.NewTLSConfigPool(context.Background())

	t.Run("invalid", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cache := NewJWKSProvider(tlsPool)
		go func() { require.NoError(t, cache.ServeContext(ctx)) }()
		t.Cleanup(cancel)

		_, err := cache.Get(context.Background(), &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_Jwks{
				Jwks: "{aaa}",
			},
		})

		require.ErrorIs(t, err, ErrJWKSParse)
	})

	t.Run("single-key", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cache := NewJWKSProvider(tlsPool)
		go func() { require.NoError(t, cache.ServeContext(ctx)) }()
		t.Cleanup(cancel)

		jwks, err := cache.Get(context.Background(), &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_Jwks{
				Jwks: singleKey,
			},
		})

		require.NoError(t, err)
		require.Equal(t, 1, jwks.Len())

		key, ok := jwks.Get(0)
		require.True(t, ok)
		require.Equal(t, "RS256", key.Algorithm())
		require.Equal(t, jwa.KeyType("RSA"), key.KeyType())
		require.Equal(t, "62a93512c9ee4c7f8067b5a216dade2763d32a47", key.KeyID())
	})

	t.Run("multiple-keys", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cache := NewJWKSProvider(tlsPool)
		go func() { require.NoError(t, cache.ServeContext(ctx)) }()
		t.Cleanup(cancel)

		jwks, err := cache.Get(context.Background(), &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_Jwks{
				Jwks: keys,
			},
		})

		require.NoError(t, err)
		require.Equal(t, 2, jwks.Len())

		key, ok := jwks.Get(0)
		require.True(t, ok)
		require.Equal(t, "RS256", key.Algorithm())
		require.Equal(t, jwa.KeyType("RSA"), key.KeyType())
		require.Equal(t, "62a93512c9ee4c7f8067b5a216dade2763d32a47", key.KeyID())

		key, ok = jwks.Get(1)
		require.True(t, ok)
		require.Equal(t, "RS256", key.Algorithm())
		require.Equal(t, jwa.KeyType("RSA"), key.KeyType())
		require.Equal(t, "b3319a147514df7ee5e4bcdee51350cc890cc89e", key.KeyID())
	})
}

func TestDynamicJWKSProvider(t *testing.T) {
	var (
		pub  = newKey(t)
		jwks = newKeySet(pub)

		tlsPool  = internal.NewTLSConfigPool(context.Background())
		newCache = func(t *testing.T) JWKSProvider {
			cache := NewJWKSProvider(tlsPool)
			g := run.Group{Logger: telemetry.NoopLogger()}
			g.Register(cache)
			go func() { _ = g.Run() }()

			// Block until the cache is initialized
			<-cache.started
			return cache
		}
	)

	t.Run("invalid url", func(t *testing.T) {
		server := newTestServer(t, jwks)
		cache := newCache(t)

		config := &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
				JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{
					JwksUri: server.URL + "/not-found",
				},
			},
		}

		_, err := cache.Get(context.Background(), config)

		require.ErrorIs(t, err, ErrJWKSFetch)
		require.Equal(t, int32(1), atomic.LoadInt32(server.requestCount)) // The attempt to load the JWKS is made, but fails
	})

	t.Run("cache load", func(t *testing.T) {
		server := newTestServer(t, jwks)
		cache := newCache(t)

		config := &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
				JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{
					JwksUri:                  server.URL,
					PeriodicFetchIntervalSec: 1,
				},
			},
			SkipVerifyPeerCert: structpb.NewBoolValue(true),
		}

		keys, err := cache.Get(context.Background(), config)
		require.NoError(t, err)
		require.Equal(t, jwks, keys)
		require.Equal(t, int32(1), atomic.LoadInt32(server.requestCount))
	})

	t.Run("cached results", func(t *testing.T) {
		server := newTestServer(t, jwks)
		cache := newCache(t)

		config := &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
				JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{
					JwksUri:                  server.URL,
					PeriodicFetchIntervalSec: 60,
				},
			},
		}

		for i := 0; i < 5; i++ {
			keys, err := cache.Get(context.Background(), config)
			require.NoError(t, err)
			require.Equal(t, jwks, keys)
			require.Equal(t, int32(1), atomic.LoadInt32(server.requestCount)) // Cached results after the first request
		}
	})

	t.Run("cache refresh", func(t *testing.T) {
		server := newTestServer(t, jwks)
		cache := newCache(t)

		config := &oidcv1.OIDCConfig{
			JwksConfig: &oidcv1.OIDCConfig_JwksFetcher{
				JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{
					JwksUri:                  server.URL,
					PeriodicFetchIntervalSec: 1,
				},
			},
		}

		// Load the entry in the cache and remove it to let the background refresher refresh it
		_, err := cache.Get(context.Background(), config)
		require.NoError(t, err)
		jwks.Remove(pub)

		// Wait for the refresh period and check that the JWKS has been refreshed
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(server.requestCount) > 1
		}, 3*time.Second, 1*time.Second)
	})
}

type server struct {
	*httptest.Server
	requestCount *int32
}

func newTestServer(t *testing.T, jwks jwk.Set) *server {
	s := &server{requestCount: new(int32)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(s.requestCount, 1)

		if strings.HasSuffix(req.URL.Path, "/not-found") {
			res.WriteHeader(404)
			return
		}

		bytes, err := json.Marshal(jwks)
		require.NoError(t, err)
		res.WriteHeader(200)
		_, _ = res.Write(bytes)
	}))
	t.Cleanup(func() { atomic.StoreInt32(s.requestCount, 0) })
	t.Cleanup(s.Close)
	return s
}

const keyID = "test"

func newKeySet(keys ...jwk.Key) jwk.Set {
	jwks := jwk.NewSet()
	for _, k := range keys {
		jwks.Add(k)
	}
	return jwks
}

func newKey(t *testing.T) jwk.Key {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub, err := jwk.New(rsaKey.PublicKey)
	require.NoError(t, err)

	err = pub.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)
	err = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(t, err)

	return pub
}
