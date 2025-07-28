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
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	mockv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/mock"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal/watch"
)

func TestSessionStoreFactoryInit(t *testing.T) {
	redis1 := miniredis.RunT(t)
	redis2 := miniredis.RunT(t)

	config := &configv1.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    8080,
		LogLevel:      "debug",
		Threads:       1,
		Chains: []*configv1.FilterChain{
			{
				Name: "memory1",
				Filters: []*configv1.Filter{
					{Type: &configv1.Filter_Mock{Mock: &mockv1.MockConfig{}}},
					{Type: &configv1.Filter_Oidc{Oidc: &oidcv1.OIDCConfig{}}},
				},
			},
			{
				Name: "memory2",
				Filters: []*configv1.Filter{
					{Type: &configv1.Filter_Oidc{Oidc: &oidcv1.OIDCConfig{}}},
				},
			},
			{
				Name: "memory3",
				Filters: []*configv1.Filter{
					{Type: &configv1.Filter_Oidc{Oidc: &oidcv1.OIDCConfig{AbsoluteSessionTimeout: 5}}},
				},
			},
			{
				Name: "redis1",
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Oidc{
							Oidc: &oidcv1.OIDCConfig{
								RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: "redis://" + redis1.Addr()},
							},
						},
					},
				},
			},
			{
				Name: "redis2",
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Oidc{
							Oidc: &oidcv1.OIDCConfig{
								RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: "redis://" + redis2.Addr()},
							},
						},
					},
				},
			},
		},
	}

	store := NewSessionStoreFactory(config, noopWatcher{}).(*sessionStoreFactory)
	require.NoError(t, store.PreRun())

	require.NotNil(t, store.fallbackStore)
	require.Len(t, store.stores, 4) // 2 redis, 2 in-memory (from the 3 in-memory 2 share config and use the same store)

	require.Nil(t, store.Get(nil))
	require.IsType(t, &memoryStore{}, store.Get(&oidcv1.OIDCConfig{}))                       // returns the shared one as config is equivalent
	require.IsType(t, &memoryStore{}, store.Get(&oidcv1.OIDCConfig{IdleSessionTimeout: 10})) // return the fallback one
	require.IsType(t, &memoryStore{}, store.Get(config.Chains[0].Filters[1].GetOidc()))
	require.IsType(t, &memoryStore{}, store.Get(config.Chains[1].Filters[0].GetOidc()))
	require.IsType(t, &memoryStore{}, store.Get(config.Chains[2].Filters[0].GetOidc()))
	require.Same(t, store.Get(&oidcv1.OIDCConfig{}), store.Get(config.Chains[1].Filters[0].GetOidc()))
	require.Same(t, store.Get(config.Chains[0].Filters[1].GetOidc()), store.Get(config.Chains[1].Filters[0].GetOidc()))
	require.Equal(t, redis1.Addr(), store.Get(config.Chains[3].Filters[0].GetOidc()).(*redisStore).client.(*redis.Client).Options().Addr)
	require.Equal(t, redis2.Addr(), store.Get(config.Chains[4].Filters[0].GetOidc()).(*redisStore).client.(*redis.Client).Options().Addr)
}

func TestSessionStoreFactoryRedisInitFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetError("server error")

	config := &configv1.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    8080,
		LogLevel:      "debug",
		Threads:       1,
		Chains: []*configv1.FilterChain{
			{
				Name: "redis",
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Oidc{
							Oidc: &oidcv1.OIDCConfig{
								RedisSessionStoreConfig: &oidcv1.RedisConfig{ServerUri: "redis://" + mr.Addr()},
							},
						},
					},
				},
			},
		},
	}

	g := run.Group{}
	g.Register(NewSessionStoreFactory(config, noopWatcher{}))

	require.ErrorContains(t, g.Run(), "server error")
}

func TestSessionStoreFactoryRedisUpdate(t *testing.T) {
	ca, caKey, caPEM := testCA(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	serverCert, _, _ := testCertificate(t, "redis.example.com", ca, caKey)
	_, clientCertPEM, clientKeyPEM := testCertificate(t, "client.example.com", ca, caKey)

	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(tmp+"/ca.crt", caPEM, 0600))
	require.NoError(t, os.WriteFile(tmp+"/client.crt", clientCertPEM, 0600))
	require.NoError(t, os.WriteFile(tmp+"/client.key", clientKeyPEM, 0600))
	require.NoError(t, os.WriteFile(tmp+"/redis-password", []byte("redis-pass"), 0600))

	mr := miniredis.NewMiniRedis()
	mr.RequireUserAuth("authservice", "redis-pass")
	require.NoError(t, mr.StartTLS(&tls.Config{
		ClientCAs:    pool,
		Certificates: []tls.Certificate{serverCert},
		ServerName:   "redis.example.com",
	}))

	redisConfig := &oidcv1.RedisConfig{
		ServerUri:     "redis://" + mr.Addr(),
		Username:      "authservice",
		RedisPassword: &oidcv1.RedisConfig_PasswordFile{PasswordFile: tmp + "/redis-password"},
		TlsConfig: &oidcv1.RedisConfig_TLSConfig{
			Ca:         &oidcv1.RedisConfig_TLSConfig_TrustedCaFile{TrustedCaFile: tmp + "/ca.crt"},
			ClientCert: &oidcv1.RedisConfig_TLSConfig_ClientCertFile{ClientCertFile: tmp + "/client.crt"},
			ClientKey:  &oidcv1.RedisConfig_TLSConfig_ClientKeyFile{ClientKeyFile: tmp + "/client.key"},
		},
	}

	fileWatcher := watch.NewFileWatcher(watch.NewOpts())
	factory := NewSessionStoreFactory(&configv1.Config{
		Chains: []*configv1.FilterChain{
			{
				Filters: []*configv1.Filter{
					{
						Type: &configv1.Filter_Oidc{
							Oidc: &oidcv1.OIDCConfig{RedisSessionStoreConfig: redisConfig},
						},
					},
				},
			},
		},
	}, fileWatcher).(*sessionStoreFactory)

	// Verify that the files have been initialized
	require.Empty(t, redisConfig.GetPassword())
	require.Empty(t, redisConfig.GetTlsConfig().GetClientCertPem())
	require.Empty(t, redisConfig.GetTlsConfig().GetClientKeyPem())
	require.Empty(t, redisConfig.GetTlsConfig().GetTrustedCaPem())

	require.NoError(t, factory.PreRun())
	require.Equal(t, "redis-pass", redisConfig.GetPassword())
	require.Equal(t, string(clientCertPEM), redisConfig.GetTlsConfig().GetClientCertPem())
	require.Equal(t, string(clientKeyPEM), redisConfig.GetTlsConfig().GetClientKeyPem())
	require.Equal(t, string(caPEM), redisConfig.GetTlsConfig().GetTrustedCaPem())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = fileWatcher.Start(ctx.Done())
	}()

	// Set new values. This will cause a redis connect failure, but we don't care about that here.
	// We just want to verify that the values are updated
	require.NoError(t, os.WriteFile(tmp+"/redis-password", []byte("new-redis-pass"), 0600))
	require.NoError(t, os.WriteFile(tmp+"/client.crt", []byte("updated-client-cert"), 0600))
	require.NoError(t, os.WriteFile(tmp+"/client.key", []byte("updated-client-key"), 0600))
	require.NoError(t, os.WriteFile(tmp+"/ca.crt", []byte("updated-ca"), 0600))

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		factory.redisCallbackLock.Lock()
		defer factory.redisCallbackLock.Unlock()

		assert.Equal(t, "new-redis-pass", redisConfig.GetPassword())
		assert.Equal(t, "updated-client-cert", redisConfig.GetTlsConfig().GetClientCertPem())
		assert.Equal(t, "updated-client-key", redisConfig.GetTlsConfig().GetClientKeyPem())
		assert.Equal(t, "updated-ca", redisConfig.GetTlsConfig().GetTrustedCaPem())
	}, 30*time.Second, time.Second)
}

func TestSessionGenerator(t *testing.T) {
	t.Run("random", func(t *testing.T) {
		sg := NewRandomGenerator()
		require.NotEqual(t, sg.GenerateSessionID(), sg.GenerateSessionID())
		require.NotEqual(t, sg.GenerateState(), sg.GenerateState())
		require.NotEqual(t, sg.GenerateNonce(), sg.GenerateNonce())
		require.NotEqual(t, sg.GenerateCodeVerifier(), sg.GenerateCodeVerifier())
	})
	t.Run("static", func(t *testing.T) {
		sg := NewStaticGenerator("sessionid", "nonce", "state", "codeverifier")
		require.Equal(t, sg.GenerateSessionID(), sg.GenerateSessionID())
		require.Equal(t, sg.GenerateState(), sg.GenerateState())
		require.Equal(t, sg.GenerateNonce(), sg.GenerateNonce())
		require.Equal(t, sg.GenerateCodeVerifier(), sg.GenerateCodeVerifier())
		require.Equal(t, "sessionid", sg.GenerateSessionID())
		require.Equal(t, "state", sg.GenerateState())
		require.Equal(t, "nonce", sg.GenerateNonce())
		require.Equal(t, "codeverifier", sg.GenerateCodeVerifier())
	})
}

var _ watch.Callbacker = (*noopWatcher)(nil)

type noopWatcher struct{}

func (noopWatcher) Watch(string, ...watch.Callback) error { return nil }
