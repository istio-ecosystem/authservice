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
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

func TestSessionStoreFactory(t *testing.T) {
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

	store := SessionStoreFactory{Config: config}
	g := run.Group{Logger: telemetry.NoopLogger()}
	g.Register(&store)
	require.NoError(t, g.Run())

	require.NotNil(t, store.memory)
	require.Len(t, store.redis, 2)

	require.Nil(t, store.Get(nil))
	require.IsType(t, &memoryStore{}, store.Get(&oidcv1.OIDCConfig{}))
	require.IsType(t, &memoryStore{}, store.Get(config.Chains[0].Filters[1].GetOidc()))
	require.IsType(t, &memoryStore{}, store.Get(config.Chains[1].Filters[0].GetOidc()))
	require.Equal(t, redis1.Addr(), store.Get(config.Chains[2].Filters[0].GetOidc()).(*redisStore).client.(*redis.Client).Options().Addr)
	require.Equal(t, redis2.Addr(), store.Get(config.Chains[3].Filters[0].GetOidc()).(*redisStore).client.(*redis.Client).Options().Addr)
}

func TestSessionStoreFactoryRedisFails(t *testing.T) {
	mr := miniredis.RunT(t)
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

	store := SessionStoreFactory{Config: config}
	g := run.Group{Logger: telemetry.NoopLogger()}
	g.Register(&store)

	mr.SetError("server error")
	require.ErrorContains(t, g.Run(), "server error")
}
