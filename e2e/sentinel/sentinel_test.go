// Copyright 2026 Tetrate
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

package sentinel

import (
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/e2e"
	"github.com/istio-ecosystem/authservice/internal/oidc"
)

const (
	sentinelAddr  = "localhost:26379"
	sentinelUser  = "sentinel-user"
	sentinelPass  = "sentinel-pass"
	masterName    = "mymaster"
	masterService = "redis-master"
)

var redisConfig = &oidcv1.RedisConfig{
	ServerUri:              "redis+sentinel://" + sentinelAddr + "?master_name=" + masterName,
	SentinelUsername:       sentinelUser,
	SentinelPasswordConfig: &oidcv1.RedisConfig_SentinelPassword{SentinelPassword: sentinelPass},
}

func TestSentinelRequiresAuthentication(t *testing.T) {
	client, err := oidc.NewRedisClient(&oidcv1.RedisConfig{ServerUri: redisConfig.ServerUri})
	require.NoError(t, err)

	_, err = oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.ErrorContains(t, err, "NOAUTH")
}

func TestSentinelStore(t *testing.T) {
	client, err := oidc.NewRedisClient(redisConfig)
	require.NoError(t, err)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := t.Context()

	as, err := store.GetAuthorizationState(ctx, "s1")
	require.NoError(t, err)
	require.Nil(t, as)

	// Create a session and verify it can be read back
	as = &oidc.AuthorizationState{
		State:        "state",
		Nonce:        "nonce",
		RequestedURL: "https://example.com",
		CodeVerifier: "code_verifier",
	}
	require.NoError(t, store.SetAuthorizationState(ctx, "s1", as))

	got, err := store.GetAuthorizationState(ctx, "s1")
	require.NoError(t, err)
	require.Equal(t, as, got)

	// Verify that the session TTL has been set
	ttl := client.TTL(ctx, "s1").Val()
	require.Greater(t, ttl, time.Duration(0))
}

func TestSentinelFailover(t *testing.T) {
	waitForHealthyReplica(t)

	client, err := oidc.NewRedisClient(redisConfig)
	require.NoError(t, err)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := t.Context()

	as := &oidc.AuthorizationState{
		State:        "state",
		Nonce:        "nonce",
		RequestedURL: "https://example.com",
		CodeVerifier: "code_verifier",
	}
	require.NoError(t, store.SetAuthorizationState(ctx, "before-failover", as))

	// Make sure the write has reached the replica before the master goes away
	acked, err := client.(*redis.Client).Do(ctx, "WAIT", 1, 2000).Int()
	require.NoError(t, err)
	require.GreaterOrEqual(t, acked, 1)

	docker := e2e.NewDockerCompose(e2e.WithDockerComposeLogFunc(t.Log))
	require.NoError(t, docker.StopDockerService(masterService))
	t.Cleanup(func() { require.NoError(t, docker.StartDockerService(masterService)) })

	// Writes fail until the sentinel promotes the replica and the failover client picks
	// up the new master; with a standalone client this would never recover
	require.Eventually(t, func() bool {
		return store.SetAuthorizationState(ctx, "after-failover", as) == nil
	}, 30*time.Second, 1*time.Second)

	// Sessions written before the failover survive it
	got, err := store.GetAuthorizationState(ctx, "before-failover")
	require.NoError(t, err)
	require.Equal(t, as, got)
}

// waitForHealthyReplica blocks until the sentinel reports a healthy replica for the
// monitored master, so that a failover has a candidate to promote.
func waitForHealthyReplica(t *testing.T) {
	sentinel := redis.NewSentinelClient(&redis.Options{Addr: sentinelAddr, Username: sentinelUser, Password: sentinelPass})
	t.Cleanup(func() { _ = sentinel.Close() })

	require.Eventually(t, func() bool {
		replicas, err := sentinel.Replicas(t.Context(), masterName).Result()
		if err != nil || len(replicas) == 0 {
			return false
		}
		for _, replica := range replicas {
			if strings.Contains(replica["flags"], "down") || replica["master-link-status"] != "ok" {
				return false
			}
		}
		return true
	}, 30*time.Second, 500*time.Millisecond)
}
