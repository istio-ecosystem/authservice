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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
)

func TestRedisAuth(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	mr.RequireUserAuth("redis-user", "redis-pass")
	require.NoError(t, mr.Start())

	t.Run("missing-credentials", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "NOAUTH")
	})

	t.Run("invalid-credentials", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri:     "redis://" + mr.Addr(),
			Username:      "redis-user",
			RedisPassword: &oidc.RedisConfig_Password{Password: "wrong-pass"},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "WRONGPASS")
	})

	t.Run("valid-credentials", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri:     "redis://" + mr.Addr(),
			Username:      "redis-user",
			RedisPassword: &oidc.RedisConfig_Password{Password: "redis-pass"},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.NoError(t, err)
	})
}

func TestRedisTLS(t *testing.T) {
	mr := miniredis.NewMiniRedis()

	ca, caKey, caPEM := testCA(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	serverCert, _, _ := testCertificate(t, "redis.example.com", ca, caKey)

	require.NoError(t, mr.StartTLS(&tls.Config{
		ClientCAs:    pool,
		Certificates: []tls.Certificate{serverCert},
		ServerName:   "redis.example.com",
	}))

	t.Run("plain-text", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "EOF")
	})

	t.Run("untrusted", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri: "redis://" + mr.Addr(),
			TlsConfig: &oidc.RedisConfig_TLSConfig{},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "certificate is not trusted")
	})

	t.Run("skip-verify", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri: "redis://" + mr.Addr(),
			TlsConfig: &oidc.RedisConfig_TLSConfig{
				SkipVerifyPeerCert: true,
			},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.NoError(t, err)
	})

	t.Run("tls", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri: "redis://" + mr.Addr(),
			TlsConfig: &oidc.RedisConfig_TLSConfig{
				Ca: &oidc.RedisConfig_TLSConfig_TrustedCaPem{TrustedCaPem: string(caPEM)},
			},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.NoError(t, err)
	})
}

func TestRedisMTLS(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	mr.RequireUserAuth("redis-user", "redis-pass")

	ca, caKey, caPEM := testCA(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	serverCert, _, _ := testCertificate(t, "redis.example.com", ca, caKey)

	require.NoError(t, mr.StartTLS(&tls.Config{
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		ServerName:   "redis.example.com",
	}))

	t.Run("missing-certificate", func(t *testing.T) {
		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri:     "redis://" + mr.Addr(),
			Username:      "redis-user",
			RedisPassword: &oidc.RedisConfig_Password{Password: "redis-pass"},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "EOF")
	})

	t.Run("untrusted-certificate", func(t *testing.T) {
		_, _, alternateCA := testCA(t)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(alternateCA)

		_, certPEM, keyPEM := testCertificate(t, "client.example.com", ca, caKey)

		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri:     "redis://" + mr.Addr(),
			Username:      "redis-user",
			RedisPassword: &oidc.RedisConfig_Password{Password: "redis-pass"},
			TlsConfig: &oidc.RedisConfig_TLSConfig{
				Ca:         &oidc.RedisConfig_TLSConfig_TrustedCaPem{TrustedCaPem: string(alternateCA)},
				ClientCert: &oidc.RedisConfig_TLSConfig_ClientCertPem{ClientCertPem: string(certPEM)},
				ClientKey:  &oidc.RedisConfig_TLSConfig_ClientKeyPem{ClientKeyPem: string(keyPEM)},
			},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.ErrorContains(t, err, "certificate signed by unknown authority")
	})

	t.Run("ok", func(t *testing.T) {
		_, certPEM, keyPEM := testCertificate(t, "client.example.com", ca, caKey)

		client, err := NewRedisClient(&oidc.RedisConfig{
			ServerUri:     "redis://" + mr.Addr(),
			Username:      "redis-user",
			RedisPassword: &oidc.RedisConfig_Password{Password: "redis-pass"},
			TlsConfig: &oidc.RedisConfig_TLSConfig{
				Ca:         &oidc.RedisConfig_TLSConfig_TrustedCaPem{TrustedCaPem: string(caPEM)},
				ClientCert: &oidc.RedisConfig_TLSConfig_ClientCertPem{ClientCertPem: string(certPEM)},
				ClientKey:  &oidc.RedisConfig_TLSConfig_ClientKeyPem{ClientKeyPem: string(keyPEM)},
			},
		})
		require.NoError(t, err)

		_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
		require.NoError(t, err)
	})
}

func TestRedisTokenResponse(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)

	store, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	tr, err := store.GetTokenResponse(t.Context(), "s1")
	require.NoError(t, err)
	require.Nil(t, tr)

	// Create a session and verify it's added and accessed time is set
	tr = &TokenResponse{
		IDToken:              newToken(),
		AccessToken:          newToken(),
		AccessTokenExpiresAt: time.Now().Add(30 * time.Minute),
		RefreshToken:         newToken(),
	}
	require.NoError(t, store.SetTokenResponse(t.Context(), "s1", tr))

	// Verify we can retrieve the token
	got, err := store.GetTokenResponse(t.Context(), "s1")
	require.NoError(t, err)
	// The testify library doesn't properly compare times, so we need to do it manually
	// then set the times in the returned object so that we can compare the rest of the
	// fields normally
	require.True(t, tr.AccessTokenExpiresAt.Equal(got.AccessTokenExpiresAt))
	got.AccessTokenExpiresAt = tr.AccessTokenExpiresAt
	require.Equal(t, tr, got)

	// Verify that the session TTL has been set
	added, _ := client.HGet(t.Context(), "s1", keyTimeAdded).Time()
	ttl := client.TTL(t.Context(), "s1").Val()
	require.Greater(t, added.Unix(), int64(0))
	require.Greater(t, ttl, time.Duration(0))

	// Check keys are deleted
	tr.AccessToken = ""
	tr.RefreshToken = ""
	tr.AccessTokenExpiresAt = time.Time{}
	require.NoError(t, store.SetTokenResponse(t.Context(), "s1", tr))

	var rt redisToken
	vals := client.HMGet(t.Context(), "s1", keyAccessToken, keyRefreshToken, keyAccessTokenExpiry)
	require.NoError(t, vals.Scan(&rt))
	require.Empty(t, rt.AccessToken)
	require.True(t, rt.AccessTokenExpiresAt.IsZero())
	require.Empty(t, rt.RefreshToken)
}

func TestRedisAuthorizationState(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)
	store, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	as, err := store.GetAuthorizationState(t.Context(), "s1")
	require.NoError(t, err)
	require.Nil(t, as)

	as = &AuthorizationState{
		State:        "state",
		Nonce:        "nonce",
		RequestedURL: "requested_url",
		CodeVerifier: "code_verifier",
	}
	require.NoError(t, store.SetAuthorizationState(t.Context(), "s1", as))

	// Verify that the right state is returned and the expiration time is updated
	got, err := store.GetAuthorizationState(t.Context(), "s1")
	require.NoError(t, err)
	require.Equal(t, as, got)

	// Verify that the session TTL has been set
	added, _ := client.HGet(t.Context(), "s1", keyTimeAdded).Time()
	ttl := client.TTL(t.Context(), "s1").Val()
	require.Greater(t, added.Unix(), int64(0))
	require.Greater(t, ttl, time.Duration(0))

	// Verify that clearing the authz state also updates the session access timestamp
	require.NoError(t, store.ClearAuthorizationState(t.Context(), "s1"))

	var at redisAuthState
	vals := client.HMGet(t.Context(), "s1", keyState, keyNonce, keyRequestedURL)
	require.NoError(t, vals.Scan(&at))
	require.Empty(t, at.State)
	require.Empty(t, at.Nonce)
	require.Empty(t, at.RequestedURL)

	// Verify that the session TTL is still there
	added, _ = client.HGet(t.Context(), "s1", keyTimeAdded).Time()
	ttl = client.TTL(t.Context(), "s1").Val()
	require.Greater(t, added.Unix(), int64(0))
	require.Greater(t, ttl, time.Duration(0))
}

func TestRedisRemoveSession(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)
	store, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	t.Run("unexisting", func(t *testing.T) {
		require.NoError(t, store.RemoveSession(t.Context(), "s1"))
	})

	t.Run("existing", func(t *testing.T) {
		require.NoError(t, client.HSet(t.Context(), "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, store.RemoveSession(t.Context(), "s1"))
	})
}

func TestRedisRemoveAllExpired(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)
	store, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.RemoveAllExpired(t.Context()))
}

func TestRedisPingError(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)
	mr.SetError("ping error")

	_, err = NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.EqualError(t, err, "ping error")
}

func TestRefreshExpiration(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(&oidc.RedisConfig{ServerUri: "redis://" + mr.Addr()})
	require.NoError(t, err)
	store, err := NewRedisStore(&Clock{}, client, 0, 0)
	require.NoError(t, err)
	rs := store.(*redisStore)

	t.Run("delete session if no time added", func(t *testing.T) {
		require.NoError(t, client.HSet(t.Context(), "s1", keyAccessToken, "").Err())
		err := rs.refreshExpiration(t.Context(), "s1", time.Time{})
		require.ErrorIs(t, err, ErrRedis)
		require.Equal(t, redis.Nil, client.Get(t.Context(), "s1").Err())
	})

	t.Run("no expiration set if no timeouts", func(t *testing.T) {
		require.NoError(t, client.HSet(t.Context(), "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, rs.refreshExpiration(t.Context(), "s1", time.Time{}))

		res, err := client.TTL(t.Context(), "s1").Result()
		require.NoError(t, err)
		require.Equal(t, time.Duration(-1), res)
	})

	t.Run("set idle expiration", func(t *testing.T) {
		rs.absoluteSessionTimeout = 0
		rs.idleSessionTimeout = 1 * time.Minute
		require.NoError(t, client.HSet(t.Context(), "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, rs.refreshExpiration(t.Context(), "s1", time.Time{}))

		res, err := client.TTL(t.Context(), "s1").Result()
		require.NoError(t, err)
		require.Greater(t, res, time.Duration(0))
		require.LessOrEqual(t, res, rs.idleSessionTimeout)
	})

	t.Run("set absolute expiration", func(t *testing.T) {
		rs.absoluteSessionTimeout = 30 * time.Second
		rs.idleSessionTimeout = 0
		require.NoError(t, client.HSet(t.Context(), "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, rs.refreshExpiration(t.Context(), "s1", time.Time{}))

		res, err := client.TTL(t.Context(), "s1").Result()
		require.NoError(t, err)
		require.Greater(t, res, time.Duration(0))
		require.LessOrEqual(t, res, rs.absoluteSessionTimeout)
	})

	t.Run("set smallest expiration", func(t *testing.T) {
		rs.idleSessionTimeout = 10 * time.Second
		rs.absoluteSessionTimeout = 20 * time.Second
		require.NoError(t, client.HSet(t.Context(), "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, rs.refreshExpiration(t.Context(), "s1", time.Time{}))

		res, err := client.TTL(t.Context(), "s1").Result()
		require.NoError(t, err)
		require.Greater(t, res, time.Duration(0))
		require.LessOrEqual(t, res, rs.idleSessionTimeout)
	})
}

func testCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	defaultSubject := pkix.Name{
		Organization: []string{"Tetrate"},
		Country:      []string{"US"},
		Locality:     []string{"San Francisco"},
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2025),
		Subject:               defaultSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	return ca, caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func testCertificate(t *testing.T, dnsName string, ca *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, []byte, []byte) {
	defaultSubject := pkix.Name{
		Organization: []string{"Tetrate"},
		Country:      []string{"US"},
		Locality:     []string{"San Francisco"},
	}

	template := x509.Certificate{
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		SerialNumber: big.NewInt(2024),
		Subject:      defaultSubject,
		DNSNames:     []string{dnsName, "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, &template, ca, &certKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return tlsCert, certPEM, keyPEM
}
