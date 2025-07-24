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

package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/telemetry"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
	inthttp "github.com/istio-ecosystem/authservice/internal/http"
	"github.com/istio-ecosystem/authservice/internal/oidc"
)

var (
	callbackRequest = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "localhost:443", Path: "/callback?code=auth-code&state=new-state",
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}

	noSessionRequest = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/",
					Method: "GET",
				},
			},
		},
	}

	withSessionHeader = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/",
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}

	logoutWithNoSession = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/logout?some-params",
					Method: "GET",
				},
			},
		},
	}

	logoutWithSession = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/logout?some-params",
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}

	requestedAppURL = "https://localhost:443/final-app"
	validAuthState  = &oidc.AuthorizationState{
		Nonce:        newNonce,
		State:        newState,
		RequestedURL: requestedAppURL,
	}

	yesterday = time.Now().Add(-24 * time.Hour)
	tomorrow  = time.Now().Add(24 * time.Hour)

	sessionID       = "test-session-id"
	newSessionID    = "new-session-id"
	newNonce        = "new-nonce"
	newState        = "new-state"
	newCodeVerifier = "new-code-verifier"

	basicOIDCConfig = &oidcv1.OIDCConfig{
		IdToken: &oidcv1.TokenConfig{
			Header:   "Authorization",
			Preamble: "Bearer",
		},
		AccessToken: &oidcv1.TokenConfig{
			Header:   "X-Access-Token",
			Preamble: "Bearer",
		},
		TokenUri:         "http://idp-test-server/token",
		AuthorizationUri: "http://idp-test-server/auth",
		CallbackUri:      "https://localhost:443/callback",
		ClientId:         "test-client-id",
		ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecret{
			ClientSecret: "test-client-secret",
		},
		Scopes: []string{"openid", "email"},
		Logout: &oidcv1.LogoutConfig{
			Path:        "/logout",
			RedirectUri: "http://idp-test-server/logout?with-params",
		},
	}

	dynamicOIDCConfig = &oidcv1.OIDCConfig{
		IdToken: &oidcv1.TokenConfig{
			Header:   "Authorization",
			Preamble: "Bearer",
		},
		AccessToken: &oidcv1.TokenConfig{
			Header:   "X-Access-Token",
			Preamble: "Bearer",
		},
		ConfigurationUri: "http://idp-test-server/.well-known/openid-configuration",
		CallbackUri:      "https://localhost:443/callback",
		ClientId:         "test-client-id",
		ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecret{
			ClientSecret: "test-client-secret",
		},
		Scopes: []string{"openid", "email"},
		Logout: &oidcv1.LogoutConfig{Path: "/logout"},
	}

	wellKnownURIs = `
{
	"issuer": "http://idp-test-server",
	"authorization_endpoint": "http://idp-test-server/authorize",
	"end_session_endpoint": "http://idp-test-server/endsession",
	"token_endpoint": "http://idp-test-server/token",
	"jwks_uri": "http://idp-test-server/jwks"
}`

	wellKnownURIsNoEndSessionEndpoint = `
{
	"issuer": "http://idp-test-server",
	"authorization_endpoint": "http://idp-test-server/authorize",
	"token_endpoint": "http://idp-test-server/token",
	"jwks_uri": "http://idp-test-server/jwks"
}`

	wantRedirectParams = url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client-id"},
		"redirect_uri":          {"https://localhost:443/callback"},
		"scope":                 {"openid email"},
		"state":                 {newState},
		"nonce":                 {newNonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(newCodeVerifier)},
		"code_challenge_method": {"S256"},
	}

	wantRedirectBaseURI = "http://idp-test-server/auth"
)

func TestOIDCProcess(t *testing.T) {
	unknownJWKPriv, _ := newKeyPair(t)
	jwkPriv, jwkPub := newKeyPair(t)
	// We remove the optional "alg" field from this key to test that we can
	// properly validate against them. Some providers (e.g. Microsoft Identity)
	// exclude the "alg" field from their keys.
	noAlgJwkPriv, noAlgJwkPub := newKeyPair(t)
	err := noAlgJwkPriv.Set(jwk.KeyIDKey, noAlgKeyID)
	require.NoError(t, err)
	err = noAlgJwkPub.Set(jwk.KeyIDKey, noAlgKeyID)
	require.NoError(t, err)
	err = noAlgJwkPub.Remove(jwk.AlgorithmKey)
	require.NoError(t, err)

	bytes, err := json.Marshal(newKeySet(t, jwkPub, noAlgJwkPub))
	require.NoError(t, err)
	basicOIDCConfig.JwksConfig = &oidcv1.OIDCConfig_Jwks{
		Jwks: string(bytes),
	}

	clock := oidc.Clock{}
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	store := sessions.Get(basicOIDCConfig)
	tlsPool := internal.NewTLSConfigPool(context.Background())
	h, err := NewOIDCHandler(basicOIDCConfig, tlsPool,
		oidc.NewJWKSProvider(newConfigFor(basicOIDCConfig), tlsPool), sessions, clock,
		oidc.NewStaticGenerator(newSessionID, newNonce, newState, newCodeVerifier))
	require.NoError(t, err)

	ctx := context.Background()

	tokenExchangeBearerFile := t.TempDir() + "/token-exchange-bearer"
	require.NoError(t, os.WriteFile(tokenExchangeBearerFile, []byte("token"), 0644))

	// The following subset of tests is testing the requests to the app, not any callback or auth flow.
	// So there's no expected communication with any external server.

	requestToAppTests := []struct {
		name                string
		req                 *envoy.CheckRequest
		storedTokenResponse *oidc.TokenResponse
		responseVerify      func(*testing.T, *envoy.CheckResponse)
	}{
		{
			name: "invalid request with missing http",
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
			},
		},
		{
			name: "request with no sessionID",
			req:  noSessionRequest,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
			},
		},
		{
			name: "request with no existing sessionID",
			req:  withSessionHeader,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
				// The old one should have been removed
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name: "request with an existing sessionID expired with no refresh token",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
				AccessToken:          "access-token",
				AccessTokenExpiresAt: yesterday,
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
				// The old one should have been removed
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name: "request with an existing sessionID not expired",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
				AccessToken:          "access-token",
				AccessTokenExpiresAt: tomorrow,
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)), "access-token")
				// The sessionID should not have been changed
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredState(t, store, newSessionID, false)
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "matches logout: request with no sessionId",
			req:  logoutWithNoSession,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), "http://idp-test-server/logout", url.Values{"with-params": {""}})
				requireDeleteCookie(t, resp.GetDeniedResponse())
			},
		},
		{
			name: "matches logout: request with sessionId",
			req:  logoutWithSession,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), "http://idp-test-server/logout", url.Values{"with-params": {""}})
				requireDeleteCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, sessionID, false)
			},
		},
	}

	for _, tt := range requestToAppTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, store.RemoveSession(ctx, sessionID))
				require.NoError(t, store.RemoveSession(ctx, newSessionID))
			})

			if tt.storedTokenResponse != nil {
				require.NoError(t, store.SetTokenResponse(ctx, sessionID, tt.storedTokenResponse))
			}

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, tt.req, resp))
			tt.responseVerify(t, resp)
		})
	}

	// The following subset of tests is testing the callback requests, so there's expected communication with the IDP server.

	idpServer := newServer(wellKnownURIs)
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	callbackTests := []struct {
		name                       string
		setup                      func(*oidcv1.OIDCConfig)
		cleanup                    func(*oidcv1.OIDCConfig)
		req                        *envoy.CheckRequest
		storedAuthState            *oidc.AuthorizationState
		mockTokensResponse         mockIdpResponse
		mockTokensExchangeResponse mockIdpResponse
		responseVerify             func(*testing.T, *envoy.CheckResponse)
	}{
		{
			name:            "successfully retrieve new tokens",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:            "successfully retrieve new tokens when 'alg' is not specified in JWK",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, noAlgJwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "request is invalid, query parameters are missing",
			req:  modifyCallbackRequestPath("/callback?"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, query has invalid format",
			req:  modifyCallbackRequestPath("/callback?invalid;format"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, state is missing",
			req:  modifyCallbackRequestPath("/callback?code=auth-code"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, code is missing",
			req:  modifyCallbackRequestPath("/callback?state=new-state"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "session state not found in the store",
			req:  callbackRequest,
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				require.Equal(t, typev3.StatusCode_BadRequest, response.GetDeniedResponse().GetStatus().GetCode())
				require.Equal(t, "Oops, your session has expired. Please try again.", response.GetDeniedResponse().GetBody())
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "session state stored does not match the request",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        newNonce,
				State:        "non-matching-state",
				RequestedURL: requestedAppURL,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:               "idp server returns non-200 status code",
			req:                callbackRequest,
			storedAuthState:    validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusInternalServerError, nil),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:               "idp server returns empty body",
			req:                callbackRequest,
			storedAuthState:    validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, nil),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned non-bearer token type",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "not-bearer",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned invalid expires_in for access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: -1,
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp didn't return access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: 3600,
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp server returns invalid JWT id-token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     "not-a-jwt",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp server returns JWT signed with unknown key",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, unknownJWKPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "idp didn't return nonce",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        "old-nonce",
				State:        newState,
				RequestedURL: requestedAppURL,
			},
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder()),
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "session nonce stored does not match idp returned nonce",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        "old-nonce",
				State:        newState,
				RequestedURL: requestedAppURL,
			},
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", "non-matching-nonce")),
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned empty audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce)),
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned non-matching audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"non-matching-audience"})),
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "token exchange client credentials",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_ClientCredentials_{
						ClientCredentials: &oidcv1.OIDCConfig_TokenExchange_ClientCredentials{},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				AccessToken: "access-token-exchanged",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token-exchanged")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "token exchange bearer",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_Token{
								Token: "token",
							},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				AccessToken: "access-token-exchanged",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token-exchanged")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "token exchange bearer file",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_TokenPath{
								TokenPath: tokenExchangeBearerFile,
							},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				AccessToken: "access-token-exchanged",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token-exchanged")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			// This test will fail because the kubernetes service account token file located at
			// /var/run/secrets/kubernetes.io/serviceaccount/token is not expected to be present
			// in the test environment.
			name: "token exchange kubernetes service account",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_TokenPath{},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "token exchange failure",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_Token{
								Token: "token",
							},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusForbidden, nil),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
	}

	for _, tt := range callbackTests {
		t.Run("matches callback: "+tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(basicOIDCConfig)
			}
			idpServer.Start()
			t.Cleanup(func() {
				idpServer.Stop()
				if tt.cleanup != nil {
					tt.cleanup(basicOIDCConfig)
				}
				require.NoError(t, store.RemoveSession(ctx, sessionID))
			})

			idpServer.tokensResponse = tt.mockTokensResponse
			idpServer.tokenExchangeResponse = tt.mockTokensExchangeResponse

			// Set the authorization state in the store, so it can be found by the handler
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, tt.storedAuthState))

			resp := &envoy.CheckResponse{}
			err = h.Process(ctx, tt.req, resp)
			require.NoError(t, err)

			tt.responseVerify(t, resp)
		})
	}

	validIDToken := newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce))
	validIDTokenWithoutNonce := newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}))

	expiredTokenResponse := &oidc.TokenResponse{
		IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday).Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		RefreshToken:         "refresh-token",
		AccessToken:          "access-token",
		AccessTokenExpiresAt: yesterday,
	}

	refreshTokensTests := []struct {
		name                       string
		setup                      func(*oidcv1.OIDCConfig)
		cleanup                    func(*oidcv1.OIDCConfig)
		req                        *envoy.CheckRequest
		storedAuthState            *oidc.AuthorizationState
		storedTokenResponse        *oidc.TokenResponse
		mockTokensResponse         mockIdpResponse
		mockTokensExchangeResponse mockIdpResponse
		responseVerify             func(*testing.T, *envoy.CheckResponse)
	}{
		{
			name:                "IDP server returns empty body",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse:  mockTokenResponse(http.StatusOK, nil),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns an non-200 status",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse:  mockTokenResponse(http.StatusInternalServerError, nil),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns response with an invalid token_type",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "invalid-token-type",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns a response with an invalid expires_at",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   -1,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns a response with no access token - succeeds using the stored access token",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:   validIDToken,
				TokenType: "Bearer",
				ExpiresIn: 10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, validIDToken, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:                "IDP server doesn't return an id-token - succeeds using the stored id-token",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				TokenType:   "Bearer",
				ExpiresIn:   10,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, expiredTokenResponse.IDToken, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:                "IDP server returns an invalid JWT as id-token - succeeds using the stored id-token",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     "not-a-jwt",
				TokenType:   "Bearer",
				ExpiresIn:   10,
				AccessToken: "access-token",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, expiredTokenResponse.IDToken, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:                "IDP server returns an id-token signed with unknown key",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, unknownJWKPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns an id-token with non-matching nonce",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", "non-matching-nonce")),
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns an id-token with no nonce claim - succeeds as it is not required",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDTokenWithoutNonce,
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, validIDTokenWithoutNonce, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:                "IDP server returns an id-token with non-matching audience",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"non-matching-audience"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
		{
			name:                "IDP server returns lowercase 'bearer' token, succeeds",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, validIDToken, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name:                "succeed",
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, validIDToken, "access-token")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "succeed with token exchange",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_Token{
								Token: "token",
							},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				AccessToken: "access-token-exchanged",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, validIDToken, "access-token-exchanged")
				requireStoredTokens(t, store, sessionID, true)
				requireStoredAccessToken(t, store, sessionID, "access-token-exchanged")
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "token exchange failed",
			setup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = &oidcv1.OIDCConfig_TokenExchange{
					TokenExchangeUri: "http://idp-test-server/token-exchange",
					Credentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_{
						BearerTokenCredentials: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials{
							BearerToken: &oidcv1.OIDCConfig_TokenExchange_BearerTokenCredentials_Token{
								Token: "token",
							},
						},
					},
				}
			},
			cleanup: func(cfg *oidcv1.OIDCConfig) {
				cfg.TokenExchange = nil
			},
			req:                 withSessionHeader,
			storedTokenResponse: expiredTokenResponse,
			mockTokensResponse: mockTokenResponse(http.StatusOK, &idpTokensResponse{
				IDToken:     validIDToken,
				AccessToken: "access-token",
				TokenType:   "Bearer",
				ExpiresIn:   10,
			}),
			mockTokensExchangeResponse: mockTokenResponse(http.StatusUnauthorized, &idpTokensResponse{
				AccessToken: "access-token-exchanged",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}),
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				requireStoredState(t, store, newSessionID, true)
				requireStoredState(t, store, sessionID, false)
			},
		},
	}

	for _, tt := range refreshTokensTests {
		t.Run("refresh tokens: "+tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(basicOIDCConfig)
			}
			idpServer.Start()
			t.Cleanup(func() {
				idpServer.Stop()
				if tt.cleanup != nil {
					tt.cleanup(basicOIDCConfig)
				}
				require.NoError(t, store.RemoveSession(ctx, sessionID))
				require.NoError(t, store.RemoveSession(ctx, newSessionID))
			})

			idpServer.tokensResponse = tt.mockTokensResponse
			idpServer.tokenExchangeResponse = tt.mockTokensExchangeResponse

			if tt.storedAuthState == nil {
				tt.storedAuthState = validAuthState
			}
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, tt.storedAuthState))
			if tt.storedTokenResponse != nil {
				require.NoError(t, store.SetTokenResponse(ctx, sessionID, tt.storedTokenResponse))
			}

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, tt.req, resp))
			tt.responseVerify(t, resp)
		})
	}
}

func TestOIDCProcessWithFailingSessionStore(t *testing.T) {
	store := &storeMock{delegate: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}
	sessions := &mockSessionStoreFactory{store: store}
	tlsPool := internal.NewTLSConfigPool(context.Background())

	jwkPriv, jwkPub := newKeyPair(t)
	bytes, err := json.Marshal(newKeySet(t, jwkPub))
	require.NoError(t, err)
	basicOIDCConfig.JwksConfig = &oidcv1.OIDCConfig_Jwks{
		Jwks: string(bytes),
	}

	h, err := NewOIDCHandler(basicOIDCConfig, tlsPool, oidc.NewJWKSProvider(newConfigFor(basicOIDCConfig), tlsPool),
		sessions, oidc.Clock{}, oidc.NewStaticGenerator(newSessionID, newNonce, newState, newCodeVerifier))
	require.NoError(t, err)

	ctx := context.Background()

	// The following subset of tests is testing the requests to the app, not any callback or auth flow.
	// So there's no expected communication with any external server.
	requestToAppTests := []struct {
		name        string
		req         *envoy.CheckRequest
		storeErrors map[int]bool
	}{
		{
			name:        "app request - fails to get token response from given session ID",
			req:         withSessionHeader,
			storeErrors: map[int]bool{getTokenResponse: true},
		},
		{
			name:        "app request (redirect to IDP) - fails to remove old session",
			req:         withSessionHeader,
			storeErrors: map[int]bool{removeSession: true},
		},
		{
			name:        "app request (redirect to IDP) - fails to set new authorization state",
			req:         withSessionHeader,
			storeErrors: map[int]bool{setAuthorizationState: true},
		},
		{
			name:        "logout request - fails to remove session",
			req:         logoutWithSession,
			storeErrors: map[int]bool{removeSession: true},
		},
	}

	for _, tt := range requestToAppTests {
		t.Run(tt.name, func(t *testing.T) {
			store.errs = tt.storeErrors
			t.Cleanup(func() { store.errs = nil })
			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, tt.req, resp))
			requireSessionErrorResponse(t, resp)
		})
	}

	idpServer := newServer(wellKnownURIs)
	idpServer.tokensResponse = mockTokenResponse(http.StatusOK, &idpTokensResponse{
		IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		AccessToken: "access-token",
		TokenType:   "Bearer",
	})
	idpServer.Start()
	t.Cleanup(idpServer.Stop)
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	// The following subset of tests is testing the callback requests, so there's expected communication with the IDP server.
	// The store is expected to fail in some way, so the handler should return an error response.
	callbackTests := []struct {
		name              string
		storeCallsToError map[int]bool
	}{
		{
			name:              "callback request - fails to get authorization state",
			storeCallsToError: map[int]bool{getAuthorizationState: true},
		},
		{
			name:              "callback request - fails to clear old authorization state",
			storeCallsToError: map[int]bool{clearAuthorizationState: true},
		},
		{
			name:              "callback request - fails to set new token response",
			storeCallsToError: map[int]bool{setTokenResponse: true},
		},
	}

	for _, tt := range callbackTests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, validAuthState))

			store.errs = tt.storeCallsToError
			t.Cleanup(func() { store.errs = nil })

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, callbackRequest, resp))
			requireSessionErrorResponse(t, resp)
		})
	}

	// The following subset of tests is testing the refresh tokens requests, so there's expected communication with the IDP server.
	// The store is expected to fail in some way, so the handler should return an error response.
	refreshTokensTests := []struct {
		name              string
		storeCallsToError map[int]bool
		wantRedirect      bool
	}{
		{
			name:              "refresh tokens - fails to get the authorization state",
			storeCallsToError: map[int]bool{getAuthorizationState: true},
			wantRedirect:      true,
		},
		{
			name:              "refresh tokens - fails to set new token response",
			storeCallsToError: map[int]bool{setTokenResponse: true},
			wantRedirect:      false,
		},
	}

	for _, tt := range refreshTokensTests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, validAuthState))
			require.NoError(t, store.SetTokenResponse(ctx, sessionID, &oidc.TokenResponse{
				IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday).Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				RefreshToken:         "refresh-token",
				AccessToken:          "access-token",
				AccessTokenExpiresAt: yesterday,
			}))

			store.errs = tt.storeCallsToError
			t.Cleanup(func() { store.errs = nil })

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, withSessionHeader, resp))
			require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
			requireStandardResponseHeaders(t, resp)
			if tt.wantRedirect {
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
			} else {
				requireSessionErrorResponse(t, resp)
			}
		})
	}
}

func TestOIDCProcessWithFailingJWKSProvider(t *testing.T) {
	funcJWKSProvider := jwksProviderFunc(func() (jwk.Set, error) {
		return nil, errors.New("test jwks provider error")
	})

	jwkPriv, _ := newKeyPair(t)

	clock := oidc.Clock{}
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	store := sessions.Get(basicOIDCConfig)
	tlsPool := internal.NewTLSConfigPool(context.Background())
	h, err := NewOIDCHandler(basicOIDCConfig, tlsPool, funcJWKSProvider, sessions, clock,
		oidc.NewStaticGenerator(newSessionID, newNonce, newState, newCodeVerifier))
	require.NoError(t, err)

	idpServer := newServer(wellKnownURIs)
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	ctx := context.Background()

	idpServer.Start()
	t.Cleanup(func() {
		idpServer.Stop()
		require.NoError(t, store.RemoveSession(ctx, sessionID))
	})

	idpServer.tokensResponse = mockTokenResponse(http.StatusOK, &idpTokensResponse{
		IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		AccessToken: "access-token",
		TokenType:   "Bearer",
	})

	expiredTokenResponse := &oidc.TokenResponse{
		IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday).Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		RefreshToken:         "refresh-token",
		AccessToken:          "access-token",
		AccessTokenExpiresAt: yesterday,
	}

	require.NoError(t, store.SetAuthorizationState(ctx, sessionID, validAuthState))

	t.Run("callback request ", func(t *testing.T) {
		resp := &envoy.CheckResponse{}
		require.NoError(t, h.Process(ctx, callbackRequest, resp))
		require.Equal(t, int32(codes.Internal), resp.GetStatus().GetCode())
		requireStandardResponseHeaders(t, resp)
		requireStoredTokens(t, store, sessionID, false)
	})

	require.NoError(t, store.SetTokenResponse(ctx, sessionID, expiredTokenResponse))

	t.Run("refresh tokens - redirect to reauthenticate", func(t *testing.T) {
		resp := &envoy.CheckResponse{}
		require.NoError(t, h.Process(ctx, withSessionHeader, resp))

		require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
		requireStandardResponseHeaders(t, resp)
		requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
		requireCookie(t, resp.GetDeniedResponse())
		requireStoredState(t, store, newSessionID, true)
	})
}

func TestMatchesCallbackPath(t *testing.T) {
	tests := []struct {
		callback   string
		host, path string
		want       bool
	}{
		{"https://example.com", "example.com", "/", false},
		{"https://example.com/callback", "example.com", "/callback", true},
		{"http://example.com/callback", "example.com", "/callback", true},
		{"https://example.com/callback", "example.com", "/callback/", false},
		{"http://example.com/callback", "example.com", "/callback/", false},
		{"https://example.com/callback", "example.com", "/callback?query#fragment", true},
		{"http://example.com/callback", "example.com", "/callback?query#fragment", true},
		{"https://example.com:443/callback", "example.com", "/callback", true},
		{"https://example.com:8443/callback", "example.com", "/callback", false},
		{"https://example.com:8443/callback", "example.com:8443", "/callback", true},
		{"http://example.com/callback", "example.com", "/callback", true},
		{"http://example.com:80/callback", "example.com", "/callback", true},
		{"http://example.com:8080/callback", "example.com", "/callback", false},
		{"http://example.com:8080/callback", "example.com:8080", "/callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.callback, func(t *testing.T) {
			got := matchesCallbackPath(telemetry.NoopLogger(),
				&oidcv1.OIDCConfig{CallbackUri: tt.callback},
				&envoy.AttributeContext_HttpRequest{Host: tt.host, Path: tt.path})
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesLogoutPath(t *testing.T) {
	var (
		logoutPathConfig      = &oidcv1.LogoutConfig{Path: "/logout"}
		emptyLogoutPathConfig = &oidcv1.LogoutConfig{}
	)

	tests := []struct {
		name         string
		logoutConfig *oidcv1.LogoutConfig
		reqPath      string
		want         bool
	}{
		{"with-config", logoutPathConfig, "/logout", true},
		{"with-config", logoutPathConfig, "/logout/", false},
		{"with-config", logoutPathConfig, "/logout?query#fragment", true},
		{"with-config", logoutPathConfig, "/other", false},
		{"with-config", logoutPathConfig, "/logout-nope", false},
		{"empty-config", emptyLogoutPathConfig, "/logout", false},
		{"empty-config", emptyLogoutPathConfig, "/logout/", false},
		{"empty-config", emptyLogoutPathConfig, "/logout?query#fragment", false},
		{"empty-config", emptyLogoutPathConfig, "/other", false},
		{"empty-config", emptyLogoutPathConfig, "/logout-nope", false},
		{"nil-config", nil, "/logout", false},
		{"nil-config", nil, "/logout/", false},
		{"nil-config", nil, "/logout?query#fragment", false},
		{"nil-config", nil, "/other", false},
		{"nil-config", nil, "/logout-nope", false},
	}

	for _, tt := range tests {
		t.Run(tt.name+" "+tt.reqPath, func(t *testing.T) {
			got := matchesLogoutPath(telemetry.NoopLogger(),
				&oidcv1.OIDCConfig{Logout: tt.logoutConfig},
				&envoy.AttributeContext_HttpRequest{Path: tt.reqPath})
			require.Equal(t, tt.want, got)
		})
	}

}

func TestEncodeTokensToHeaders(t *testing.T) {
	const (
		idToken     = "id-token"
		accessToken = "access-token"
	)

	tests := []struct {
		name                 string
		config               *oidcv1.OIDCConfig
		idToken, accessToken string
		want                 map[string]string
	}{
		{
			name: "only id token",
			config: &oidcv1.OIDCConfig{
				IdToken: &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: "",
			want: map[string]string{
				"Authorization": "Bearer " + idToken,
			},
		},
		{
			name: "id token and access token",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"Authorization":  "Bearer " + idToken,
				"X-Access-Token": "Bearer " + accessToken,
			},
		},
		{
			name: "not default config",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "X-Id-Token", Preamble: "Other"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token-Other", Preamble: "Other"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"X-Id-Token":           "Other " + idToken,
				"X-Access-Token-Other": "Other " + accessToken,
			},
		},
		{
			name: "config with access token but no access token in response",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: "",
			want: map[string]string{
				"Authorization": "Bearer " + idToken,
			},
		},
		{
			name: "config with no access token but access token in response",
			config: &oidcv1.OIDCConfig{
				IdToken: &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"Authorization": "Bearer " + idToken,
			},
		},
		{
			name: "config with out preamble",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "X-ID-Token"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"X-ID-Token":     idToken,
				"X-Access-Token": accessToken,
			},
		},
	}

	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}
	tlsPool := internal.NewTLSConfigPool(context.Background())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewOIDCHandler(tt.config, tlsPool, nil, sessions, oidc.Clock{}, nil)
			require.NoError(t, err)

			tokResp := &oidc.TokenResponse{
				IDToken: tt.idToken,
			}
			if tt.accessToken != "" {
				tokResp.AccessToken = tt.accessToken
			}

			got := h.(*oidcHandler).encodeTokensToHeaders(tokResp)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAreTokensExpired(t *testing.T) {
	jwkPriv, _ := newKeyPair(t)

	tests := []struct {
		name                  string
		config                *oidcv1.OIDCConfig
		idToken               string
		accessTokenExpiration time.Time
		want                  bool
	}{
		{
			name:    "no expiration - only id token",
			config:  &oidcv1.OIDCConfig{},
			idToken: newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			want:    false,
		},
		{
			name:                  "no expiration - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: tomorrow,
			want:                  false,
		},
		{
			name:    "expired - only id token",
			config:  &oidcv1.OIDCConfig{},
			idToken: newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
			want:    true,
		},
		{
			name:                  "expired - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired - but access token not in config",
			config:                &oidcv1.OIDCConfig{},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  false,
		},
	}

	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}
	tlsPool := internal.NewTLSConfigPool(context.Background())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewOIDCHandler(tt.config, tlsPool, nil, sessions, oidc.Clock{}, nil)
			require.NoError(t, err)

			tokResp := &oidc.TokenResponse{
				IDToken: tt.idToken,
			}
			if !tt.accessTokenExpiration.IsZero() {
				tokResp.AccessToken = "access-token"
				tokResp.AccessTokenExpiresAt = tt.accessTokenExpiration
			}

			got, err := h.(*oidcHandler).areRequiredTokensExpired(h.(*oidcHandler).log, tokResp)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLoadWellKnownConfig(t *testing.T) {
	idpServer := newServer(wellKnownURIs)
	idpServer.Start()
	t.Cleanup(idpServer.Stop)

	cfg := proto.Clone(dynamicOIDCConfig).(*oidcv1.OIDCConfig)
	require.NoError(t, loadWellKnownConfig(idpServer.newHTTPClient(), cfg))
	require.Equal(t, cfg.AuthorizationUri, "http://idp-test-server/authorize")
	require.Equal(t, cfg.TokenUri, "http://idp-test-server/token")
	require.Equal(t, cfg.GetJwksFetcher().GetJwksUri(), "http://idp-test-server/jwks")
	require.Equal(t, cfg.GetLogout().GetRedirectUri(), "http://idp-test-server/endsession")
}

func TestLoadWellKnownConfigMissingLogoutRedirectURI(t *testing.T) {
	idpServer := newServer(wellKnownURIsNoEndSessionEndpoint)
	idpServer.Start()
	t.Cleanup(idpServer.Stop)

	cfg := proto.Clone(dynamicOIDCConfig).(*oidcv1.OIDCConfig)
	cfg.ConfigurationUri = "http://missing-logout/.well-known/openid-configuration"
	require.ErrorIs(t, loadWellKnownConfig(idpServer.newHTTPClient(), cfg), ErrMissingLogoutRedirectURI)
}

func TestLoadWellKnownConfigError(t *testing.T) {
	clock := oidc.Clock{}
	tlsPool := internal.NewTLSConfigPool(context.Background())
	cfg := proto.Clone(dynamicOIDCConfig).(*oidcv1.OIDCConfig)
	cfg.ConfigurationUri = "http://stopped-server/.well-known/openid-configuration"
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	_, err := NewOIDCHandler(cfg, tlsPool, oidc.NewJWKSProvider(newConfigFor(basicOIDCConfig), tlsPool),
		sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState, newCodeVerifier))
	require.Error(t, err) // Fail to retrieve the dynamic config since the test server is not running
}

func TestNewOIDCHandler(t *testing.T) {
	clock := oidc.Clock{}
	tlsPool := internal.NewTLSConfigPool(context.Background())
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}

	tests := []struct {
		name    string
		config  *oidcv1.OIDCConfig
		wantErr bool
	}{
		{"empty", &oidcv1.OIDCConfig{}, false},
		{"proxy uri", &oidcv1.OIDCConfig{ProxyUri: "http://proxy"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := NewOIDCHandler(tt.config, tlsPool, oidc.NewJWKSProvider(newConfigFor(basicOIDCConfig), tlsPool),
				sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState, newCodeVerifier))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

		})
	}
}

func TestCookieAttributesConfig(t *testing.T) {
	for _, tt := range []struct {
		name           string
		config         *oidcv1.OIDCConfig
		wantAttributes []string
	}{
		{
			name:           "unset cookie attributes",
			config:         &oidcv1.OIDCConfig{},
			wantAttributes: []string{"HttpOnly", "Secure", "Path=/", "SameSite=Lax"},
		},
		{
			name: "samesite=strict",
			config: &oidcv1.OIDCConfig{CookieAttributes: &oidcv1.OIDCConfig_CookieAttributes{
				SameSite: oidcv1.OIDCConfig_CookieAttributes_SAME_SITE_STRICT,
			}},
			wantAttributes: []string{"HttpOnly", "Secure", "Path=/", "SameSite=Strict"},
		},
		{
			name: "samesite=none/domain=foo.com",
			config: &oidcv1.OIDCConfig{CookieAttributes: &oidcv1.OIDCConfig_CookieAttributes{
				SameSite: oidcv1.OIDCConfig_CookieAttributes_SAME_SITE_NONE,
				Domain:   "foo.com",
			}},
			wantAttributes: []string{"HttpOnly", "Secure", "Path=/", "SameSite=None", "Domain=foo.com"},
		},
		{
			name: "partitioned",
			config: &oidcv1.OIDCConfig{CookieAttributes: &oidcv1.OIDCConfig_CookieAttributes{
				Partitioned: true,
			}},
			wantAttributes: []string{"HttpOnly", "Secure", "Path=/", "SameSite=Lax", "Partitioned"},
		},
	} {
		haveAttributes := getCookieDirectives(tt.config, -1)
		require.Equal(t, tt.wantAttributes, haveAttributes)
	}
}

func modifyCallbackRequestPath(path string) *envoy.CheckRequest {
	return &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "localhost:443", Path: path,
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}
}

const (
	keyID      = "test"
	keyAlg     = jwa.RS256
	noAlgKeyID = "noAlgTest"
)

func newKeySet(t *testing.T, keys ...jwk.Key) jwk.Set {
	jwks := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, jwks.AddKey(k))
	}
	return jwks
}

func newKeyPair(t *testing.T) (jwk.Key, jwk.Key) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	priv, err := jwk.FromRaw(rsaKey)
	require.NoError(t, err)
	err = priv.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)

	pub, err := jwk.FromRaw(rsaKey.PublicKey)
	require.NoError(t, err)

	err = pub.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)
	err = pub.Set(jwk.AlgorithmKey, keyAlg)
	require.NoError(t, err)

	return priv, pub
}

func newJWT(t *testing.T, key jwk.Key, builder *jwt.Builder) string {
	token, err := builder.Claim(jwk.KeyIDKey, key.KeyID()).Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(keyAlg, key))
	require.NoError(t, err)
	return string(signed)
}

func requireSessionErrorResponse(t *testing.T, resp *envoy.CheckResponse) {
	require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
	require.Equal(t, "There was an error accessing your session data. Try again later.", resp.GetDeniedResponse().GetBody())
}

func requireStoredTokens(t *testing.T, store oidc.SessionStore, sessionID string, wantExists bool) {
	got, err := store.GetTokenResponse(context.Background(), sessionID)
	require.NoError(t, err)
	if wantExists {
		require.NotNil(t, got)
	} else {
		require.Nil(t, got)
	}
}

func requireStoredAccessToken(t *testing.T, store oidc.SessionStore, sessionID string, token string) {
	got, err := store.GetTokenResponse(context.Background(), sessionID)
	require.NoError(t, err)
	require.Equal(t, token, got.AccessToken)
}

func requireStoredState(t *testing.T, store oidc.SessionStore, sessionID string, wantExists bool) {
	got, err := store.GetAuthorizationState(context.Background(), sessionID)
	require.NoError(t, err)
	if wantExists {
		require.NotNil(t, got)
	} else {
		require.Nil(t, got)
	}
}

func requireRedirectResponse(t *testing.T, response *envoy.DeniedHttpResponse, wantRedirectBaseURI string, wantRedirectParams url.Values) {
	var locationHeader string
	for _, header := range response.GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderLocation {
			locationHeader = header.GetHeader().GetValue()
		}
	}

	require.Equal(t, typev3.StatusCode_Found, response.GetStatus().GetCode())
	got, err := url.Parse(locationHeader)
	require.NoError(t, err)

	require.Equal(t, wantRedirectBaseURI, got.Scheme+"://"+got.Host+got.Path)

	gotParams := got.Query()
	for k, v := range wantRedirectParams {
		require.Equal(t, v, gotParams[k])
	}
	require.Len(t, gotParams, len(wantRedirectParams))
}

func requireCookie(t *testing.T, response *envoy.DeniedHttpResponse) {
	var cookieHeader string
	for _, header := range response.GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderSetCookie {
			cookieHeader = header.GetHeader().GetValue()
		}
	}
	require.Equal(t, "__Host-authservice-session-id-cookie=new-session-id; HttpOnly; Secure; Path=/; SameSite=Lax", cookieHeader)
}

func requireDeleteCookie(t *testing.T, response *envoy.DeniedHttpResponse) {
	var cookieHeader string
	for _, header := range response.GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderSetCookie {
			cookieHeader = header.GetHeader().GetValue()
		}
	}
	require.Equal(t, "__Host-authservice-session-id-cookie=deleted; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0", cookieHeader)
}

func requireTokensInResponse(t *testing.T, resp *envoy.OkHttpResponse, cfg *oidcv1.OIDCConfig, idToken, accessToken string) {
	var (
		gotIDToken, gotAccessToken   string
		wantIDToken, wantAccessToken string
	)

	wantIDToken = encodeHeaderValue(cfg.GetIdToken().GetPreamble(), idToken)
	if cfg.GetAccessToken() != nil {
		wantAccessToken = encodeHeaderValue(cfg.GetAccessToken().GetPreamble(), accessToken)
	}

	for _, header := range resp.GetHeaders() {
		if header.GetHeader().GetKey() == cfg.GetIdToken().GetHeader() {
			gotIDToken = header.GetHeader().GetValue()
		}
		if header.GetHeader().GetKey() == cfg.GetAccessToken().GetHeader() {
			gotAccessToken = header.GetHeader().GetValue()
		}
	}

	require.Equal(t, wantIDToken, gotIDToken)
	if cfg.GetAccessToken() != nil {
		require.Equal(t, wantAccessToken, gotAccessToken)
	} else {
		require.Empty(t, gotAccessToken)
	}
}

func requireStandardResponseHeaders(t *testing.T, resp *envoy.CheckResponse) {
	for _, header := range resp.GetDeniedResponse().GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderCacheControl {
			require.EqualValues(t, inthttp.HeaderCacheControlNoCache, header.GetHeader().GetValue())
		}
		if header.GetHeader().GetKey() == inthttp.HeaderPragma {
			require.EqualValues(t, inthttp.HeaderPragmaNoCache, header.GetHeader().GetValue())
		}
	}
}

func newConfigFor(oidc *oidcv1.OIDCConfig) *configv1.Config {
	return &configv1.Config{
		Chains: []*configv1.FilterChain{
			{Filters: []*configv1.Filter{{Type: &configv1.Filter_Oidc{Oidc: oidc}}}},
		},
	}
}

type mockIdpResponse struct {
	resp       *idpTokensResponse
	statusCode int
}

func mockTokenResponse(statusCode int, response *idpTokensResponse) mockIdpResponse {
	return mockIdpResponse{
		resp:       response,
		statusCode: statusCode,
	}
}

// idpServer is a mock IDP server that can be used to test the OIDC handler.
// It listens on a bufconn.Listener and provides a http.Client that can be used to make requests to it.
// It returns a predefined response when the /token endpoint is called, that can be set using the tokensResponse field.
type idpServer struct {
	server                *http.Server
	listener              *bufconn.Listener
	tokensResponse        mockIdpResponse
	tokenExchangeResponse mockIdpResponse
}

func newServer(wellKnownPayload string) *idpServer {
	s := &http.Server{}
	idpServer := &idpServer{server: s, listener: bufconn.Listen(1024)}

	handler := http.NewServeMux()
	handler.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(idpServer.tokensResponse.statusCode)

		if idpServer.tokensResponse.statusCode == http.StatusOK && idpServer.tokensResponse.resp != nil {
			err := json.NewEncoder(w).Encode(idpServer.tokensResponse.resp)
			if err != nil {
				http.Error(w, fmt.Errorf("cannot json encode token response: %w", err).Error(), http.StatusInternalServerError)
			}
		}
	})
	handler.HandleFunc("/token-exchange", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(idpServer.tokenExchangeResponse.statusCode)

		if idpServer.tokenExchangeResponse.statusCode == http.StatusOK && idpServer.tokenExchangeResponse.resp != nil {
			err := json.NewEncoder(w).Encode(idpServer.tokenExchangeResponse.resp)
			if err != nil {
				http.Error(w, fmt.Errorf("cannot json encode token response: %w", err).Error(), http.StatusInternalServerError)
			}
		}
	})
	handler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(wellKnownPayload))
	})
	s.Handler = handler
	return idpServer
}

// Start starts the server in a goroutine.
func (s *idpServer) Start() {
	go func() { _ = s.server.Serve(s.listener) }()
}

// Stop stops the server.
func (s *idpServer) Stop() {
	_ = s.listener.Close()
}

// newHTTPClient returns a new http.Client that can be used to make requests to the server via the bufconn.Listener.
func (s *idpServer) newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return s.listener.DialContext(ctx)
			},
		},
	}
}

const (
	setTokenResponse = iota
	getTokenResponse
	setAuthorizationState
	getAuthorizationState
	clearAuthorizationState
	removeSession
	removeAllExpired
)

var (
	_ oidc.SessionStore = &storeMock{}

	errStore = errors.New("store error")
)

// storeMock is a mock implementation of oidc.SessionStore that allows to configure when a method must fail with an error.
type storeMock struct {
	delegate oidc.SessionStore
	errs     map[int]bool
}

// SetTokenResponse Implements oidc.SessionStore.
func (s *storeMock) SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *oidc.TokenResponse) error {
	if s.errs[setTokenResponse] {
		return errStore
	}
	return s.delegate.SetTokenResponse(ctx, sessionID, tokenResponse)
}

// GetTokenResponse Implements oidc.SessionStore.
func (s *storeMock) GetTokenResponse(ctx context.Context, sessionID string) (*oidc.TokenResponse, error) {
	if s.errs[getTokenResponse] {
		return nil, errStore
	}
	return s.delegate.GetTokenResponse(ctx, sessionID)
}

// SetAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *oidc.AuthorizationState) error {
	if s.errs[setAuthorizationState] {
		return errStore
	}
	return s.delegate.SetAuthorizationState(ctx, sessionID, authorizationState)
}

// GetAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) GetAuthorizationState(ctx context.Context, sessionID string) (*oidc.AuthorizationState, error) {
	if s.errs[getAuthorizationState] {
		return nil, errStore
	}
	return s.delegate.GetAuthorizationState(ctx, sessionID)
}

// ClearAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) ClearAuthorizationState(ctx context.Context, sessionID string) error {
	if s.errs[clearAuthorizationState] {
		return errStore
	}
	return s.delegate.ClearAuthorizationState(ctx, sessionID)
}

// RemoveSession Implements oidc.SessionStore.
func (s *storeMock) RemoveSession(ctx context.Context, sessionID string) error {
	if s.errs[removeSession] {
		return errStore
	}
	return s.delegate.RemoveSession(ctx, sessionID)
}

// RemoveAllExpired Implements oidc.SessionStore.
func (s *storeMock) RemoveAllExpired(ctx context.Context) error {
	if s.errs[removeAllExpired] {
		return errStore
	}
	return s.delegate.RemoveAllExpired(ctx)
}

var _ oidc.SessionStoreFactory = &mockSessionStoreFactory{}

// mockSessionStoreFactory is a mock implementation of oidc.SessionStoreFactory that returns a predefined store.
type mockSessionStoreFactory struct {
	store oidc.SessionStore
}

func (m mockSessionStoreFactory) Get(_ *oidcv1.OIDCConfig) oidc.SessionStore {
	return m.store
}

var _ oidc.JWKSProvider = jwksProviderFunc(nil)

type jwksProviderFunc func() (jwk.Set, error)

func (j jwksProviderFunc) Get(context.Context, *oidcv1.OIDCConfig) (jwk.Set, error) {
	return j()
}
