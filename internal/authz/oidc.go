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

package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	inthttp "github.com/tetrateio/authservice-go/internal/http"
	"github.com/tetrateio/authservice-go/internal/oidc"
)

var (
	_ Handler = (*oidcHandler)(nil)

	// standardResponseHeaders are the headers that are added to every denied response.
	standardResponseHeaders = []*corev3.HeaderValueOption{
		{Header: &corev3.HeaderValue{Key: inthttp.HeaderCacheControl, Value: inthttp.HeaderCacheControlNoCache}},
		{Header: &corev3.HeaderValue{Key: inthttp.HeaderPragma, Value: inthttp.HeaderPragmaNoCache}},
	}
)

// oidc handler is an implementation of the Handler interface that implements
// the OpenID connect protocol.
type oidcHandler struct {
	log        telemetry.Logger
	config     *oidcv1.OIDCConfig
	jwks       oidc.JWKSProvider
	sessions   oidc.SessionStoreFactory
	sessionGen oidc.SessionGenerator
	clock      oidc.Clock
	httpClient *http.Client
}

// NewOIDCHandler creates a new OIDC implementation of the Handler interface.
func NewOIDCHandler(cfg *oidcv1.OIDCConfig, jwks oidc.JWKSProvider,
	sessions oidc.SessionStoreFactory, clock oidc.Clock,
	sessionGen oidc.SessionGenerator) (Handler, error) {

	client, err := getHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	if err := loadWellKnownConfig(client, cfg); err != nil {
		return nil, err
	}

	return &oidcHandler{
		log:        internal.Logger(internal.Authz).With("type", "oidc"),
		config:     cfg,
		jwks:       jwks,
		sessions:   sessions,
		clock:      clock,
		sessionGen: sessionGen,
		httpClient: client,
	}, nil
}

func getHTTPClient(cfg *oidcv1.OIDCConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	var err error
	if transport.TLSClientConfig, err = internal.LoadTLSConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.ProxyUri != "" {
		// config validation ensures that the proxy uri is valid
		proxyURL, _ := url.Parse(cfg.ProxyUri)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{Transport: transport}, nil
}

// Process a CheckRequest and populate a CheckResponse according to the mockHandler configuration.
func (o *oidcHandler) Process(ctx context.Context, req *envoy.CheckRequest, resp *envoy.CheckResponse) error {
	log := o.log.Context(ctx)
	log.Debug("process request",
		"source-principal", req.GetAttributes().GetSource().GetPrincipal(),
		"source-address", req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress(),
		"destination-principal", req.GetAttributes().GetDestination().GetPrincipal(),
		"destination-address", req.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetAddress(),
	)
	defer func() {
		log.Debug("process result", "allow", resp.GetDeniedResponse() == nil, "status", codes.Code(resp.Status.GetCode()).String())
	}()

	if req.GetAttributes().GetRequest().GetHttp() == nil {
		log.Info("missing http in the request")
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return nil
	}

	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	sessionID := getSessionIDFromCookie(log, headers, o.config)

	// If the request is for the configured logout path,
	// then logout and redirect to the configured logout redirect uri.
	if matchesLogoutPath(log, o.config, req.GetAttributes().GetRequest().GetHttp()) {
		log.Info("handling logout request")
		if sessionID != "" {
			log.Info("removing session from session store during logout", "session-id", sessionID)
			store := o.sessions.Get(o.config)
			if err := store.RemoveSession(ctx, sessionID); err != nil {
				log.Error("error removing session", err)
				setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
				return nil
			}
		}
		log.Info("Logout complete. Redirecting to logout redirect uri")
		deny := newDenyResponse()
		// add IDP logout location
		setRedirect(deny, o.config.GetLogout().GetRedirectUri())
		// add the set-cookie header to delete the session_id cookie
		setSetCookieHeader(deny, generateSetCookieHeader(getCookieName(o.config), "deleted", 0))
		setDenyResponse(resp, deny, codes.Unauthenticated)
		return nil
	}

	// If the request does not have a session_id cookie,
	// then generate a session id, put it in a header, and redirect for login.
	if sessionID == "" {
		log.Info("No session cookie detected. Generating new session and sending user to re-authenticate.")
		o.redirectToIDP(ctx, log, resp, req.GetAttributes().GetRequest().GetHttp(), "")
		return nil
	}

	log = log.With("session-id", sessionID)

	// If the request path is the callback for receiving the authorization code,
	// has a session id then exchange it for tokens and redirects end-user back to
	// their originally requested URL.
	if matchesCallbackPath(log, o.config, req.GetAttributes().GetRequest().GetHttp()) {
		log.Debug("handling callback request")
		o.retrieveTokens(ctx, log, req, resp, sessionID)
		return nil
	}

	log.Debug("attempting session retrieval")

	store := o.sessions.Get(o.config)
	tokenResponse, err := store.GetTokenResponse(ctx, sessionID)
	if err != nil {
		log.Error("error retrieving tokens from session store", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return nil
	}

	// If the user has a session_id cookie but there are no required tokens in the
	// session store associated with it, then redirect for login.
	if tokenResponse == nil {
		log.Info("Required tokens are not present. Sending user to re-authenticate.")
		o.redirectToIDP(ctx, log, resp, req.GetAttributes().GetRequest().GetHttp(), sessionID)
		return nil
	}

	// If both ID & Access token are still unexpired,
	// then allow the request to proceed (no need to intervene).
	log.Debug("checking tokens expiration")
	expired, err := o.areRequiredTokensExpired(tokenResponse)
	if err != nil {
		log.Error("error checking token expiration", err)
		setDenyResponse(resp, newDenyResponse(), codes.Internal)
		return nil
	}
	if !expired {
		log.Info("Tokens not expired. Allowing request to proceed.")
		o.allowResponse(resp, tokenResponse)
		return nil
	}

	// If tokens are expired, then:

	// If there is no refresh token,
	// then direct the request to the identity provider for authentication
	if tokenResponse.RefreshToken == "" {
		log.Info("A token was expired, but session did not contain a refresh token. Sending user to re-authenticate.")
		o.redirectToIDP(ctx, log, resp, req.GetAttributes().GetRequest().GetHttp(), sessionID)
		return nil
	}

	// If the user has an unexpired refresh token then use it to request a fresh
	// token_response. If successful, allow the request to proceed. If
	// unsuccessful, redirect for login.
	log.Debug("attempting token refresh")
	refreshedTokens := o.refreshToken(ctx, log, tokenResponse, tokenResponse.RefreshToken, sessionID)
	if refreshedTokens == nil {
		log.Info("Token refresh failed. Sending user to re-authenticate.")
		o.redirectToIDP(ctx, log, resp, req.GetAttributes().GetRequest().GetHttp(), sessionID)
		return nil
	}
	if err := store.SetTokenResponse(ctx, sessionID, refreshedTokens); err != nil {
		log.Error("error saving refreshed tokens to session store", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return nil
	}

	log.Info("Token refresh successful. Allowing request to proceed.")
	o.allowResponse(resp, refreshedTokens)
	return nil
}

// redirectToIDP redirects the request to the Identity Provider for authentication.
// It sets the appropriate headers and status code in the CheckResponse to notify about the redirect.
// It also removes the session id, if given, from the session store.
func (o *oidcHandler) redirectToIDP(ctx context.Context, log telemetry.Logger,
	resp *envoy.CheckResponse, httpRequest *envoy.AttributeContext_HttpRequest, oldSessionID string) {

	store := o.sessions.Get(o.config)
	if oldSessionID != "" {
		// remove old session and regenerate session_id to prevent session fixation attacks
		if err := store.RemoveSession(ctx, oldSessionID); err != nil {
			log.Error("error removing old session", err)
			setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
			return
		}
	}

	var (
		sessionID = o.sessionGen.GenerateSessionID()
		nonce     = o.sessionGen.GenerateNonce()
		state     = o.sessionGen.GenerateState()
	)

	// Store the authorization state
	requestedURL := httpRequest.GetScheme() + "://" + httpRequest.GetHost() + httpRequest.GetPath()
	if httpRequest.GetQuery() != "" {
		requestedURL += "?" + httpRequest.GetQuery()
	}
	if err := store.SetAuthorizationState(ctx, sessionID, &oidc.AuthorizationState{
		State:        state,
		Nonce:        nonce,
		RequestedURL: requestedURL,
	}); err != nil {
		log.Error("error storing the new authorization state", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return
	}

	// Generate the redirect URL
	query := url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{o.config.GetClientId()},
		"redirect_uri":  []string{o.config.GetCallbackUri()},
		"scope":         []string{strings.Join(o.config.GetScopes(), " ")},
		"state":         []string{state},
		"nonce":         []string{nonce},
	}
	redirectURL := o.config.GetAuthorizationUri() + "?" + query.Encode()

	// Generate denied response with redirect headers
	deny := newDenyResponse()
	setRedirect(deny, redirectURL)

	// add the set-cookie header
	cookieName := getCookieName(o.config)
	setSetCookieHeader(deny, generateSetCookieHeader(cookieName, sessionID, -1))
	setDenyResponse(resp, deny, codes.Unauthenticated)
}

// retrieveTokens retrieves the tokens from the Identity Provider and redirects the user back to the originally requested URL.
func (o *oidcHandler) retrieveTokens(ctx context.Context, log telemetry.Logger, req *envoy.CheckRequest, resp *envoy.CheckResponse, sessionID string) {
	store := o.sessions.Get(o.config)

	_, query, _ := inthttp.GetPathQueryFragment(req.GetAttributes().GetRequest().GetHttp().GetPath())
	queryParams, err := url.ParseQuery(query)
	switch {
	case err != nil:
		log.Error("error parsing query", err, "query", query)
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return
	case len(queryParams) == 0:
		log.Info("form data is invalid, no query parameters found", "query", query)
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return
	}

	stateFromReq := queryParams.Get("state")
	codeFromReq := queryParams.Get("code")
	if stateFromReq == "" || codeFromReq == "" {
		log.Info("form data is invalid, missing state or code", "state", stateFromReq, "code", codeFromReq)
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return
	}

	stateFromStore, err := store.GetAuthorizationState(ctx, sessionID)
	if err != nil {
		log.Error("error retrieving authorization state from session store", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return
	}

	if stateFromStore == nil {
		log.Info("missing state, nonce, and original url requested by user in the store. Cannot redirect.")
		deny := newDenyResponse()
		deny.Body = "Oops, your session has expired. Please try again."
		deny.Status = &typev3.HttpStatus{Code: typev3.StatusCode_BadRequest}
		setDenyResponse(resp, deny, codes.Unauthenticated)
		return
	}

	// compare the state from the request with the state from the store
	if stateFromReq != stateFromStore.State {
		log.Info("state from request does not match state from store", "state-from-request", stateFromReq, "state-from-store", stateFromStore.State)
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return
	}

	// build body
	form := url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{codeFromReq},
		"redirect_uri": []string{o.config.GetCallbackUri()},
	}

	// build headers
	headers := http.Header{
		inthttp.HeaderContentType:   []string{inthttp.HeaderContentTypeFormURLEncoded},
		inthttp.HeaderAuthorization: []string{inthttp.BasicAuthHeader(o.config.GetClientId(), o.config.GetClientSecret())},
	}

	log.Info("performing request to retrieve new tokens")
	bodyTokens, errCode := performIDPRequest(log, o.httpClient, o.config.GetTokenUri(), form, headers)
	if errCode != codes.OK {
		setDenyResponse(resp, newDenyResponse(), errCode)
		return
	}

	// validate IDP tokens response
	if !isValidIDPNewTokensResponse(log, o.config, bodyTokens) {
		setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return
	}

	// validate ID token
	if ok, errCode := o.isValidIDToken(ctx, log, bodyTokens.IDToken, stateFromStore.Nonce, true); !ok {
		setDenyResponse(resp, newDenyResponse(), errCode)
		return
	}

	if err := store.ClearAuthorizationState(ctx, sessionID); err != nil {
		log.Error("error clearing authorization state", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return
	}

	// Knock 5 seconds off the expiry time to take into account the time it may
	// have taken to retrieve the token.
	expiresIn := time.Duration(bodyTokens.ExpiresIn)*time.Second - 5
	accessTokenExpiration := o.clock.Now().Add(expiresIn)

	log.Debug("saving tokens to session store")
	if err := store.SetTokenResponse(ctx, sessionID, &oidc.TokenResponse{
		IDToken:              bodyTokens.IDToken,
		AccessToken:          bodyTokens.AccessToken,
		RefreshToken:         bodyTokens.RefreshToken,
		AccessTokenExpiresAt: accessTokenExpiration,
	}); err != nil {
		log.Error("error saving tokens to session store", err)
		setDenyResponse(resp, newSessionErrorResponse(), codes.Unauthenticated)
		return
	}
	log.Debug("tokens retrieved successfully")

	deny := newDenyResponse()
	deny.Status = &typev3.HttpStatus{Code: typev3.StatusCode_Found}
	deny.Headers = append(deny.Headers, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: inthttp.HeaderLocation, Value: stateFromStore.RequestedURL},
	})
	setDenyResponse(resp, deny, codes.Unauthenticated)
}

// refreshToken retrieves new tokens from the Identity Provider using the given refresh token.
func (o *oidcHandler) refreshToken(ctx context.Context, log telemetry.Logger, expiredTokens *oidc.TokenResponse, token, sessionID string) *oidc.TokenResponse {
	store := o.sessions.Get(o.config)

	form := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{token},
		"client_id":     []string{o.config.GetClientId()},
		"client_secret": []string{o.config.GetClientSecret()},
		// according to this link, omitting the `scope` param should return new
		// tokens with the previously requested `scope`
		// https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/
	}

	// build headers
	headers := http.Header{
		inthttp.HeaderContentType: []string{inthttp.HeaderContentTypeFormURLEncoded},
	}

	log.Info("performing request to refresh access token")
	bodyTokens, errCode := performIDPRequest(log, o.httpClient, o.config.GetTokenUri(), form, headers)

	if errCode != codes.OK {
		return nil
	}

	// validate IDP tokens response
	if !isValidIDPRefreshTokenResponse(log, bodyTokens) {
		//setDenyResponse(resp, newDenyResponse(), codes.InvalidArgument)
		return nil
	}

	// merge the new tokens with the stored ones
	newTokenResponse := &oidc.TokenResponse{}

	_, err := oidc.ParseToken(bodyTokens.IDToken)
	if err != nil {
		log.Error("error parsing new id token, using the old one", err)
		newTokenResponse.IDToken = expiredTokens.IDToken
	} else {
		log.Debug("updating id token")
		newTokenResponse.IDToken = bodyTokens.IDToken
	}

	if bodyTokens.AccessToken != "" {
		log.Debug("updating access token")
		newTokenResponse.AccessToken = bodyTokens.AccessToken
	} else {
		newTokenResponse.AccessToken = expiredTokens.AccessToken
	}

	if bodyTokens.RefreshToken != "" {
		log.Debug("updating refresh token")
		newTokenResponse.RefreshToken = bodyTokens.RefreshToken
	} else {
		newTokenResponse.RefreshToken = expiredTokens.RefreshToken
	}

	if bodyTokens.ExpiresIn > 0 {
		log.Debug("updating access token expiration")
		// Knock 5 seconds off the expiry time to take into account the time it may
		// have taken to retrieve the token.
		expiresIn := time.Duration(bodyTokens.ExpiresIn)*time.Second - 5
		newTokenResponse.AccessTokenExpiresAt = o.clock.Now().Add(expiresIn)
	} else {
		newTokenResponse.AccessTokenExpiresAt = expiredTokens.AccessTokenExpiresAt
	}

	stateFromStore, err := store.GetAuthorizationState(ctx, sessionID)
	if err != nil {
		log.Error("error retrieving authorization state from session store", err)
		return nil
	}
	var expectedNonce string
	if stateFromStore != nil {
		expectedNonce = stateFromStore.Nonce
	}

	// validate the id token
	if ok, _ := o.isValidIDToken(context.Background(), log, newTokenResponse.IDToken, expectedNonce, false); !ok {
		return nil
	}

	return newTokenResponse
}

// idpTokensResponse is the response from the Identity Provider when requesting tokens.
type idpTokensResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	DeviceSecret string `json:"device_secret"`
}

// performIDPRequest performs a request to the Identity Provider to retrieve tokens.
func performIDPRequest(log telemetry.Logger, client *http.Client, uri string, form url.Values, headers http.Header) (*idpTokensResponse, codes.Code) {
	oidcReq, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		log.Error("error creating tokens request to OIDC", err)
		return nil, codes.Internal
	}
	oidcReq.Header = headers

	oidcResp, err := client.Do(oidcReq)
	if err != nil {
		log.Error("error performing tokens request to OIDC", err)
		return nil, codes.Internal
	}

	if oidcResp.StatusCode != http.StatusOK {
		log.Info("OIDC server returned non-200 status code", "status-code", oidcResp.StatusCode, "url", oidcReq.URL.String())
		return nil, codes.Unknown
	}

	respBody, err := io.ReadAll(oidcResp.Body)
	_ = oidcResp.Body.Close()
	if err != nil {
		log.Error("error reading tokens response", err)
		return nil, codes.Internal
	}

	bodyTokens := &idpTokensResponse{}
	err = json.Unmarshal(respBody, &bodyTokens)
	if err != nil {
		log.Error("error unmarshalling tokens response", err)
		return nil, codes.Internal
	}

	return bodyTokens, codes.OK
}

// isValidIDPNewTokensResponse checks if the response from the Identity Provider is valid according to the OpenID Connect specification.
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
func isValidIDPNewTokensResponse(log telemetry.Logger, config *oidcv1.OIDCConfig, tokenResponse *idpTokensResponse) bool {
	// token_type must be Bearer
	if tokenResponse.TokenType != "Bearer" {
		log.Info("token type is not Bearer in token response", "token-type", tokenResponse.TokenType)
		return false
	}

	// expires_in must be a positive value
	if tokenResponse.ExpiresIn < 0 {
		log.Info("expires_in is not a positive value in token response", "expires-in", tokenResponse.ExpiresIn)
		return false
	}

	// If access_token forwarding is configured but there is not an access token
	// in the token response then there is a problem
	if config.GetAccessToken() != nil && tokenResponse.AccessToken == "" {
		log.Info("access token forwarding is configured but no access token was returned")
		return false
	}

	return true
}

// isValidIDPRefreshTokenResponse checks if the response from the Identity Provider is valid according to the OpenID Connect specification.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
func isValidIDPRefreshTokenResponse(log telemetry.Logger, tokenResponse *idpTokensResponse) bool {
	// token_type must be Bearer
	if tokenResponse.TokenType != "Bearer" {
		log.Info("token type is not Bearer in token response", "token-type", tokenResponse.TokenType)
		return false
	}

	// expires_in must be a positive value
	if tokenResponse.ExpiresIn < 0 {
		log.Info("expires_in is not a positive value in token response", "expires-in", tokenResponse.ExpiresIn)
		return false
	}

	return true
}

// isValidIDToken checks if the id token is valid according to the OpenID Connect specification.
// It checks the nonce, audience, and verifies the signature with the fetched jwks.
// It returns a boolean indicating if the token is valid and a code indicating the reason if it is not.
// If the nonce is not required, it will only check the expectedNonce against the token's nonce if it is present, as OIDC spec defines.
func (o *oidcHandler) isValidIDToken(ctx context.Context, log telemetry.Logger, idTokenString, expectedNonce string, isNonceRequired bool) (bool, codes.Code) {
	idToken, err := oidc.ParseToken(idTokenString)
	if err != nil {
		log.Error("error parsing id token", err)
		return false, codes.Internal
	}

	oidcNonce, ok := idToken.Get("nonce")
	if !ok && isNonceRequired {
		log.Info("id token does not have nonce claim")
		return false, codes.InvalidArgument
	}
	if ok {
		tokenNonce := oidcNonce.(string)
		// if nonce is not required, both token and expected nonce must be present to perform the check
		if (isNonceRequired || tokenNonce != "" && expectedNonce != "") && tokenNonce != expectedNonce {
			log.Info("id token nonce does not match", "nonce-from-id-token", oidcNonce, "nonce-from-store", expectedNonce)
			return false, codes.InvalidArgument
		}
	}

	var audMatches bool
	for _, a := range idToken.Audience() {
		if a == o.config.GetClientId() {
			audMatches = true
			break
		}
	}
	if !audMatches {
		log.Info("id token audience does not match", "aud-from-id-token", idToken.Audience(), "aud-from-config", o.config.GetClientId())
		return false, codes.InvalidArgument
	}

	jwtSet, err := o.jwks.Get(ctx, o.config)
	if err != nil {
		log.Error("error fetching jwks", err)
		return false, codes.Internal
	}

	if _, err := jws.VerifySet([]byte(idTokenString), jwtSet); err != nil {
		log.Error("error verifying id token with fetched jwks", err)
		return false, codes.Internal
	}

	return true, codes.OK
}

// newDenyResponse creates a new DeniedHttpResponse with the standard headers.
func newDenyResponse() *envoy.DeniedHttpResponse {
	deny := &envoy.DeniedHttpResponse{}
	deny.Headers = append(deny.Headers, standardResponseHeaders...)
	return deny
}

// newSessionErrorResponse creates a new DeniedHttpResponse with the proper data to notify about a session error.
func newSessionErrorResponse() *envoy.DeniedHttpResponse {
	return &envoy.DeniedHttpResponse{
		Body: "There was an error accessing your session data. Try again later.",
	}
}

// setDenyResponse populates the CheckResponse as a Denied response with the given code and headers.
func setDenyResponse(resp *envoy.CheckResponse, deny *envoy.DeniedHttpResponse, code codes.Code) {
	resp.HttpResponse = &envoy.CheckResponse_DeniedResponse{DeniedResponse: deny}
	resp.Status = &status.Status{Code: int32(code)}
}

// setRedirect populates the DeniedHttpResponse with the given location and a 302 status code.
func setRedirect(deny *envoy.DeniedHttpResponse, location string) {
	deny.Status = &typev3.HttpStatus{Code: typev3.StatusCode_Found}
	deny.Headers = append(deny.Headers, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: inthttp.HeaderLocation, Value: location},
	})
}

// setSetCookieHeader populates the DeniedHttpResponse with the given cookie.
func setSetCookieHeader(deny *envoy.DeniedHttpResponse, cookie string) {
	deny.Headers = append(deny.Headers, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: inthttp.HeaderSetCookie, Value: cookie},
	})
}

// allowResponse populates the CheckResponse as an OK response with the required tokens.
func (o *oidcHandler) allowResponse(resp *envoy.CheckResponse, tokens *oidc.TokenResponse) {
	ok := resp.GetOkResponse()
	if ok == nil {
		ok = &envoy.OkHttpResponse{}
	}

	for key, value := range o.encodeTokensToHeaders(tokens) {
		ok.Headers = append(ok.Headers, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: key, Value: value}})
	}

	resp.HttpResponse = &envoy.CheckResponse_OkResponse{OkResponse: ok}
	resp.Status = &status.Status{Code: int32(codes.OK)}
}

// matchesCallbackPath checks if the request matches the configured callback uri.
// Request done by the IDP directly to the authservice to exchange the authorization code for tokens.
func matchesCallbackPath(log telemetry.Logger, config *oidcv1.OIDCConfig, httpReq *envoy.AttributeContext_HttpRequest) bool {
	reqFullPath := httpReq.GetPath()
	reqHost := httpReq.GetHost()
	reqPath, _, _ := inthttp.GetPathQueryFragment(reqFullPath)

	// no need to handle the error since config validation already checks for this
	confURI, _ := url.Parse(config.GetCallbackUri())
	confPort := confURI.Port()
	confHost := confURI.Hostname()
	confScheme := confURI.Scheme
	confPath := confURI.Path
	confHostAndPort := confHost
	if confPort != "" {
		confHostAndPort += ":" + confPort
	}

	hostMatches := reqHost == confHostAndPort ||
		(confScheme == "https" && confPort == "443" && reqHost == confHost) || // default https port
		(confScheme == "http" && confPort == "80" && reqHost == confHost) // default http port

	pathMatches := reqPath == confPath

	if pathMatches && hostMatches {
		log.Debug("request matches configured callback uri")
		return true
	}
	return false
}

// matchesLogoutPath checks if the request matches the configured logout uri.
// Request done by the end-user to log out.
func matchesLogoutPath(log telemetry.Logger, config *oidcv1.OIDCConfig, httpReq *envoy.AttributeContext_HttpRequest) bool {
	if config.GetLogout() == nil {
		return false
	}

	reqPath, _, _ := inthttp.GetPathQueryFragment(httpReq.GetPath())
	confPath := config.GetLogout().GetPath()

	if reqPath == confPath {
		log.Debug("request matches configured logout uri")
		return true
	}
	return false
}

// encodeTokensToHeaders encodes the tokens to the headers according to the configuration.
func (o *oidcHandler) encodeTokensToHeaders(tokens *oidc.TokenResponse) map[string]string {
	headers := make(map[string]string)

	// Always add the ID token to the headers
	headers[o.config.GetIdToken().GetHeader()] = encodeHeaderValue(o.config.IdToken.GetPreamble(), tokens.IDToken)

	if o.config.GetAccessToken() == nil || tokens.AccessToken == "" {
		return headers
	}

	// If there is an access token and config enables it, add it to the headers
	headers[o.config.GetAccessToken().GetHeader()] = encodeHeaderValue(o.config.GetAccessToken().GetPreamble(), tokens.AccessToken)

	return headers
}

// encodeHeaderValue encodes the value with the given preamble, if any
func encodeHeaderValue(preamble string, value string) string {
	if preamble != "" {
		return preamble + " " + value
	}
	return value
}

// areRequiredTokensExpired checks if the required tokens are expired.
func (o *oidcHandler) areRequiredTokensExpired(tokens *oidc.TokenResponse) (bool, error) {
	idToken, err := tokens.ParseIDToken()
	if err != nil {
		return false, fmt.Errorf("parsing id token: %w", err)
	}

	if idToken.Expiration().Before(o.clock.Now()) {
		return true, nil
	}
	if o.config.GetAccessToken() != nil && tokens.AccessToken != "" && !tokens.AccessTokenExpiresAt.IsZero() {
		return tokens.AccessTokenExpiresAt.Before(o.clock.Now()), nil
	}
	return false, nil
}

// generateSetCookieHeader generates the Set-Cookie header value with the given cookie name, value, and timeout.
func generateSetCookieHeader(cookieName, cookieValue string, timeout time.Duration) string {
	directives := getCookieDirectives(timeout)
	return inthttp.EncodeCookieHeader(cookieName, cookieValue, directives)
}

// getCookieDirectives returns the directives to use in the Set-Cookie header depending on the timeout.
func getCookieDirectives(timeout time.Duration) []string {
	directives := []string{inthttp.HeaderSetCookieHTTPOnly, inthttp.HeaderSetCookieSecure, inthttp.HeaderSetCookieSameSiteLax, "Path=/"}
	if timeout >= 0 {
		directives = append(directives, fmt.Sprintf("%s=%d", inthttp.HeaderSetCookieMaxAge, int(timeout.Seconds())))
	}
	return directives
}

// getSessionIDFromCookie retrieves the session id from the cookie in the headers.
func getSessionIDFromCookie(log telemetry.Logger, headers map[string]string, config *oidcv1.OIDCConfig) string {
	cookieName := getCookieName(config)

	value := headers[inthttp.HeaderCookie]
	if value == "" {
		log.Info("session id cookie is missing", "cookie-name", cookieName)
		return ""
	}

	for name, value := range inthttp.DecodeCookiesHeader(value) {
		if name == cookieName {
			return value
		}
	}

	log.Info("session id cookie is missing", "cookie-name", cookieName)
	return ""
}

const (
	prefixCookieName  = "__Host-"
	suffixCookieName  = "-authservice-session-id-cookie"
	defaultCookieName = "__Host-authservice-session-id-cookie"
)

// getCookieName returns the cookie name to use for the session id.
func getCookieName(config *oidcv1.OIDCConfig) string {
	if prefix := config.GetCookieNamePrefix(); prefix != "" {
		return prefixCookieName + prefix + suffixCookieName
	}
	return defaultCookieName
}

// loadWellKnownConfig loads the OIDC well-known configuration into the given OIDCConfig.
func loadWellKnownConfig(client *http.Client, cfg *oidcv1.OIDCConfig) error {
	if cfg.GetConfigurationUri() == "" {
		return nil
	}

	wellKnownConfig, err := oidc.GetWellKnownConfig(client, cfg.GetConfigurationUri())
	if err != nil {
		return err
	}

	cfg.AuthorizationUri = wellKnownConfig.AuthorizationEndpoint
	cfg.TokenUri = wellKnownConfig.TokenEndpoint
	if cfg.GetJwksFetcher() == nil {
		cfg.JwksConfig = &oidcv1.OIDCConfig_JwksFetcher{
			JwksFetcher: &oidcv1.OIDCConfig_JwksFetcherConfig{},
		}
	}
	cfg.GetJwksFetcher().JwksUri = wellKnownConfig.JWKSURL

	return nil
}
