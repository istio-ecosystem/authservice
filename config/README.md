# Configuration reference
<a name="top"></a>

## Table of Contents

- [v1/oidc/config.proto](#v1_oidc_config-proto)
    - [LogoutConfig](#authservice-config-v1-oidc-LogoutConfig)
    - [OIDCConfig](#authservice-config-v1-oidc-OIDCConfig)
    - [OIDCConfig.CookieAttributes](#authservice-config-v1-oidc-OIDCConfig-CookieAttributes)
    - [OIDCConfig.JwksFetcherConfig](#authservice-config-v1-oidc-OIDCConfig-JwksFetcherConfig)
    - [OIDCConfig.SecretReference](#authservice-config-v1-oidc-OIDCConfig-SecretReference)
    - [OIDCConfig.TokenExchange](#authservice-config-v1-oidc-OIDCConfig-TokenExchange)
    - [OIDCConfig.TokenExchange.BearerTokenCredentials](#authservice-config-v1-oidc-OIDCConfig-TokenExchange-BearerTokenCredentials)
    - [OIDCConfig.TokenExchange.ClientCredentials](#authservice-config-v1-oidc-OIDCConfig-TokenExchange-ClientCredentials)
    - [RedisConfig](#authservice-config-v1-oidc-RedisConfig)
    - [TokenConfig](#authservice-config-v1-oidc-TokenConfig)
  
    - [OIDCConfig.CookieAttributes.SameSite](#authservice-config-v1-oidc-OIDCConfig-CookieAttributes-SameSite)
  
- [v1/mock/config.proto](#v1_mock_config-proto)
    - [MockConfig](#authservice-config-v1-mock-MockConfig)
  
- [v1/config.proto](#v1_config-proto)
    - [Config](#authservice-config-v1-Config)
    - [Filter](#authservice-config-v1-Filter)
    - [FilterChain](#authservice-config-v1-FilterChain)
    - [Match](#authservice-config-v1-Match)
    - [StringMatch](#authservice-config-v1-StringMatch)
    - [TriggerRule](#authservice-config-v1-TriggerRule)
  
- [Scalar Value Types](#scalar-value-types)




<a name="v1_oidc_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/oidc/config.proto



<a name="authservice-config-v1-oidc-LogoutConfig"></a>

### LogoutConfig
When specified, the Authservice will destroy the Authservice session when a request is
made to the configured path.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| path | [string](#string) |  | A http request path that the Authservice matches against to initiate logout. Whenever a request is made to that path, the Authservice will remove the Authservice-specific cookies and respond with a redirect to the configured `redirect_uri`. Removing the cookies causes the user to be unauthenticated in future requests. If the service application has its own logout controller, then it may be desirable to have its logout controller redirect to this path. If the service application does not need its own logout controller, then the application's logout button/link's href can GET or POST directly to this path. Required. |
| redirect_uri | [string](#string) |  | A URI specifying the destination to which the Authservice will redirect any request made to the logout `path`. For example, it may be desirable to redirect the logged out user to the homepage of the service application, or to the [logout endpoint of the OIDC Provider](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout). As with all redirects, the user's browser will perform a GET to this URI. Required when the OIDC discovery is not used or when the OIDC discovery does not provide the `end_session_endpoint`. |






<a name="authservice-config-v1-oidc-OIDCConfig"></a>

### OIDCConfig
The configuration of an OpenID Connect filter that can be used to retrieve identity and access tokens
via the standard authorization code grant flow from an OIDC Provider.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configuration_uri | [string](#string) |  | The OIDC Provider's [issuer identifier](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig). If this is set, the endpoints will be dynamically retrieved from the OIDC Provider's configuration endpoint. |
| authorization_uri | [string](#string) |  | The OIDC Provider's [authorization endpoint](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint). Required if `configuration_uri` is not set. |
| token_uri | [string](#string) |  | The OIDC Provider's [token endpoint](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint). Required if `configuration_uri` is not set. |
| callback_uri | [string](#string) |  | This value will be used as the `redirect_uri` param of the authorization code grant [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). This URL must be one of the Redirection URI values for the Client pre-registered at the OIDC provider. Note: The Istio gateway's VirtualService must be prepared to ensure that this URL will get routed to the service so that the Authservice can intercept the request and handle it (see [example](https://github.com/istio-ecosystem/authservice/blob/master/bookinfo-example/config/bookinfo-gateway.yaml)). Required. |
| jwks | [string](#string) |  | The JSON JWKS response from the OIDC provider’s `jwks_uri` URI which can be found in the OIDC provider's [configuration response](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse). Note that this JSON value must be escaped when embedded in a json configmap (see [example](https://github.com/istio-ecosystem/authservice/blob/master/bookinfo-example/config/authservice-configmap-template.yaml)). Used during token verification. |
| jwks_fetcher | [OIDCConfig.JwksFetcherConfig](#authservice-config-v1-oidc-OIDCConfig-JwksFetcherConfig) |  | Configuration to allow JWKs to be retrieved and updated asynchronously at regular intervals. |
| client_authentication_method | [string](#string) |  | Available [Client Authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) methods. * `client_secret_basic` - Clients authenticate using the HTTP Basic authentication scheme. * `client_secret_post` - Clients authenticate by including the Client Credentials in the request body. * `client_secret_jwt` - Clients create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256 (not implemented). * `private_key_jwt` - Clients that have registered a public key sign a JWT using that key (not implemented). * `none` - The Client does not authenticate itself at the Token Endpoint, either because it uses only the Implicit Flow (and so does not use the Token Endpoint) or because it is a Public Client with no Client Secret or other authentication mechanism (not implemented). If not set, it defaults to `client_secret_basic`. |
| client_id | [string](#string) |  | The OIDC client ID assigned to the filter to be used in the [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). Required. The client ID is used to authenticate to the Token endpoint using HTTP Basic Auth and it must not contain a colon (":") character. |
| client_secret | [string](#string) |  | The OIDC client secret assigned to the filter to be used in the [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). This field keeps the client secret in plain text. Recommend to use `client_secret_ref` instead when running in a Kubernetes cluster. |
| client_secret_ref | [OIDCConfig.SecretReference](#authservice-config-v1-oidc-OIDCConfig-SecretReference) |  | The Kubernetes secret that contains the OIDC client secret assigned to the filter to be used in the [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). This is an Opaque secret. The client secret should be stored in the key "client-secret". This filed is only valid when running in a Kubernetes cluster. |
| scopes | [string](#string) | repeated | Additional scopes passed to the OIDC Provider in the [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). The `openid` scope is always sent to the OIDC Provider, and does not need to be specified here. Required, but an empty array is allowed. |
| cookie_name_prefix | [string](#string) |  | A unique identifier of the Authservice's browser cookies. Can be any string. Needed when multiple services in the same domain are each protected by their own Authservice, in which case each service's Authservice should have a unique value to avoid cookie name conflicts. Also needed when an Authservice is configured with multiple `oidc` filters (across multiple `chains`), each sharing a Redis server for their session storage, to avoid having those `oidc` filters read/write the same sessions in Redis. Optional. |
| cookie_attributes | [OIDCConfig.CookieAttributes](#authservice-config-v1-oidc-OIDCConfig-CookieAttributes) |  | Configure the cookie attributes to set for Authservice session cookies. |
| id_token | [TokenConfig](#authservice-config-v1-oidc-TokenConfig) |  | The configuration for adding ID Tokens as headers to requests forwarded to a service. Required. |
| access_token | [TokenConfig](#authservice-config-v1-oidc-TokenConfig) |  | The configuration for adding Access Tokens as headers to requests forwarded to a service. Optional. |
| logout | [LogoutConfig](#authservice-config-v1-oidc-LogoutConfig) |  | When specified, the Authservice will destroy the Authservice session when a request is made to the configured path. Optional. |
| absolute_session_timeout | [uint32](#uint32) |  | The Authservice associates obtained OIDC tokens with a session ID in a session store. It also stores some temporary information during the login process into the session store, which will be removed when the user finishes the login. This configuration option sets the number of seconds since a user's session with the Authservice has started until that session should expire. When configured to `0`, which is the default value, the session will never timeout based on the time that it was started, but can still timeout due to being idle. When both `absolute_session_timeout` and `idle_session_timeout` are zero, then sessions will never expire. These settings do not affect how quickly the OIDC tokens contained inside the user's session expire. Optional. |
| idle_session_timeout | [uint32](#uint32) |  | The Authservice associates obtained OIDC tokens with a session ID in a session store. It also stores some temporary information during the login process into the session store, which will be removed when the user finishes the login. This configuration option sets the number of seconds since the most recent incoming request from that user until the user's session with the Authservice should expire. When configured to `0`, which is the default value, session expiration will not consider idle time, but can still consider timeout based on maximum absolute time since added. When both `absolute_session_timeout` and `idle_session_timeout` are zero, then sessions will never expire. These settings do not affect how quickly the OIDC tokens contained inside the user's session expire. Optional. |
| trusted_certificate_authority | [string](#string) |  | String PEM-encoded certificate authority to trust when performing HTTPS calls to the OIDC Identity Provider. Optional. |
| trusted_certificate_authority_file | [string](#string) |  | The file path to the PEM-encoded certificate authority to trust when performing HTTPS calls to the OIDC Identity Provider. Optional. |
| trusted_certificate_authority_refresh_interval | [google.protobuf.Duration](#google-protobuf-Duration) |  | The duration between refreshes of the trusted certificate authority if `trusted_certificate_authority_file` is set. Unset or 0 (the default) disables the refresh, useful is no rotation is expected. Is a String that ends in `s` to indicate seconds and is preceded by the number of seconds, e.g. `120s` (represents 2 minutes). Optional. |
| proxy_uri | [string](#string) |  | The Authservice makes two kinds of direct network connections directly to the OIDC Provider. Both are POST requests to the configured `token_uri` of the OIDC Provider. The first is to exchange the authorization code for tokens, and the other is to use the refresh token to obtain new tokens. Configure the `proxy_uri` when both of these requests should be made through a web proxy. The format of `proxy_uri` is `http://proxyserver.example.com:8080`, where `:<port_number>` is optional. Userinfo (usernames and passwords) in the `proxy_uri` setting are not yet supported. The `proxy_uri` should always start with `http://`. The Authservice will upgrade the connection to the OIDC provider to HTTPS using an HTTP CONNECT request to the proxy server. The proxy server will see the hostname and port number of the OIDC provider in plain text in the CONNECT request, but all other communication will occur over an encrypted HTTPS connection negotiated directly between the Authservice and the OIDC provider. See also the related `trusted_certificate_authority` configuration option. Optional. |
| redis_session_store_config | [RedisConfig](#authservice-config-v1-oidc-RedisConfig) |  | When specified, the Authservice will use the configured Redis server to store session data. Optional. |
| skip_verify_peer_cert | [google.protobuf.Value](#google-protobuf-Value) |  | If set to true, the verification of the destination certificate will be skipped when making a request to the Token Endpoint. This option is useful when you want to use a self-signed certificate for testing purposes, but basically should not be set to true in any other cases. Optional. keep this field out from the trusted_ca_config one of for backward compatibility. |
| token_exchange | [OIDCConfig.TokenExchange](#authservice-config-v1-oidc-OIDCConfig-TokenExchange) |  | When configured, the Authservice will exchange the OIDC access token for a service-specific token from the defined authorization server. This is useful to automatically exchange the access token obtained from the Identity Provider for a service-specific token issued by an internal authorization server. |






<a name="authservice-config-v1-oidc-OIDCConfig-CookieAttributes"></a>

### OIDCConfig.CookieAttributes



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| same_site | [OIDCConfig.CookieAttributes.SameSite](#authservice-config-v1-oidc-OIDCConfig-CookieAttributes-SameSite) |  | Which SameSite cookie attribute to use. Defaults to `SAME_SITE_LAX`. |
| domain | [string](#string) |  | The domain for the cookie. If not set, the cookie will be set for the domain of the request the Authservice is processing. If you want the cookie to be shared across multiple subdomains, you can set this to the top-level domain (e.g. `example.com`), which will allow the cookie to be sent with requests to any subdomain of that domain (e.g., `api.example.com`, `www.example.com`, etc.). This attribute only applies when `same_site` is set to `SAME_SITE_NONE`. |
| partitioned | [bool](#bool) |  | If partitioned is set to true, the cookie will be partitioned by the top-level site that the request is made to. This means that the cookie will not be shared across different top-level sites connecting to your protected environment, even if they share the same domain. This is useful for ensuring that the cookie is only sent with requests to the same top-level site that it was set for and provides tenancy between different top-level sites served by your protected environment. |






<a name="authservice-config-v1-oidc-OIDCConfig-JwksFetcherConfig"></a>

### OIDCConfig.JwksFetcherConfig
This message defines a setting to allow asynchronous retrieval and update of the JWK for
JWT validation at regular intervals.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| jwks_uri | [string](#string) |  | Request URI that has the JWKs. Required if `configuration_uri` is not set. |
| periodic_fetch_interval_sec | [uint32](#uint32) |  | Request interval to check whether new JWKs are available. If not specified, default to 1200 seconds, 20min. Optional. |
| skip_verify_peer_cert | [google.protobuf.Value](#google-protobuf-Value) |  | **Deprecated.** If set to true, the verification of the destination certificate will be skipped when making a request to the JWKs URI. This option is useful when you want to use a self-signed certificate for testing purposes, but basically should not be set to true in any other cases. Optional. Deprecated: Use the one from the OIDCConfig instead. |






<a name="authservice-config-v1-oidc-OIDCConfig-SecretReference"></a>

### OIDCConfig.SecretReference
This message defines a reference to a Kubernetes Secret resource.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  | The namespace of the referenced Secret, if not set, defaults to the namespace where the Authservice is running. |
| name | [string](#string) |  | The name of the referenced Secret. |






<a name="authservice-config-v1-oidc-OIDCConfig-TokenExchange"></a>

### OIDCConfig.TokenExchange
Configuration for exchanging the access token obtained from the OIDC Provider for
a service-specific token.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token_exchange_uri | [string](#string) |  | The Token Exchange endpoint to call to exchange the OIDC access token for a service-specific token. |
| client_credentials | [OIDCConfig.TokenExchange.ClientCredentials](#authservice-config-v1-oidc-OIDCConfig-TokenExchange-ClientCredentials) |  | The client credentials to use when exchanging the token. |
| bearer_token_credentials | [OIDCConfig.TokenExchange.BearerTokenCredentials](#authservice-config-v1-oidc-OIDCConfig-TokenExchange-BearerTokenCredentials) |  | The bearer token credentials to use when exchanging the token. |






<a name="authservice-config-v1-oidc-OIDCConfig-TokenExchange-BearerTokenCredentials"></a>

### OIDCConfig.TokenExchange.BearerTokenCredentials
Configures a Bearer Token to be used as a bearer token to authenticate to the
Token Exchange endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | The bearer token to use when exchanging the token. This is useful when the Token Exchange endpoint requires a specific bearer token to authenticate the request. |
| token_path | [string](#string) |  | The path to the file containing the token to use when exchanging the token. |
| kubernetes_service_account_token | [bool](#bool) |  | Use the Kubernetes Service Account Token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` |






<a name="authservice-config-v1-oidc-OIDCConfig-TokenExchange-ClientCredentials"></a>

### OIDCConfig.TokenExchange.ClientCredentials
Client Credentials designates that the OIDC clientID and clientSecret should be used to authenticate
to the Token Exchange endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| client_id | [string](#string) |  | The Client ID to use. If not set, the Client ID from the OIDC configuration will be used. |
| client_secret | [string](#string) |  | The OIDC client secret to use. If not set, the Client Secret from the OIDC configuration will be used. |
| client_secret_ref | [OIDCConfig.SecretReference](#authservice-config-v1-oidc-OIDCConfig-SecretReference) |  | The Kubernetes secret that contains the OIDC client secret to be used. If not set, the Client Secret from the OIDC configuration will be used. |






<a name="authservice-config-v1-oidc-RedisConfig"></a>

### RedisConfig
When specified, the Authservice will use the configured Redis server to store session data


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| server_uri | [string](#string) |  | The Redis server uri, e.g. "tcp://127.0.0.1:6379" |






<a name="authservice-config-v1-oidc-TokenConfig"></a>

### TokenConfig
Defines how a token obtained through an OIDC flow is forwarded to services.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| header | [string](#string) |  | The name of the header that Authservice adds to the request when forwarding to services. The value of this header will contain the `preamble` and the token. This value is case-insensitive, as http header names are case-insensitive. Note that this value must be `Authorization` for the [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) to inspect the token. Required. |
| preamble | [string](#string) |  | The authentication scheme of the token. For example, when the preamble is `Bearer` and `header` is `Authorization`, the following header will be added to the request to the service: `Authorization: Bearer ID_TOKEN_VALUE`. Note that this value must be `Bearer`, case-sensitive, when header is `Authorization`. Optional. |





 <!-- end messages -->


<a name="authservice-config-v1-oidc-OIDCConfig-CookieAttributes-SameSite"></a>

### OIDCConfig.CookieAttributes.SameSite


| Name | Number | Description |
| ---- | ------ | ----------- |
| SAME_SITE_UNSPECIFIED | 0 | If unspecified, Authservice will use `SAME_SITE_LAX` as the default. |
| SAME_SITE_LAX | 1 | Lax allows the cookie to be sent with top-level cross-site GET subrequest navigations (e.g. links, images, etc.) to your protected environment, but not with cross-site POST requests or other methods. |
| SAME_SITE_STRICT | 2 | Strict will only include the cookie on same-site requests. This means the cookie will not be sent with any cross-site requests, including top-level subrequest navigations to your protected environment. |
| SAME_SITE_NONE | 3 | None means the cookie will be sent with all cross-site requests to your protected environment, regardless of the HTTP method. This is useful for cross-site requests that require authentication, such as when the Authservice is used in a cross-origin setup especially when requiring various subdomains of your environment to share the same session. When using this option, make sure you add Origin checking in your Istio Authorization Policies to restrict the domains you allow cross-site requests from. |


 <!-- end enums -->

 <!-- end HasExtensions -->

 <!-- end services -->



<a name="v1_mock_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/mock/config.proto



<a name="authservice-config-v1-mock-MockConfig"></a>

### MockConfig
Mock filter config. The only thing which can be defined is whether it
allows or rejects any request it matches.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow | [bool](#bool) |  | Boolean specifying whether the filter should return OK for any request it matches. Defaults to false (not OK). |





 <!-- end messages -->

 <!-- end enums -->

 <!-- end HasExtensions -->

 <!-- end services -->



<a name="v1_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## v1/config.proto



<a name="authservice-config-v1-Config"></a>

### Config
The top-level configuration object.
For a simple example, see the [sample JSON in the bookinfo configmap template](https://github.com/istio-ecosystem/authservice/blob/master/bookinfo-example/config/authservice-configmap-template-for-authn-and-authz.yaml).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| chains | [FilterChain](#authservice-config-v1-FilterChain) | repeated | Each incoming http request is matched against the list of filters in the chain, in order, until a matching filter is found. The first matching filter is then applied to the request. After the first match is made, other filters in the chain are ignored. Order of chain declaration is therefore important. At least one `FilterChain` is required in this array. |
| listen_address | [string](#string) |  | The IP address for the Authservice to listen for incoming requests to process. Required. |
| listen_port | [int32](#int32) |  | The TCP port for the Authservice to listen for incoming requests to process. Required. |
| log_level | [string](#string) |  | The verbosity of logs generated by the Authservice. Must be one of `trace`, `debug`, `info', 'error' or 'critical'. Required. |
| threads | [uint32](#uint32) |  | The number of threads in the thread pool to use for processing. The main thread will be used for accepting connections, before sending them to the thread-pool for processing. The total number of running threads, including the main thread, will be N+1. Required. |
| trigger_rules | [TriggerRule](#authservice-config-v1-TriggerRule) | repeated | List of trigger rules to decide if the Authservice should be used to authenticate the request. The Authservice authentication happens if any one of the rules matched. If the list is not empty and none of the rules matched, the request will be allowed to proceed without Authservice authentication. The format and semantics of `trigger_rules` are the same as the `triggerRules` setting on the Istio Authentication Policy (see https://istio.io/docs/reference/config/security/istio.authentication.v1alpha1). CAUTION: Be sure that your configured `OIDCConfig.callback` and `OIDCConfig.logout` paths each satisfies at least one of the trigger rules, or else the Authservice will not be able to intercept requests made to those paths to perform the appropriate login/logout behavior. Optional. Leave this empty to always trigger authentication for all paths. |
| default_oidc_config | [oidc.OIDCConfig](#authservice-config-v1-oidc-OIDCConfig) |  | Global configuration of OIDC. This value will be applied to all filter definition when it defined as `oidc_override`. Optional. |
| allow_unmatched_requests | [bool](#bool) |  | If true will allow the the requests even no filter chain match is found. Default false. Optional. |
| health_listen_address | [string](#string) |  | The Authservice provides an HTTP server to check the health state. This configures the address for the health server to listen for. Optional. Defaults to the value of `listen_address`. |
| health_listen_port | [int32](#int32) |  | The TCP port for the health server to listen for. Optional. Defaults 10004. |
| health_listen_path | [string](#string) |  | The path for the health server to attend. Optional. Defaults to "/healthz". |






<a name="authservice-config-v1-Filter"></a>

### Filter
A filter configuration.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| oidc | [oidc.OIDCConfig](#authservice-config-v1-oidc-OIDCConfig) |  | An OpenID Connect filter configuration. |
| oidc_override | [oidc.OIDCConfig](#authservice-config-v1-oidc-OIDCConfig) |  | This value will be used when `default_oidc_config` exists. It will override values of them. If that doesn't exist, this configuration will be rejected. |
| mock | [mock.MockConfig](#authservice-config-v1-mock-MockConfig) |  | Mock filter configuration for testing and letting AuthService run even if no OIDC providers are configured. |






<a name="authservice-config-v1-FilterChain"></a>

### FilterChain
A chain of one or more filters that will sequentially process an HTTP request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | A user-defined identifier for the processing chain used in log messages. Required. |
| match | [Match](#authservice-config-v1-Match) |  | A rule to determine whether an HTTP request should be processed by the filter chain. If not defined, the filter chain will match every request. Optional. |
| filters | [Filter](#authservice-config-v1-Filter) | repeated | The configuration of one of more filters in the filter chain. When the filter chain matches an incoming request, then this list of filters will be applied to the request in the order that they are declared. All filters are evaluated until one of them returns a non-OK response. If all filters return OK, the envoy proxy is notified that the request may continue. The first filter that returns a non-OK response causes the request to be rejected with the filter's returned status and any remaining filters are skipped. At least one `Filter` is required in this array. |






<a name="authservice-config-v1-Match"></a>

### Match
Specifies how a request can be matched to a filter chain.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| header | [string](#string) |  | The name of the http header used to match against. Required. |
| prefix | [string](#string) |  | The expected prefix. If the actual value of the header starts with this prefix, then it will be considered a match. |
| equality | [string](#string) |  | The expected value. If the actual value of the header exactly equals this value, then it will be considered a match. |






<a name="authservice-config-v1-StringMatch"></a>

### StringMatch
Describes how to match a given string. Match is case-sensitive.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| exact | [string](#string) |  | exact string match. |
| prefix | [string](#string) |  | prefix-based match. |
| suffix | [string](#string) |  | suffix-based match. |
| regex | [string](#string) |  | ECMAscript style regex-based match as defined by [EDCA-262](http://en.cppreference.com/w/cpp/regex/ecmascript). Example: "^/pets/(.*?)?" |






<a name="authservice-config-v1-TriggerRule"></a>

### TriggerRule
Trigger rule to match against a request. The trigger rule is satisfied if
and only if both rules, excluded_paths and include_paths are satisfied.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| excluded_paths | [StringMatch](#authservice-config-v1-StringMatch) | repeated | List of paths to be excluded from the request. The rule is satisfied if request path does not match to any of the path in this list. Optional. |
| included_paths | [StringMatch](#authservice-config-v1-StringMatch) | repeated | List of paths that the request must include. If the list is not empty, the rule is satisfied if request path matches at least one of the path in the list. If the list is empty, the rule is ignored, in other words the rule is always satisfied. Optional. |





 <!-- end messages -->

 <!-- end enums -->

 <!-- end HasExtensions -->

 <!-- end services -->



## Scalar Value Types

| Type | Notes |
| ----------- | ----- |
| <a name="double" /> double |  |
| <a name="float" /> float |  |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. |
| <a name="uint32" /> uint32 | Uses variable-length encoding. |
| <a name="uint64" /> uint64 | Uses variable-length encoding. |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. |
| <a name="sfixed32" /> sfixed32 | Always four bytes. |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. |
| <a name="bool" /> bool |  |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. |

