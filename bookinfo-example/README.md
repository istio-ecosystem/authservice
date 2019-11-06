# Bookinfo with Authservice example (Sidecar integration)

##


This doc shows how to integrate `authservice` into an Istio system deployed on Kubernetes.

This demo takes advantage of an Istio feature set that gives the ability to inject http filters on 
Sidecars. This feature set was released in Istio 1.3.0.

Things needed before starting:

- A Kubernetes cluster that is compatible with Istio 1.3
- An OIDC provider configured to support Authorization Code grant type. The urls and credentials for this 
provider will be needed to configure `authservice`.

 
#### Pre-requisites:
1. Download Istio

   [`scripts/download-istio-1.3.sh`](scripts/download-istio-1.3.sh)

1. Install Istio

   [`scripts/install-istio.sh`](scripts/install-istio.sh)

1. If certs signed by a known CA cannot be obtained, generate self signed certs for the ingress gateway

   [`scripts/generate-self-signed-certs-for-ingress-gateway.sh`](scripts/generate-self-signed-certs-for-ingress-gateway.sh)


#### Configuring and Integrating `authservice` with `bookinfo`

1. Setup a `ConfigMap` for `authservice`. Fill in [`config/authservice-configmap-template.yaml`](config/authservice-configmap-template.yaml) 
to include the OIDC provider's configurations. Currently, only the `oidc` filter can be configured in the `ConfigMap`.
See the following table for the description of each field:    

    | Field                       | Optionality | Description
    |-----------------------------|-------------|-----------------------------------------------------------------------------------
    | listen_address              |  Optional   | The ip address the authservice will listen on. Defaults to 127.0.0.1. 
    | listen_port                 |  Optional   | The port the authservice will listen on. Defaults to 10003
    | log_level                   |  Optional   | Log verbosity. Must be one of trace, debug, info, error, critical. Defaults to trace.
    | oidc.authorization          |  Required   | The Authorization Endpoint of your OIDC provider.
    | oidc.token                  |  Required   | The Token Endpoint of your OIDC provider
    | oidc.jwks_uri               |  Ignored    | *This is currently ignored.* In a future version it will be the URL of your OIDC provider’s public key set to validate signature of the JWT. See [OpenID Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata). This should match the `jwksUri` value of [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/). This configuration is mutually exclusive with `oidc.jwks`, per OIDC filter configuration.
    | oidc.jwks                   |  Required   | The JSON JWKS response from your OIDC provider’s `jwks_uri` URI which can be found in your OIDC provider's [configuration response](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse). Note that you have to escape the JSON string for this value (see example in the yaml template). This configuration is mutually exclusive with `oidc.jwks_uri`, per OIDC filter configuration.
    | oidc.callback               |  Required   | This value will be used as the `redirect_uri` param of the Authorization Code Grant Authentication Request. You must add this URL to the Redirection URI values for the Client pre-registered at the OIDC provider. See [OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). You must also prepare your [Istio VirtualService](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/) to ensure that this URL will get routed to `productpage`.
    | oidc.client_id              |  Required   | The Client ID of your OIDC Client.
    | oidc.client_secret          |  Required   | The Client Secret of your OIDC Client.
    | oidc.scopes                 |  Optional   | A list of scopes to request when the authservice obtains a token. In addition to this list, the `openid` scope will always be requested. This value will be used as the `scope` param of the Authorization Code Grant Authentication Request.
    | oidc.landing_page           |  Required   | After the user logs in, they will be redirected back to this URL. This should be the homepage URL of `productpage`.
    | oidc.logout.path            |  Optional   | A http request path that the authservice matches against to initiate logout. Whenever a request is made to that path, the authservice will remove the authservice-specific cookies and respond with a redirect to the configured `oidc.logout.redirect_to_uri`. Removing the cookies causes the user to be unauthenticated in future requests. If your application has its own logout controller, then you may wish to have that controller redirect to this path. If your application does not need its own logout controller, then the application's logout button/link's href can GET or POST directly to this path.
    | oidc.logout.redirect_to_uri |  Optional   | A URI specifying the destination to which the authservice will redirect any request made to the `oidc.logout.path`. For example, you may wish to redirect the logged out user to the homepage of your app, or to the [logout endpoint of your IDP](https://openid.net/specs/openid-connect-session-1_0.html#RPLogout). As with all redirects, the user's browser will perform a GET to this URI.
    | oidc.cryptor_secret         |  Required   | The secret to be used to encrypt and decrypt the authservice's browser cookies. Can be any string.
    | oidc.cookie_name_prefix     |  Optional   | The unique identifier of the authservice's browser cookies. Can be any string. Only needed when multiple apps in the same domain are each protected by their own authservice, to avoid cookie name conflicts.
    | oidc.id_token.preamble      |  Required   | The authentication scheme of the token. E.g. when the `preamble` is `Bearer` and `oidc.id_token.header` is `Authorization`, this header will be added to the request to the app: `Authorization: Bearer ID_TOKEN_VALUE`. Note that this value **MUST** be `Bearer`, case-sensitive, when `oidc.id_token.header` is `Authorization`. 
    | oidc.id_token.header        |  Required   | The name of the header that `authservice` adds to the request. This header will contain the ID Token. This value is case-insensitive. Note that this value **MUST** be `Authorization` for [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) to work.
    | oidc.timeout                |  Required   | The amount of time a user has to authenticate with the IDP before their authentication flow expires. The timer starts when an unauthenticated user visits an app protected by the `authservice`, keeps running while they are redirected to their IDP to log in, continues to run while they enter their username/password and potentially perform 2-factor authentication, and stops when the `authservice` receives the authcode from the OIDC provider's redirect. If it takes longer than the timeout for the authcode to be received, then the authcode will be rejected by the `authservice` causing the login to fail, even if the user successfully logged in to their IDP.

   Once the values have been substituted, apply the ConfigMap.
   
   `kubectl apply -f config/authservice-configmap-template.yaml`

1. Deploy the `bookinfo` and the `authservice` apps. Note that the `authservice` should be in the same Pod as `productpage`. 
Also note that, for the time being, there are some manual steps associated with specifying the `authservice` image (see comment in the yaml file). 

    `kubectl apply -f config/bookinfo-with-authservice.yaml`
    
    Wait for the pods to be in `Running` state.

1. Set up the Istio gateway and routing rules for the `bookinfo` app. Note that a `match` entry is required to include
   your Authentication Request callback URL (a.k.a the authservice ConfigMap's `oidc.callback` field mentioned above) in 
   `productpage`'s `VirtualService` definition.

    `kubectl apply -f config/bookinfo-gateway.yaml`

1. Confirm that the `bookinfo` app is running.
   After determining the [ingress IP and port](https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/#determining-the-ingress-ip-and-ports),
   use a browser to navigate to `productpage`, substituting the ingress host: `https://<INGRESS_HOST>/productpage`.

   Note that at this point, the `bookinfo` sample apps are deployed without security. 

1. Edit the `issuer` and `jwksUri` settings in [`config/bookinfo-authn-policy-template.yaml`](config/bookinfo-authn-policy-template.yaml). 
   Apply the Authentication Policy for the `bookinfo` application.

    `kubectl apply -f config/bookinfo-authn-policy-template.yaml`
    
   Now visit the `bookinfo` productpage app with a browser again. The page should not be accessible by an 
   unauthenticated user, giving a 401 error.
    
1. Add the [External Authorization filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter#config-http-filters-ext-authz)
   using an [Istio EnvoyFilter](https://istio.io/docs/reference/config/networking/v1alpha3/envoy-filter/). 
   This example shows how to insert the External Authorization filter in the sidecar of the `productpage` app.
   The filter is inserted before the [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/),
   which was added in the previous step.

    `kubectl apply -f config/external-authz-envoyfilter-sidecar.yaml`    
    
   Now visit the `bookinfo` productpage app with a browser again. The page should redirect an unauthenticated 
   user to the OIDC provider's login page. Upon login, the authenticated user should be redirected back 
   and gain access to the `productpage` with the OIDC token in the appropriate request header.
