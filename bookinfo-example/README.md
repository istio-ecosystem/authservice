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
1. Download Istio [`./scripts/download-istio-1.3.sh`](./scripts/download-istio-1.3.sh).

1. Install Istio [`./scripts/install-istio.sh`](./scripts/install-istio.sh).

1. If you do not have certs signed by a known CA, you can generate self signed certs for the ingress 
gateway [`./scripts/generate-self-signed-certs-for-ingress-gateway.sh`](./scripts/generate-self-signed-certs-for-ingress-gateway.sh).


#### Configuring and Integrating `authservice` with `bookinfo`

1. Setup a `ConfigMap` for `authservice`. Fill in [`config/authservice-configmap-template.yaml`](config/authservice-configmap-template.yaml) 
to include your OIDC provider's configurations. Currently, you can only include the `oidc` filter config in the `ConfigMap`, 
see the following table for the description of each field:    
    
| Field              | Description                                                                                                                                                                                                                                                                                                                                                                                                                     |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| oidc.authorization | The Authorization Endpoint of your OIDC provider.                                                                                                                                                                                                                                                                                                                                                                               |
| oidc.token         | The Token Endpoint of your OIDC provider.                                                                                                                                                                                                                                                                                                                                                                                       |
| oidc.jwks          | The URL of your OIDC provider’s public key set to validate signature of the JWT. See [OpenID Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata). This should match the `jwksUri` value of [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/).                                                                                                               |
| oidc.callback      | This value will be used as the `redirect_uri` param of the Authorization Code Grant Authentication Request. You must add this URL to the Redirection URI values for the Client pre-registered at the OIDC provider. See [OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). You must also prepare your [Istio VirtualService](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/) to ensure that this URL will get routed to `productpage`.  |
| oidc.landing_page  | After the user logs in, they will be redirected back to this URL. This should be the homepage URL of `productpage`.                                                                                                                                                                                                                                                                                                               |
| oidc.client_id     | The Client ID of your OIDC Client.                                                                                                                                                                                                                                                                                                                                                                                              |
| oidc.client_secret | The Client Secret of your OIDC Client.                                                                                                                                                                                                                                                                                                                                                                                          |
| oidc.scopes        | A list of scopes to request. In addition to this list, the `openid` scope will always be requested. This value will be used as the `scope` param of the Authorization Code Grant Authentication Request.                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                                                                                                                  
        
   Once the values have been substituted, apply the ConfigMap.
   
   `kubectl apply -f ./config/authservice-configmap-template.yaml`
    
2. Deploy the `bookinfo` apps where the `authservice` is deployed in the same Pod as `productpage`. 
Wait for the `bookinfo` Pods to be in `Running` state.

    `kubectl apply -f config/bookinfo-with-authservice.yaml`
    
3. Set up the Istio gateway and routing rules for the `bookinfo` app. Note that you have to add matching logic to include
your Authentication Request callback URL (a.k.a the authservice ConfigMap's `oidc.callback` field mentioned above) in 
`productpage`'s `VirtualService` definition.

    `kubectl apply -f config/bookinfo-gateway.yaml`  

4. At this point, the `bookinfo` sample apps are deployed without security. 
After you [determine the ingress IP and port](https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/#determining-the-ingress-ip-and-ports),
you can use a browser to navigate to `productpage`, substituting the ingress host: `https://<INGRESS_HOST>/productpage`.

5. Fill in [`config/bookinfo-authn-policy-template.yaml`](config/bookinfo-authn-policy-template.yaml) to include the configurations as well. 
Apply the Authentication Policy for the `bookinfo` application.

    `kubectl apply -f ./config/bookinfo-authn-policy-template.yaml`
    
    Now visit the `bookinfo` productpage app with a browser again. The page should not be accessible by an 
    unauthenticated user (due to 401 error).
    
6. Add the [External Authorization filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter#config-http-filters-ext-authz)
using [Istio EnvoyFilter](https://istio.io/docs/reference/config/networking/v1alpha3/envoy-filter/). 
This example shows how to insert the External Authorization filter before the [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) 
applied in the last step to the Sidecar to `productpage` app.  

    `kubectl apply -f ./config/external-authz-envoyfilter-sidecar.yaml`    
    
    Now visit the `bookinfo` productpage app with a browser again. The page should redirect an unauthenticated 
    user to the OIDC provider's login page. Upon login, the authenticated user should be redirected back 
    and gain access to the `productpage`. 
    
    

