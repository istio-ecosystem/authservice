# Bookinfo with Authservice example (Sidecar integration)

This doc shows how to integrate Authservice into an Istio system deployed on Kubernetes.

This demo takes advantage of an Istio feature set that gives the ability to inject http filters on 
Sidecars. This feature set was released in Istio 1.3.0.

Things needed before starting:

- A Kubernetes cluster that is compatible with Istio 1.3 or newer
- An OIDC provider configured to support Authorization Code grant type. The urls and credentials for this 
provider will be needed to configure Authservice.

 
#### Pre-requisites:
1. Download Istio 1.3 or greater. For example:

   [`scripts/download-istio-1.4.sh`](scripts/download-istio-1.4.sh)

1. Install Istio and enable sidecar injection for the namespace where services will be deployed. For example, 
   you could install the Istio demo like this:

   [`scripts/install-istio.sh`](scripts/install-istio.sh)
    
1. If certs signed by a known CA cannot be obtained, generate self signed certs for the ingress gateway. For example:

   [`scripts/generate-self-signed-certs-for-ingress-gateway.sh`](scripts/generate-self-signed-certs-for-ingress-gateway.sh)


#### Configuring and Integrating Authservice with `bookinfo`

1. Setup a `ConfigMap` for Authservice. Fill in [`config/authservice-configmap-template.yaml`](config/authservice-configmap-template.yaml)
to include the OIDC provider's configurations. Currently, only the `oidc` filter can be configured in the `ConfigMap`. See [here](../docs/README.md)
for the description of each field. Once the values have been substituted, apply the ConfigMap.
   
   `kubectl apply -f config/authservice-configmap-template.yaml`

1. Deploy the `bookinfo` and the Authservice apps. Note that the Authservice should be in the same Pod as `productpage`.
Edit `config/bookinfo-with-authservice.yaml` and replace the authservice image name (see comment in the yaml file). See
"Using the authservice docker image" section in the [README.md](https://github.com/istio-ecosystem/authservice/blob/master/README.md#using-the-authservice-docker-image)
for more information.

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
