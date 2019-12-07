# Bookinfo with Authservice Example (Sidecar integration)

This doc shows how to integrate Authservice into an Istio system deployed on Kubernetes.

This demo uses the [Istio Bookinfo sample application](https://istio.io/docs/examples/bookinfo/).

This demo takes advantage of an Istio feature set that gives the ability to inject http filters on 
Sidecars. This feature set was released in Istio 1.3.0.

Things needed before starting:

- A Kubernetes cluster that is compatible with Istio 1.3 or newer
- An OIDC provider configured to support Authorization Code grant type. The urls and credentials for this 
provider will be needed to configure Authservice.

 
### Pre-requisites:
1. Download Istio 1.3 or greater. For example:

   [`scripts/download-istio-1.4.sh`](scripts/download-istio-1.4.sh)

1. Install Istio and enable sidecar injection for the namespace where services will be deployed. For example, 
   one could install the Istio demo like this:

   [`scripts/install-istio.sh`](scripts/install-istio.sh)
    
1. If certs signed by a known CA cannot be obtained, generate self signed certs for the ingress gateway. For example:

   [`scripts/generate-self-signed-certs-for-ingress-gateway.sh`](scripts/generate-self-signed-certs-for-ingress-gateway.sh)


### Deploy Bookinfo Using the Authservice for Token Acquisition 

The goal of these steps is the protect the `productpage` service with OIDC authentication provided by the mesh.

These steps demonstrate how to:
1. Configure the Authservice to provide token acquisition for end-users of the `productpage` service
1. Deploy the Authservice along with the Bookinfo sample app, in the same pod as the `productpage` service
1. Configure Istio authentication for the `productpage` service, using standard Istio features
1. Activate the Authservice by adding it to the data path of the `productpage` service

To keep things simple, we deploy everything into the default namespace and we don't enable authentication for the
other services of the Bookinfo app aside from `productpage`.

1. Setup a `ConfigMap` for Authservice. Fill in [`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)
   to include the OIDC provider's configurations. Currently, only the `oidc` filter can be configured in the `ConfigMap`. See [here](../docs/README.md)
   for the description of each field. Once the values have been substituted, apply the ConfigMap.
   
   `kubectl apply -f config/authservice-configmap-template-for-authn.yaml`

1. The Github Package Registry does not work seamlessly with k8s until [issue #870](https://github.com/kubernetes-sigs/kind/issues/870)
   is fixed and released. As a workaround, manually `docker pull` the latest authservice image from
   [https://github.com/istio-ecosystem/authservice/packages](https://github.com/istio-ecosystem/authservice/packages)
   and push it to your own image registry (e.g. Docker Hub).
   See the ["Using the authservice docker image" section in the README.md](https://github.com/istio-ecosystem/authservice/blob/master/README.md#using-the-authservice-docker-image)
   for more information.

1. Edit [`config/bookinfo-with-authservice-template.yaml`](config/bookinfo-with-authservice-template.yaml)
   and replace the authservice image name with the reference to the image in your registry from the step above.
   Then apply the file to deploy Bookinfo and Authservice.

    `kubectl apply -f config/bookinfo-with-authservice-template.yaml`
    
    Wait for the new pods to be in `Running` state.
    
    Note that the Authservice will be deployed in the same Pod as `productpage`.

1. If the `callback` or `logout` paths in [`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)
   were edited in a previous step, then edit those same paths in [`config/bookinfo-gateway.yaml`](config/bookinfo-gateway.yaml).
   Otherwise, no edit is needed. When ready, apply the file to create the ingress gateway and routing rules for Bookinfo:

    `kubectl apply -f config/bookinfo-gateway.yaml`

1. Next confirm that the Bookinfo app is running.
   After determining the [ingress IP and port](https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/#determining-the-ingress-ip-and-ports),
   use a browser to navigate to the `productpage` UI, substituting the ingress host: `https://<INGRESS_HOST>/productpage`.

   Note that at this point, the Bookinfo sample apps are deployed without any authentication,
   and without activating the Authservice, so the `productpage` UI should show in the browser without being
   asked to authenticate.

1. Edit the `issuer` and `jwksUri` settings in [`config/bookinfo-authn-policy-template.yaml`](config/bookinfo-authn-policy-template.yaml). 
   Apply the Authentication Policy for the Bookinfo application:

    `kubectl apply -f config/bookinfo-authn-policy-template.yaml`
    
   Wait about a minute for the policy to take effect, then visit the Bookinfo `productpage` UI with a browser again.
   The page should not be accessible by an unauthenticated user, giving a 401 `Origin authentication failed.` error message.

   The UI is now protected by Istio's authentication JWT checking feature, but nothing is helping the user authenticate,
   acquire tokens, save those tokens, or transmit those tokens to the `productpage` service. Authservice to the rescue!

1. We're ready to put the Authservice into the data path for `productpage` by adding
   the [External Authorization filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter#config-http-filters-ext-authz)
   using an [Istio EnvoyFilter](https://istio.io/docs/reference/config/networking/v1alpha3/envoy-filter/). 
   This example shows how to insert the External Authorization filter in the sidecar of the `productpage` app.
   The filter is inserted before the [Istio Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/),
   which was added in the previous step.

    `kubectl apply -f config/productpage-external-authz-envoyfilter-sidecar.yaml`

   Wait about a minute for the policy to take effect, then visit the Bookinfo `productpage` UI with a browser again.
   This time the browser should redirect to the OIDC provider's login page. Upon login, the authenticated user should
   be redirected back and gain access to the `productpage`.
   
   This works because the Authservice is involved in every request to the `productpage` service.
   1. On the first request, the Authservice detected that the user is unauthenticated
   1. The Authservice redirected the browser to the OIDC Provider's authorization endpoint, which redirected the browser
      again to the OIDC Provider's login page
   1. After the user logged in, the OIDC provider redirected the browser back to the `productpage` service with an
      authorization code as a query parameter
   1. The Authservice intercepted this OIDC provider callback redirect and captured the authorization code from
      the query parameter
   1. The Authservice exchanged the authorization code for tokens by making a call from the Authservice directly to the
      OIDC provider (as a "backend-to-backend request", rather than another browser redirect)
   1. The Authservice redirected the browser back to the landing page of the `productpage` service
   1. The Authservice received the request to the landing page and injected the OIDC ID token into the `Authentication`
      http request header of that request before allowing the request to continue on to the `productpage`
   1. Before the request continues to the `productpage`, the Istio authentication policy validated the token
      from the `Authentication` request header and, since it was valid, allowed the request to go to the `productpage`
   1. The `productpage` renders its UI in the http response and the browser shows the UI

   The Authservice saves its state into the user's browser cookies, so future `productpage` page loads in the browser
   will not require authentication until the OIDC tokens expire. To log out and remove the cookies immediately,
   point the browser to `https://<INGRESS_HOST>/authservice_logout` (this path is configurable in the Authservice's
   ConfigMap).
