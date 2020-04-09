# Bookinfo with Authservice Example

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


## Deploy Bookinfo Using the Authservice for Token Acquisition (Sidecar integration)

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
   for the description of each field. Once the values have been substituted, apply the `ConfigMap`.
   
   `kubectl apply -f config/authservice-configmap-template-for-authn.yaml`
    ### <a name="authservice-image"></a> 
1. The Github Package Registry does not work seamlessly with k8s until [issue #870](https://github.com/kubernetes-sigs/kind/issues/870)
   is fixed and released. As a workaround, manually `docker pull` the latest authservice image from
   [https://github.com/istio-ecosystem/authservice/packages](https://github.com/istio-ecosystem/authservice/packages)
   and push it to an accessible image registry (e.g. Docker Hub).
   See the ["Using the authservice docker image" section in the README.md](https://github.com/istio-ecosystem/authservice/blob/master/README.md#using-the-authservice-docker-image)
   for more information.

1. Edit [`config/bookinfo-with-authservice-template.yaml`](config/bookinfo-with-authservice-template.yaml)
   and replace the authservice image name with the reference to the image in the registry from the step above.
   Then apply the file to deploy Bookinfo and Authservice.

    `kubectl apply -f config/bookinfo-with-authservice-template.yaml`
    
    Wait for the new pods to be in `Running` state.
    
    Note that the Authservice will be deployed in the same Pod as `productpage`.

1. If the `callback` or `logout` paths in [`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)
   were edited in a previous step, then edit those same paths in [`config/bookinfo-gateway.yaml`](config/bookinfo-gateway.yaml).
   Otherwise, no edit is needed. When ready, apply the file to create the ingress gateway and routing rules for Bookinfo:

    `kubectl apply -f config/bookinfo-gateway.yaml`

    Note that session affinity (via Istio `DestinationRule`) is required when you deploy multiple instances of `productpage`, 
    which ensures that the requests from the same user-agent reach the same instance of `productpage`. 
    This is required because Authservice currently only supports in-memory session storage.
    
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
   1. The Authservice redirected the browser back to the originally requested path of the `productpage` service
   1. The Authservice received the request to the `productpage` and injected the OIDC ID token into the `Authentication`
      http request header of that request before allowing the request to continue on to the `productpage`
   1. Before the request continues to the `productpage`, the Istio authentication policy validated the token
      from the `Authentication` request header and, since it was valid, allowed the request to go to the `productpage`
   1. The `productpage` renders its UI in the http response and the browser shows the UI

   The Authservice sets a session ID cookie on user's browser, so future `productpage` page loads in the browser
   will not require authentication until the OIDC tokens expire. To log out and remove the current user's session immediately,
   point the browser to `https://<INGRESS_HOST>/authservice_logout` (this path is configurable in the Authservice's
   `ConfigMap`).

## Deploy Bookinfo Using the Authservice for Token Acquisition + Authorization (Sidecar integration)

The authentication tokens acquired using the Authservice can also be used for authorization, provided that they contain 
scopes. This section demonstrates how to leverage the Authservice to relay the authorization token to protected apps and services. 
  
1. Configure the Authservice to provide authorization. It must both request scopes for protected resources and also attach the authorization token as a header.

    1. Setup a `ConfigMap` for Authservice. Fill in [`config/authservice-configmap-template-for-authn-and-authz.yaml`](config/authservice-configmap-template-for-authn-and-authz.yaml) to include the OIDC provider's configurations. Currently, only the `oidc` filter can be configured in the `ConfigMap`. See [here](../docs/README.md) for the description of each field. Once the values have been substituted, apply the `ConfigMap`.

    ```bash
    kubectl apply -f config/authservice-configmap-template-for-authn-and-authz.yaml
    ```
     This `ConfigMap` has two notable additions compared to the `ConfigMap` for authentication only ([`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)).

     1. It contains a key `chains[*].filters[*].oidc.scopes` which contains a list of strings of scopes that the Authservice is enabled to request on behalf of the service it is protecting. In this example, the Authservice will request `productpage.read`. 

     1. It contains a key `chains[*].filters[*].oidc.access_token` which is an object defining a preamble and a header name to provide the access token as a header after receipt.

1. Configure the Bookinfo app

    1. Edit [`config/bookinfo-with-authservice-template.yaml`](config/bookinfo-with-authservice-template.yaml)

       1. Supply a Authservice image. This has previously been described in the steps ["Deploy Bookinfo Using the Authservice for Token Acquisition"](#authservice-image) from above. 

    1. Deploy Bookinfo and Authservice by applying the Authservice deployment file.
       
       ```bash
       kubectl apply -f config/bookinfo-with-authservice-template.yaml
       watch kubectl get pods -A
       ```
          
    1. Wait for the new pods to be in `Running` state. Note that the Authservice will be deployed in the same Pod as `productpage`.

    1. If the `callback` or `logout` paths in [`config/authservice-configmap-template-for-authn-and-authz.yaml`](config/authservice-configmap-template-for-authn-and-authz.yaml) were edited in a previous step, then edit those same paths in [`config/bookinfo-gateway.yaml`](config/bookinfo-gateway.yaml). Otherwise, no edit is needed. When ready, apply the file to create the ingress gateway and routing rules for Bookinfo:
       ```bash
       kubectl apply -f config/bookinfo-gateway.yaml
       ```
       
       Note that session affinity (via Istio `DestinationRule`) is required when you deploy multiple instances of `productpage`, 
       which ensures that the requests from the same user-agent reach the same instance of `productpage`. 
       This is required because Authservice currently only supports in-memory session storage.
       
    1. Next confirm that the Bookinfo app is running.
       
       After determining the [ingress IP and port](https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/#determining-the-ingress-ip-and-ports), use a browser to navigate to the `productpage` UI, substituting the ingress host: `https://<INGRESS_HOST>/productpage`.
    
       Note that at this point, the Bookinfo sample apps are deployed without any authentication, and without activating the Authservice, so the `productpage` UI should show in the browser without being asked to authenticate.

1. Enable Authz

    1. Apply the authentication policy, which creates a `Policy` that enforces authentication on the services under `targets`. Replace the fields under `jwt`(`issuer` and `jwksUri` settings).
    
       ```bash
       kubectl apply -f config/bookinfo-authn-policy-template-adding-reviews.yaml
       ```
       
    1. Apply the authorization policy, creating one `AuthorizationPolicy` each for `productpage` and `reviews`. 
       
        ```bash
       kubectl apply -f config/bookinfo-authz-using-istio-authorization-policy.yaml
       ```
       
       Note: `config/bookinfo-authz-using-deprecated-rbac.yaml` can also be used, but will be removed in Istio 1.6.
    
    | ⚠️Note⚠️: Unless logout is setup prior these steps, multiple users with different scopes will be required. |
    | --- |
    
    1. Navigate to the `productpage`, substituting the ingress host: `https://<INGRESS_HOST>/productpage`. Because authentication is enabled, the user is prompted to provide their credentials for the identity provider given in the `ConfigMap`.
    
    1. Assuming the authenticated user has neither `productpage.read` nor the `reviews.read` scopes, then they should not see the `productpage` but instead should be met with an Istio unauthorized message `"RBAC: access denied"`.
    
    1. Add the scope `productpage.read` to a different user and login. The user should be able to view the `productpage` sans reviews.
       * A message should appear on the `productpage` stating `"Sorry, product reviews are currently unavailable for this book."` This is because the authenticated user is not authorized to access the `reviews` service and would require the scope `reviews.read` in order to access it.
    
#### Authz with `review` service (optional)

1. Patch `productpage` to forward authorization headers to other services.
    1. Clone https://github.com/istio/istio.
    1. Make the changes below and build the image using `/samples/bookinfo/src/productpage/Dockerfile`.
       ```diff
        --- a/samples/bookinfo/src/productpage/productpage.py
        +++ b/samples/bookinfo/src/productpage/productpage.py
        @@ -182,7 +182,9 @@ def getForwardHeaders(request):
             if 'user' in session:
                 headers['end-user'] = session['user']
        
        -    incoming_headers = ['x-request-id', 'x-datadog-trace-id', 'x-datadog-parent-id', 'x-datadog-sampled']
        +    incoming_headers = ['x-request-id',
        +                        'x-datadog-trace-id', 'x-datadog-parent-id', 'x-datadog-sampled',
        +                        'authorization']
        
             # Add user-agent to headers manually
             if 'user-agent' in request.headers:
        ```
           
    1. Tag and push the image created to an accessible registry.
    1. Replace the `productpage` image in `config/bookinfo-with-authservice-template.yaml` with the image built above.
    1. Reapply the deployment file.
          ```bash
          kubectl apply -f config/bookinfo-with-authservice-template.yaml
          ```
       
1. Log in to the `productpage` app as previously done, using a user authorized with both scopes `productpage.read` and `reviews.read`. The user will be authorized to view the `productpage` with reviews.
   
   There are three scenarios once authenticated:
   
   | Behavior                                        | productpage.read | reviews.read |
   |-------------------------------------------------|------------------|--------------|
   | Page is fully viewable                          | x                | x            |
   | Page is viewable but reviews are not            | x                |              |
   | Istio unauthorized message: RBAC: access denied |                  |              |


For a full list of Authservice configuration options, see the [configuration docs](../docs/README.md).

## Istio Ingress-gateway integration
One might want to use the Authservice at the gateway level to provide a single login flow for all applications inside an Istio mesh, a.k.a. using it as an Auth API Gateway.

### Additional Pre-requisites:

1. External Load Balancer: Currently Authservice can be used at either the sidecar or gateway. However, there may be issues when it is used at the gateway in an installation with multiple gateway instances. These issues are due to session state being stored in-memory, and only happen when users go from talking to one Authservice instance to another mid-session. Such problems can be avoided it the gateway instances are placed behind a load balancer that supports session affinity.

1. Installing Authservice in Istio Ingress-gateway: Currently, there is not yet a native way to install Authservice into the Istio Ingress-gateway. A more integrated way to install Authservice as part of the Gateway will be considered in the future. However, you can manually modify the `Deployment` of `istio-ingressgateway` to add the Authservice container:

```
containers:
        # Adding the authservice container
        - name: authservice
          image: AUTHSERVICE_IMAGE
          imagePullPolicy: Always
          ports:
            - containerPort: 10003
          volumeMounts:
            - name: authcode-sample-app-authservice-configmap-volume
              mountPath: /etc/authservice
        - name: istio-proxy
          ...
```          

### Notes:
The steps of using Authservice at the Ingress-gateway are roughly the same as the Sidecar integration steps detailed above except for these major differences:
1. The Istio Authentication Policy will have to target the Ingress-gateway, which will result in a JWT AuthN filter being added to the gateway.
1. The `ext_authz` envoy filter will have to be inserted into the gateway's filter chain (the Istio `EnvoyFilter` config will have to target the gateway).
1. The Authservice will no longer be required to be deployed at the Sidecar level alongside the application. 

Better user experience and more sample configs will be added in the future.
