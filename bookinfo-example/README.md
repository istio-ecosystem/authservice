# Bookinfo with Authservice Example

This doc shows how to integrate Authservice into an Istio system deployed on Kubernetes.

This demo uses the [Istio Bookinfo sample application](https://istio.io/docs/examples/bookinfo/).

This demo takes relies on Istio [external authorization provider](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/), released since 1.9.

### Pre-requisites:

1. Prepare your OIDC provider configuration. In our example, we use Google as identity provider.
Follow [instructions](https://developers.google.com/identity/protocols/oauth2/openid-connect) to
create one.

   ```shell
   export OIDC_CLIENT_ID="<your-client-id>"
   export OIDC_CLIENT_SECRET="<your-client-secret>"
   ```

1. Install Istio 1.9 or later.

   ```shell
   istioctl install -y
   kubectl label namespace default istio-injection=enabled --overwrite
   ```

1. In our example, we use a self signed certificate at localhost for easy setup.
This is used to terminate HTTPS at the ingress gateway since OIDC requires client callback
URI to be hosted on a protected endpoint.

   ```shell
   bash ./scripts/generate-self-signed-certs-for-ingress-gateway.sh
   ```

1. Configure the Istio mesh config with an [external authorization provider](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/).

   ```shell
   kubectl edit cm -n istio-system
   ```
   
   Change the mesh config with the config below.

   ```yaml
   data:
   mesh: |-
      extensionProviders:
      - name: "authservice-grpc"
         envoyExtAuthzGrpc:
         service: authservice.default.svc.cluster.local
         port: "10003"
   ```

1. Install authservice via Helm.

   ```shell
   helm template authservice \
      --set oidc.clientID=${OIDC_CLIENT_ID} \
      --set oidc.clientSecret=${OIDC_CLIENT_SECRET} \
      | kubectl apply -f -
   ```

1. Access product page via port-forwarding at local host.

   ```shell
   kubectl port-forward service/istio-ingressgateway 8443:443 -n istio-system
   ```

   At your browser visit the page at https://localhost:8443/productpage.

### Further Protect via RequestAuthentication and Authorization Policy

Istio native RequestAuthentication and Authorization policy can be used configure which end user
can access specific apps, at specific paths. For example, you can apply the sample configuration
to only allow authenticated request to access productpage service.

```shell
kubectl apply -f ./config/productpage-authn-authz.yaml
```

## Configure OIDC flow at Ingress Gateway

TODO(incfly): write it up with sample config and setup.

## :warning: The REST documnetation needs updates.

## Deploy Bookinfo Using the Authservice for Token Acquisition (Sidecar integration)

The goal of these steps is the protect the `productpage` service with OIDC authentication provided by the mesh.

These steps demonstrate how to:

1. Configure the Authservice to provide token acquisition for end-users of the `productpage` service
1. Deploy the Authservice along with the Bookinfo sample app, in the same pod as the `productpage` service
1. Configure Istio authentication for the `productpage` service, using standard Istio features
1. Activate the Authservice by adding it to the data path of the `productpage` service

To keep things simple, we deploy everything into the default namespace and we don't enable authentication for the
other services of the Bookinfo app aside from `productpage`.

1. Prepare your OIDC provider configuration. For our example, we are using Google as IdP.
Follow [instructions](https://developers.google.com/identity/protocols/oauth2/openid-connect) to create one
if needed.

1. Setup a `ConfigMap` for Authservice. Fill in [`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)
   to include the OIDC provider's configurations. Currently, only the `oidc` filter can be configured in the 
   `ConfigMap`. See [here](../docs/README.md) for the description of each field. Once the values
   have been substituted, apply the `ConfigMap`.
   
   `kubectl apply -f config/authservice-configmap-template-for-authn.yaml`
    ### <a name="authservice-image"></a> 

1. Apply the authservice deployment.

    `kubectl apply -f config/bookinfo-with-authservice-template.yaml`
    
    Wait for the new pods to be in `Running` state.
    
    Note that the Authservice will be deployed in the same Pod as `productpage`.

1. Configure the product page to enable authservice via a `CUSTOM` action authorization policy.

   ```shell
   kubectl apply -f ./config/ext-authz-productpage.yaml
   ```

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

1. We're ready to put the Authservice into the data path for `productpage` by 
   using an [Istio ExternalAuthorization](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/). 

    `kubectl apply -f config/productpage-external-authz-envoyfilter-sidecar.yaml`

1. Access the application at the `localhost:8443` via port forwarding, https://localhost:8443/productpage.

   ```shell
   kubectl port-forward service/istio-ingressgateway 8443:443 -n istio-system
   ```

   The browser should redirect to the OIDC provider's login page. Upon login, the authenticated user should
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
     This `ConfigMap` has several notable changes compared to the previous `ConfigMap` for authentication only ([`config/authservice-configmap-template-for-authn.yaml`](config/authservice-configmap-template-for-authn.yaml)).

     1. It updates the value at the key `chains[*].filters[*].oidc.scopes` which contains a list of strings of scopes that the Authservice is enabled to request on behalf of the service it is protecting. In this example, the Authservice will request `productpage.read` and `reviews.read`. 

     1. It adds a key `chains[*].filters[*].oidc.access_token` which is an object defining a preamble and a header name to provide the access token as a header after receipt. Note that this example assumes that the access token will be returned by the OIDC Provider in JWT format. Please check the documentation for your OIDC Provider's Authorization endpoint. In this example, the access token is configured to be sent on the header named `Authorization`. This aligns with the default header name used by Istio's Authentication `Policy` to validate JWT tokens.

     1. It has changed the value at the key `chains[*].filters[*].oidc.id_token`. This moves the ID token to a different request header compared to the `ConfigMap` for authentication only used previously. Now the ID token will be sent on a header called `x-id-token`. The header name `x-id-token` itself does not have any special meaning.

1. Configure the Bookinfo app

    1. Edit [`config/bookinfo-with-authservice-template.yaml`](config/bookinfo-with-authservice-template.yaml)

       Supply a Authservice image. This has previously been described in the steps ["Deploy Bookinfo Using the Authservice for Token Acquisition"](#authservice-image) from above. 

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

One might prefer to use the Authservice at the gateway level to provide a single login flow for all applications inside an Istio mesh, rather than using it at the sidecar level.

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
1. The `ConfigMap` should be created in the `istio-system` namespace to make it accessible to the authservice container in the `istio-ingressgateway` pod.
1. The `ext_authz` envoy filter will have to be inserted into the gateway's filter chain. E.g.:
   ```
   apiVersion: networking.istio.io/v1alpha3
   kind: EnvoyFilter
   metadata:
     name: ingress-token-service-filter
     namespace: istio-system # note: the namespace has changed
   spec:
     workloadSelector:
       labels:
         istio: ingressgateway # note: target gateway pod's label
     configPatches:
     - applyTo: HTTP_FILTER
       match:
         context: GATEWAY
   # ... the rest is the same as before
   ```
1. The Authservice will no longer be required to be deployed at the Sidecar level alongside the application. 
1. The path part of the configured `callback_uri`, and if configured, the `logout.path`, must be paths that are routable to the app by the ingress gateway's `VirtualService`, or else the Authservice at the gateway will not receieve those requests and will not be able to process them. This is a perhaps counter-intuitive since the Authservice container is no longer running in the app's pod, so it may not feel like this is needed, but it is required.

Better user experience and more sample configs will be added in the future.

## FAQ

Where I can find the authservice images?

1. The Github Package Registry does not work seamlessly with k8s until [issue #870](https://github.com/kubernetes-sigs/kind/issues/870)
   is fixed and released. As a workaround, manually `docker pull` the latest authservice image from
   [https://github.com/istio-ecosystem/authservice/packages](https://github.com/istio-ecosystem/authservice/packages)
   and push it to an accessible image registry (e.g. Docker Hub).
   See the ["Using the authservice docker image" section in the README.md](https://github.com/istio-ecosystem/authservice/blob/master/README.md#using-the-authservice-docker-image)
   for more information.
