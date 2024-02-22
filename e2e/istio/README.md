# Istio e2e tests

The [Istio](https://istio.io/) end-to-end tests are designed to verify the integration of the
Auth Service with Istio. They deploy a [KinD](https://kind.sigs.k8s.io/) Kubernetes cluster where Istio and the Auth Service are
installed and then run a series of tests to verify the integration. The following diagram shows the setup:

```mermaid
flowchart LR
    subgraph "KinD Cluster"
        subgraph http-echo
            sidecar
            app
        end
        istio-ingress["istio-ingress\n(nodeport:30000)"]
        authservice
        redis
        keycloak["keycloak\n(nodeport:30001)"]
    end
    subgraph "Host"
        test-suite
    end

    sidecar --> app
    sidecar -.OIDC.-> authservice
    authservice -.-> sidecar
    authservice --sessions--> redis
    authservice --OIDC-->keycloak
    istio-ingress --> sidecar
    test-suite --> istio-ingress
    test-suite --user login--> keycloak
```

## Accessing the cluster from the host machine

For convenience, the Kind cluster Kubeconfig is generated in `cluster/kubeconfig`, and  an be used to access
the cluster from the host machine. For example:

```bash
$ kubectl --kubeconfig cluster/kubeconfig get namespaces
```

## Manually creating and destroying the cluster

The Kind cluster is automatically created and destroyed when running the test suites. However, it is
possible to manually create and destroy the cluster by running the following commands:

```bash
$ make kind-create
$ make kind-destroy
```

This is useful for debugging purposes.
