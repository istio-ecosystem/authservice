# Copyright Istio Authors
# Licensed under the Apache License, Version 2.0 (the "License")

FROM gcr.io/distroless/cc:nonroot

COPY ./build_release/auth_server /app/auth_server
# We can't use nonroot:nonroot here since in K8s:
# https://github.com/kubernetes/kubernetes/blob/98eff192802a87c613091223f774a6c789543e74/pkg/kubelet/kuberuntime/security_context_others.go#L49.
USER 65532:65532
ENTRYPOINT ["/app/auth_server"]
