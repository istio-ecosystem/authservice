# Copyright Istio Authors
# Licensed under the Apache License, Version 2.0 (the "License")

FROM gcr.io/distroless/cc:nonroot

COPY ./build_release/auth_server /app/auth_server
USER nonroot:nonroot
ENTRYPOINT ["/app/auth_server"]
