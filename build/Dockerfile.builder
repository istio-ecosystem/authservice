# Create a base image that compile bazel c++ projects
FROM debian:buster as bazel-builder
COPY build/install-bazel.sh /build/
RUN chmod +x /build/install-bazel.sh && /build/install-bazel.sh

# Build auth binary.
FROM bazel-builder as auth-builder
COPY . /src
WORKDIR /src
RUN make bazel-bin/src/main/auth-server

# Create our final auth-server container image.
FROM debian:buster
RUN groupadd -r auth-server-grp && useradd -m -g auth-server-grp auth-server-usr

COPY --from=auth-builder /src/bazel-bin/src/main/auth_server /app/auth_server
RUN chgrp auth-server-grp /app/auth_server && chown auth-server-usr /app/auth_server && chmod u+x /app/auth_server

USER auth-server-usr
WORKDIR /app
ENTRYPOINT ["/app/auth_server"]
