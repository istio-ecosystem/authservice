# Create a base image that compile bazel c++ projects
FROM debian:buster as bazel-builder
COPY build/install-bazel.sh /build/
RUN chmod +x /build/install-bazel.sh && /build/install-bazel.sh

# Copy in only the necessary files for building.
FROM bazel-builder as auth-builder
COPY Makefile WORKSPACE /src/
COPY bazel /src/bazel
COPY config /src/config
COPY src /src/src
COPY test /src/test

# Build auth binary.
WORKDIR /src
RUN make bazel-bin/src/main/auth-server

# Create our final auth-server container image.
FROM debian:buster
RUN groupadd -r auth-server-grp && useradd -m -g auth-server-grp auth-server-usr

COPY --from=auth-builder /src/bazel-bin/src/main/auth_server /app/auth_server
COPY --from=auth-builder /src/bazel-bin/external/boost/libboost_chrono.so.1.70.0 /app/
COPY --from=auth-builder /src/bazel-bin/external/boost/libboost_context.so.1.70.0 /app/
COPY --from=auth-builder /src/bazel-bin/external/boost/libboost_coroutine.so.1.70.0 /app/
COPY --from=auth-builder /src/bazel-bin/external/boost/libboost_thread.so.1.70.0 /app/
ENV LD_LIBRARY_PATH=.
RUN chgrp auth-server-grp /app/* && chown auth-server-usr /app/* && chmod u+x /app/*

USER auth-server-usr
WORKDIR /app
ENTRYPOINT ["/app/auth_server"]
