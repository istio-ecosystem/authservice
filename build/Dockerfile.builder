# Create a base image that compile bazel c++ projects
FROM debian:buster as bazel-builder
COPY build/install-bazel.sh /build/
RUN chmod +x /build/install-bazel.sh && /build/install-bazel.sh
RUN apt-get update && apt-get -y install make cmake ninja-build build-essential

# Copy in only the necessary files for building.
FROM bazel-builder as auth-builder
COPY . /src/

# Build auth binary.
WORKDIR /src
RUN make bazel-bin/src/main/auth_server

# Create our final auth-server container image.
FROM debian:buster
RUN groupadd -r auth-server-grp && useradd -m -g auth-server-grp auth-server-usr

# Install dependencies
RUN apt update && apt upgrade -y && apt install -y --no-install-recommends \
    ca-certificates  \
    && rm -rf /var/lib/apt/lists/*

COPY --from=auth-builder \
     /src/bazel-bin/src/main/auth_server \
     /src/bazel-bin/external/boost/libboost_chrono.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_context.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_coroutine.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_thread.so.1.70.0 \
     /app/

ENV LD_LIBRARY_PATH=.
RUN chgrp auth-server-grp /app/* && chown auth-server-usr /app/* && chmod u+x /app/*

USER auth-server-usr
WORKDIR /app
ENTRYPOINT ["/app/auth_server"]
