FROM debian:buster
COPY install-bazel.sh /build/
RUN chmod +x /build/install-bazel.sh && /build/install-bazel.sh
