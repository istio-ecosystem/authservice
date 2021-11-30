# The docker image for the build environment for authservice.
FROM debian:buster

COPY build/install-bazel.sh /build/
RUN chmod +x /build/install-bazel.sh && /build/install-bazel.sh
RUN apt-get update && \
  apt-get -y install make cmake ninja-build build-essential \
  curl gnupg lsb-release wget software-properties-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install LLVM/Clang 12.
RUN wget https://apt.llvm.org/llvm.sh && \
  chmod +x llvm.sh && \
  bash ./llvm.sh 12
