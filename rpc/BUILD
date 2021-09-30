load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2

proto_library(
  name = "healthcheck_proto_lib",
  srcs = ["healthcheck.proto"],
)

cc_proto_library(
  name = "healthcheck_cc_proto",
  deps = [":healthcheck_proto_lib"],
)

cc_grpc_library(
  name = "healthcheck_cc_grpc",
  srcs = [":healthcheck_proto_lib"],
  deps = [":healthcheck_cc_proto"],
  grpc_only = True,
)
