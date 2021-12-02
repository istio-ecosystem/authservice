load("//bazel:bazel.bzl", "authsvc_cc_binary")

package(default_visibility = ["//visibility:public"])

authsvc_cc_binary(
    name = "auth_server",
    srcs = ["auth_server.cc"],
    deps = [
        "//src/config",
        "//src/service:serviceimpl",
        "@com_github_abseil-cpp//absl/flags:parse",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_proto",
    ],
)
