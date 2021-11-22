load("//bazel:bazel.bzl", "xx_binary")

package(default_visibility = ["//visibility:public"])

# TODO(here): still same redefinition error. Some envoy entry level global opotion configured.
# Not just dependencies specified. Need to look into their BAZEL config again.
# alias(
#     name = "boringssl",
#     actual = "@boringssl_fips//:ssl"
# )

alias(
    name = "boringssl",
    actual = "@boringssl_fips//:ssl",
)

xx_binary(
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

