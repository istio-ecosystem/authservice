load("//bazel:bazel.bzl", "authsvc_cc_library")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "config",
    srcs = ["get_config.cc"],
    hdrs = [
        "get_config.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/common/http",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_gabime_spdlog//:spdlog",
        "@envoy//source/common/http:header_map_lib",
    ],
)
