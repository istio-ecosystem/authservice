load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "config",
    srcs = ["get_config.cc"],
    hdrs = [
        "get_config.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/common/http:http",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_gabime_spdlog//:spdlog",
        "@envoy//source/common/http:header_map_lib",
    ],
)
