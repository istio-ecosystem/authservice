load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "http",
    srcs = ["http.cc"],
    hdrs = [
        "headers.h",
        "http.h",
    ],
    deps = [
        "//config/common:config_cc",
        "@boost//:all",
        "@boost//:coroutine",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_googlesource_boringssl//:ssl",
    ],
)
