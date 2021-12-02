load("//bazel:bazel.bzl", "authsvc_cc_library")
load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "http",
    srcs = ["http.cc"],
    hdrs = [
        "headers.h",
        "http.h",
    ],
    deps = [
        "@boost//:all",
        "@boost//:coroutine",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@envoy//bazel:boringssl",
    ],
)
