load("//bazel:bazel.bzl", "xx_library")
load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "random",
    srcs = ["random.cc"],
    hdrs = ["random.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@envoy//bazel:boringssl",
    ],
)

xx_library(
    name = "time_service",
    srcs = ["time_service.cc"],
    hdrs = ["time_service.h"],
    deps = [
    ],
)

xx_library(
    name = "synchronized",
    hdrs = ["synchronized.h"],
    deps = [
    ],
)

xx_library(
    name = "trigger_rules",
    srcs = ["trigger_rules.cc"],
    hdrs = ["trigger_rules.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "//config:config_cc",
    ],
)
