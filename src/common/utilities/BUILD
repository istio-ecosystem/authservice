load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "random",
    srcs = ["random.cc"],
    hdrs = ["random.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_googlesource_boringssl//:crypto",
    ],
)

xx_library(
    name = "time_service",
    srcs = ["time_service.cc"],
    hdrs = ["time_service.h"],
    deps = [
    ],
)
