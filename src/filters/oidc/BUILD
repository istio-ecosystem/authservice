load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "state_cookie_codec",
    srcs = ["state_cookie_codec.cc"],
    hdrs = ["state_cookie_codec.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
    ],
)

xx_library(
    name = "token_response",
    srcs = ["token_response.cc"],
    hdrs = ["token_response.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
        "@com_google_protobuf//:protobuf",
    ],
)

xx_library(
    name = "oidc_filter",
    srcs = ["oidc_filter.cc"],
    hdrs = ["oidc_filter.h"],
    deps = [
        "//src/common/http",
        "//src/common/session:token_encryptor",
        "//src/common/utilities:random",
        "//src/filters:filter",
        "//src/filters/oidc:oidc_filter_config",
        "//src/filters/oidc:state_cookie_codec",
        "//src/filters/oidc:token_response",
        "@boost//:all",
        "@com_github_gabime_spdlog//:spdlog",
    ],
)

xx_library(
    name = "oidc_filter_config",
    srcs = ["oidc_idp_configuration.cc"],
    hdrs = ["oidc_idp_configuration.h"],
    deps = ["//src/common/http"],
)
