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
    name = "in_memory_session_store",
    srcs = ["in_memory_session_store.cc"],
    hdrs = ["in_memory_session_store.h", "session_store.h"],
    deps = [
        "//src/filters/oidc:token_response",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

xx_library(
    name = "oidc_filter",
    srcs = ["oidc_filter.cc"],
    hdrs = ["oidc_filter.h"],
    deps = [
        "//config/oidc:config_cc",
        "//src/common/http",
        "//src/common/session:token_encryptor",
        "//src/common/session:session_id_generator",
        "//src/common/utilities:random",
        "//src/filters:filter",
        "//src/filters/oidc:state_cookie_codec",
        "//src/filters/oidc:in_memory_session_store",
        "//src/filters/oidc:token_response",
        "@boost//:all",
        "@com_github_abseil-cpp//absl/time:time",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_google_googleapis//google/rpc:code_cc_proto",
    ],
)
