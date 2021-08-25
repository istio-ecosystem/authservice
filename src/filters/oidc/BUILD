load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

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
    name = "authorization_state",
    srcs = ["authorization_state.cc"],
    hdrs = ["authorization_state.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
    ],
)

xx_library(
    name = "in_memory_session_store",
    srcs = ["in_memory_session_store.cc"],
    hdrs = ["in_memory_session_store.h", "session_store.h"],
    deps = [
        "//src/filters/oidc:token_response",
        "//src/filters/oidc:authorization_state",
        "//src/common/utilities:time_service",
        "//src/common/utilities:synchronized",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

xx_library(
    name = "session_store",
    srcs = [],
    hdrs = ["session_store.h"],
    deps = [
        "//src/filters/oidc:token_response",
        "//src/filters/oidc:authorization_state",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
    ],
)

xx_library(
    name = "redis_session_store",
    srcs = ["redis_session_store.cc"],
    hdrs = ["redis_session_store.h", "session_store.h"],
    deps = [
        "//src/filters/oidc:session_store",
        "//src/filters/oidc:token_response",
        "//src/filters/oidc:authorization_state",
        "//src/common/utilities:time_service",
        "//src/common/utilities:synchronized",
        "//src/filters/oidc:redis_retry_wrapper",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

xx_library(
    name = "redis_wrapper",
    srcs = ["redis_wrapper.cc"],
    hdrs = ["redis_wrapper.h"],
    deps = [
        "@com_github_sewenew_redis_plus_plus//:redis_plus_plus",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_redis_hiredis//:hiredis", # needed for linking
        "@boost//:all",
    ],
)

xx_library(
    name = "redis_retry_wrapper",
    srcs = ["redis_retry_wrapper.cc"],
    hdrs = ["redis_retry_wrapper.h"],
    deps = [
        "//src/filters/oidc:redis_wrapper",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@boost//:all",
    ],
)

xx_library(
    name = "jwks_resolver",
    srcs = ["jwks_resolver.cc"],
    hdrs = ["jwks_resolver.h"],
    deps = [
        "//src/common/http",
        "@boost//:all",
        "@com_google_absl//absl/synchronization:synchronization",
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
        "//src/common/session:session_string_generator",
        "//src/common/utilities:random",
        "//src/filters:filter",
        "//src/filters/oidc:in_memory_session_store",
        "//src/common/utilities:time_service",
        "//src/filters/oidc:token_response",
        "//src/filters/oidc:jwks_resolver",
        "@boost//:all",
        "@com_github_abseil-cpp//absl/time:time",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_google_googleapis//google/rpc:code_cc_proto",
    ],
)
