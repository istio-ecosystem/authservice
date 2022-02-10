load("//bazel:bazel.bzl", "authsvc_cc_library")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "token_response",
    srcs = ["token_response.cc"],
    hdrs = ["token_response.h"],
    deps = [
        ":jwt_verifier",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
        "@com_google_protobuf//:protobuf",
    ],
)

authsvc_cc_library(
    name = "authorization_state",
    srcs = ["authorization_state.cc"],
    hdrs = ["authorization_state.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
    ],
)

authsvc_cc_library(
    name = "session_store_factory",
    hdrs = ["session_store_factory.h"],
    deps = [
        "//config:config_cc",
    ],
)

authsvc_cc_library(
    name = "in_memory_session_store",
    srcs = ["in_memory_session_store.cc"],
    hdrs = [
        "in_memory_session_store.h",
        "session_store.h",
    ],
    deps = [
        ":session_store_factory",
        "//src/common/utilities:synchronized",
        "//src/common/utilities:time_service",
        "//src/filters/oidc:authorization_state",
        "//src/filters/oidc:token_response",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

authsvc_cc_library(
    name = "session_store",
    srcs = [],
    hdrs = ["session_store.h"],
    deps = [
        "//src/filters/oidc:authorization_state",
        "//src/filters/oidc:token_response",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
    ],
)

authsvc_cc_library(
    name = "redis_session_store",
    srcs = ["redis_session_store.cc"],
    hdrs = [
        "redis_session_store.h",
        "session_store.h",
    ],
    deps = [
        ":session_store_factory",
        "//src/common/utilities:synchronized",
        "//src/common/utilities:time_service",
        "//src/filters/oidc:authorization_state",
        "//src/filters/oidc:redis_retry_wrapper",
        "//src/filters/oidc:session_store",
        "//src/filters/oidc:token_response",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

authsvc_cc_library(
    name = "redis_wrapper",
    srcs = ["redis_wrapper.cc"],
    hdrs = ["redis_wrapper.h"],
    deps = [
        "@boost//:asio",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_redis_hiredis//:hiredis",  # needed for linking
        "@com_github_sewenew_redis_plus_plus//:redis_plus_plus",
    ],
)

authsvc_cc_library(
    name = "redis_retry_wrapper",
    srcs = ["redis_retry_wrapper.cc"],
    hdrs = ["redis_retry_wrapper.h"],
    deps = [
        "//src/filters/oidc:redis_wrapper",
        "@boost//:asio",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
    ],
)

authsvc_cc_library(
    name = "jwks_resolver",
    srcs = ["jwks_resolver.cc"],
    hdrs = ["jwks_resolver.h"],
    deps = [
        "//config/oidc:config_cc",
        "//src/common/http",
        "@boost//:asio",
        "@com_github_abseil-cpp//absl/synchronization:synchronization",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
    ],
)

authsvc_cc_library(
    name = "jwt_verifier",
    srcs = ["jwt_verifier.cc"],
    hdrs = ["jwt_verifier.h"],
    deps = [
        ":jwks_resolver",
        "@com_github_abseil-cpp//absl/container:flat_hash_map",
        "@com_github_abseil-cpp//absl/status:status",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_google_jwt_verify_lib//:jwt_verify_lib",
        "@com_google_protobuf//:protobuf",
    ],
)

authsvc_cc_library(
    name = "oidc_filter",
    srcs = ["oidc_filter.cc"],
    hdrs = ["oidc_filter.h"],
    deps = [
        "//config/oidc:config_cc",
        "//src/common/http",
        "//src/common/session:session_string_generator",
        "//src/common/utilities:random",
        "//src/common/utilities:time_service",
        "//src/filters:filter",
        "//src/filters:filter_factory",
        "//src/filters/oidc:in_memory_session_store",
        "//src/filters/oidc:jwks_resolver",
        "//src/filters/oidc:token_response",
        "@boost//:asio",
        "@com_github_abseil-cpp//absl/status:status",
        "@com_github_abseil-cpp//absl/status:statusor",
        "@com_github_abseil-cpp//absl/time:time",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_google_googleapis//google/rpc:code_cc_proto",
    ],
)
