load("//bazel:bazel.bzl", "authsvc_cc_library")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "healthcheck_http_server_lib",
    srcs = [
        "healthcheck_http_server.cc",
    ],
    hdrs = [
        "healthcheck_http_server.h",
    ],
    deps = [
        "//src/filters:filter_chain",
        "@boost//:asio",
    ],
)

authsvc_cc_library(
    name = "serviceimpl",
    srcs = [
        "async_service_impl.cc",
    ],
    hdrs = [
        "async_service_impl.h",
    ],
    deps = [
        ":healthcheck_http_server_lib",
        "//config:config_cc",
        "//src/common/http",
        "//src/common/utilities:trigger_rules",
        "//src/config",
        "//src/filters:filter_chain",
        "@boost//:thread",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy//source/common/config:version_converter_lib",
        # "@envoy//envoy/grpc:status",
        "@envoy_api//envoy/service/auth/v2:pkg_cc_grpc",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",
    ],
)
