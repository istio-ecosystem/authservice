package(default_visibility = ["//visibility:public"])

cc_library(
    name = "serviceimpl",
    srcs = [
        "async_service_impl.cc",
    ],
    hdrs = [
        "async_service_impl.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/config",
        "//src/filters:filter_chain",
        "//src/common/http",
        "//src/common/utilities:trigger_rules",
        "@boost//:thread",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:pkg_cc_grpc",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",
        "@envoy//source/common/config:version_converter_lib",
    ],
)
