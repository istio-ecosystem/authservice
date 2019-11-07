package(default_visibility = ["//visibility:public"])

cc_library(
    name = "serviceimpl",
    srcs = [
        "async_service_impl.cc",
        "service_impl.cc",
    ],
    hdrs = [
        "async_service_impl.h",
        "service_impl.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/config",
        "//src/filters:filter_chain",
        "@boost//:thread",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)
