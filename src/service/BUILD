package(default_visibility = ["//visibility:public"])

cc_library(
    name = "serviceimpl",
    srcs = [
        "service_impl.cc",
    ],
    hdrs = [
        "service_impl.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/config",
        "//src/filters:pipe",
        "//src/filters/oidc:oidc_filter",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)
