package(default_visibility = ["//visibility:public"])

cc_library(
    name = "serviceimpl",
    srcs = ["serviceimpl.cc"],
    hdrs = ["serviceimpl.h"],
    deps = [
        "//src/filters:pipe",
        "//src/filters/oidc:oidc_filter",
        "//src/filters/oidc:oidc_filter_config",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)
