package(default_visibility = ["//visibility:public"])

cc_library(
    name = "serviceimpl",
    srcs = ["serviceimpl.cc"],
    hdrs = ["serviceimpl.h"],
    deps = [
        "//config:config_cc",
        "//src/filters:filter_chain",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)
