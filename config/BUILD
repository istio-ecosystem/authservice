package(default_visibility = ["//visibility:public"])

cc_proto_library(
    name = "config_cc",
    deps = ["//config:config_proto"],
)

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
    deps = ["//config/oidc:config_proto"],
)
