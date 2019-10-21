load("@com_envoyproxy_protoc_gen_validate//bazel:pgv_proto_library.bzl", "pgv_cc_proto_library")
#cc_proto_library(
#    name = "config_cc",
#    visibility = ["//visibility:public"],
#    deps = ["//config/common:config_proto"],
#)

pgv_cc_proto_library(
    name = "config_cc",
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "//config/common:config_proto",
    ],
)

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
    visibility = ["//visibility:public"],
    deps = ["@com_envoyproxy_protoc_gen_validate//validate:validate_proto"],
)
