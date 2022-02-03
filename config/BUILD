load("@com_envoyproxy_protoc_gen_validate//bazel:pgv_proto_library.bzl", "pgv_cc_proto_library")

package(default_visibility = ["//visibility:public"])

pgv_cc_proto_library(
    name = "config_cc",
    cc_deps = ["//config/oidc:config_cc"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "//config:config_proto",
    ],
)

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
    deps = [
        "//config/mock:config_proto",
        "//config/oidc:config_proto",
        "@com_envoyproxy_protoc_gen_validate//validate:validate_proto",
    ],
)
