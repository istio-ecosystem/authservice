load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

load("//bazel:repositories.bzl", "oidcservice_dependencies")

oidcservice_dependencies()

# load go dependencies

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()
go_register_toolchains(version = "1.15.6")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

# load envoy dependencies

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

# load protoc-gen-validate dependencies

load("@com_envoyproxy_protoc_gen_validate//:dependencies.bzl", "go_third_party")

go_third_party()

# load grpc dependencies

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()
