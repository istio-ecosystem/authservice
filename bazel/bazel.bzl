# Wrappers around native build recipes to enforce consistent use of flags and build variables.

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

# envoy_stdlib_deps appends "-static-libgcc" on Linux.
load("@envoy//bazel:envoy_internal.bzl", "envoy_stdlib_deps")

_DEFAULT_COPTS = ["-Wall", "-Wextra"]

def authsvc_cc_library(name, deps = [], srcs = [], hdrs = [], copts = [], defines = [], includes = [], textual_hdrs = [], visibility = None):
    cc_library(name = name, deps = deps, srcs = srcs, hdrs = hdrs, copts = _DEFAULT_COPTS + copts, defines = defines, includes = includes, textual_hdrs = textual_hdrs, visibility = visibility)

# By default, we always do linkstatic: https://docs.bazel.build/versions/main/be/c-cpp.html#cc_binary.linkstatic.
def authsvc_cc_binary(name, deps = [], srcs = [], copts = [], defines = []):
    cc_binary(name = name, deps = deps + envoy_stdlib_deps(), srcs = srcs, copts = _DEFAULT_COPTS + copts, defines = defines)

def authsvc_cc_test(name, deps = [], srcs = [], data = []):
    cc_test(
        name = name,
        deps = deps,
        srcs = srcs,
        data = data,
        # We choose to use static link because boringssl FIPS build seem not be able
        # to resolved for unit test,
        # https://gist.github.com/Shikugawa/0ff7ef056cf6fdb2605ad81fcb0be814 (optional)
        linkstatic = True,
    )
