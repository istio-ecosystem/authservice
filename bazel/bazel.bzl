# Wrappers around native build recipes to enforce consistent use of flags and build variables.

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

_DEFAULT_COPTS = ["-Wall", "-Wextra"]

def authsvc_cc_library(name, deps = [], srcs = [], hdrs = [], copts = [], defines = [], includes = [], textual_hdrs = []):
    cc_library(name = name, deps = deps, srcs = srcs, hdrs = hdrs, copts = _DEFAULT_COPTS + copts, defines = defines, includes = includes, textual_hdrs = textual_hdrs)

def authsvc_cc_binary(name, deps = [], srcs = [], copts = [], defines = []):
    cc_binary(name = name, deps = deps, srcs = srcs, copts = _DEFAULT_COPTS + copts, defines = defines)

def authsvc_cc_test(name, deps = [], srcs = [], data = []):
    cc_test(
        name = name,
        deps = deps,
        srcs = srcs,
        data = data,
        linkstatic = False
    )
