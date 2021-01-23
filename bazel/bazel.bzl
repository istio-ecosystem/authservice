# Wrappers around native build recipes to enforce consistent use of flags and build variables.

_DEFAULT_COPTS = ["-Wall", "-Wextra"]

def xx_library(name, deps = [], srcs = [], hdrs = [], copts = [], defines = [], includes = [], textual_hdrs = []):
    native.cc_library(name = name, deps = deps, srcs = srcs, hdrs = hdrs, copts = copts, defines = defines, includes = includes, textual_hdrs = textual_hdrs)

def xx_binary(name, deps = [], srcs = [], copts = [], defines = []):
    native.cc_binary(name = name, deps = deps, srcs = srcs, copts = copts, defines = defines)
