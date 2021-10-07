load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "hiredis",
    srcs=glob(["*.c"], exclude=["test.c"]),
    hdrs=glob(["*.h"]),
    textual_hdrs=["dict.c"],
    visibility = ["//visibility:public"],
    defines = ["HIREDIS_COMPILED_LIB"],
)

cc_library(
    name = "hiredis_headers",
    hdrs=glob(["*.h"]),
    visibility = ["//visibility:public"],
    include_prefix = "hiredis",
)
