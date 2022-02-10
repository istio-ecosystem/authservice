load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "hiredis",
    srcs = glob(
        ["*.c"],
        exclude = ["test.c"],
    ),
    hdrs = glob(["*.h"]),
    defines = ["HIREDIS_COMPILED_LIB"],
    textual_hdrs = ["dict.c"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "hiredis_headers",
    hdrs = glob(["*.h"]),
    include_prefix = "hiredis",
    visibility = ["//visibility:public"],
)
