BOOST_VERSION = "1.70.0"

def new_boost_library(name, deps = []):
    boost_library(name, deps)
    boost_build_rule(name)

def boost_library(name, deps = []):
    native.cc_library(
        name = name,
        srcs =
            select({
                "osx": [
                    "libboost_{}.a".format(name),
                    "libboost_{}.dylib".format(name)
                ],
                "clang": [
                    "libboost_{}.a".format(name),
                    "libboost_{}.so.{}".format(name, BOOST_VERSION),
                ],
                "//conditions:default": [
                    "libboost_{}.a".format(name),
                    "libboost_{}.so.{}".format(name, BOOST_VERSION),
                ],
            }),
        hdrs = native.glob(
            [
                "boost/{}.hpp".format(name),
                "boost/{}/**/*.h".format(name),
                "boost/{}/**/*.hpp".format(name),
            ],
        ),
        visibility = ["//visibility:public"],
        deps = [
            ":all",
        ] + deps,
    )

def boost_build_rule(name):
    native.genrule(
        name = "build_boost_{}".format(name),
        srcs = native.glob(
            [
                "Jamroot",
                "**/Jamfile*",
                "**/*.jam",
                "**/*.cpp",
                "**/*.c",
                "**/*.S",
                "**/*.h",
                "**/*.hpp",
                "**/*.ipp",
                "project-config.jam",
            ],
            exclude = [
                "bazel-*",
                "libs/wave/test/**/*",
            ],
        ) + [
            "project-config.jam",
        ],
        outs = [
            "libboost_{}.a".format(name),

             # Until we can figure out how to correctly build dylib files and dynamically link the test binaries
             # on MacOS, when you are running on MacOS you can comment out the "libboost_{}.so.{}" line and uncomment
             # the "libboost_{}.dylib" line to compile the project and run the tests.
             # Unfortunately, select statements are not allowed for genrule `outs` :(
            "libboost_{}.so.{}".format(name, BOOST_VERSION),
#            "libboost_{}.dylib".format(name), # Use this on MacOS instead of the .so line above.
        ],
        cmd =
            select({
                "osx": """
                    ROOT=$$(dirname $(location Jamroot))
                    cp $(location project-config.jam) $$ROOT
                    pushd $$ROOT
                        ../../$(location b2) libboost_{name}.a libboost_{name}.dylib
                    popd
                    cp $$ROOT/stage/lib/libboost_{name}.a $(location libboost_{name}.a)
                    cp $$ROOT/stage/lib/libboost_{name}.dylib $(location libboost_{name}.dylib)
                """.format(name = name),
                "clang": """
                    ROOT=$$(dirname $(location Jamroot))
                    cp $(location project-config.jam) $$ROOT
                    pushd $$ROOT
                        ../../$(location b2) toolset=clang libboost_{name}.a libboost_{name}.so.{version}
                    popd
                    cp $$ROOT/stage/lib/libboost_{name}.a $(location libboost_{name}.a)
                    cp $$ROOT/stage/lib/libboost_{name}.so.{version} $(location libboost_{name}.so.{version})
                """.format(name = name, version = BOOST_VERSION),
                "//conditions:default": """
                    ROOT=$$(dirname $(location Jamroot))
                    cp $(location project-config.jam) $$ROOT
                    pushd $$ROOT
                        ../../$(location b2) libboost_{name}.a libboost_{name}.so.{version}
                    popd
                    cp $$ROOT/stage/lib/libboost_{name}.a $(location libboost_{name}.a)
                    cp $$ROOT/stage/lib/libboost_{name}.so.{version} $(location libboost_{name}.so.{version})
                """.format(name = name, version = BOOST_VERSION),
            }),

        tools = ["b2"],
    )
