cc_library(
    name = "cpp",
    srcs = [
        "src/securegcm/d2d_connection_context_v1.cc",
        "src/securegcm/d2d_crypto_ops.cc",
        "src/securegcm/java_util.cc",
        "src/securegcm/ukey2_handshake.cc",
    ],
    hdrs = glob(["include/securegcm/*.h"]),
    includes = [
        "include",
    ],
    deps = [
        "//src/main/proto:cc_proto",
        "//src/securemessage:securemessage_common",
        "//src/securemessage:securemessage_cpp_protobuf",
        "//src/securemessage:securemessage_openssl",
    ],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "cpp_tests",
    size = "small",
    srcs = [
        "test/securegcm/d2d_connection_context_v1_test.cc",
        "test/securegcm/d2d_crypto_ops_test.cc",
        "test/securegcm/java_util_test.cc",
    ],
    includes = [
        "include",
    ],
    deps = [
        ":cpp",
        "@com_google_googletest//:gtest_main",
        "//src/securemessage:securemessage_common",
        "//src/securemessage:securemessage_cpp_protobuf",
    ],
)

cc_binary(
    name = "ukey2_shell",
    srcs = ["src/securegcm/ukey2_shell.cc"],
    deps = [
        ":cpp",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)
