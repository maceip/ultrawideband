cc_library(
    name = "securemessage_openssl",
    srcs = [
        "src/securemessage/crypto_ops_openssl.cc",
    ],
    defines = ["OPENSSL_IS_BORINGSSL"],
    deps = [
        ":securemessage_common",
        "@boringssl//:crypto",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "securemessage_common",
    srcs = [
        "include/securemessage/secure_message_wrapper.h",
        "src/securemessage/byte_buffer.cc",
        "src/securemessage/crypto_ops.cc",
        "src/securemessage/raw_secure_message_parser.cc",
        "src/securemessage/util.cc",
    ],
    hdrs = [
        "include/securemessage/byte_buffer.h",
        "include/securemessage/common.h",
        "include/securemessage/crypto_ops.h",
        "include/securemessage/raw_secure_message_parser.h",
        "include/securemessage/util.h",
    ],
    visibility = ["//visibility:public"],
)

SECUREMESSAGE_CPP_PROTOBUF_SRCS = [
    "src/securemessage/public_key_proto_util.cc",
    "src/securemessage/secure_message_builder.cc",
    "src/securemessage/secure_message_parser.cc",
    "src/securemessage/secure_message_wrapper.cc",
]

SECUREMESSAGE_CPP_PROTOBUF_HDRS = [
    "include/securemessage/public_key_proto_util.h",
    "include/securemessage/secure_message_builder.h",
    "include/securemessage/secure_message_parser.h",
    "include/securemessage/secure_message_wrapper.h",
]

# The c++ protobuf specific code is separated out from the common code in order
# to make it more clear that the common portion of the library is independent
# of the c++ protobuf library.
cc_library(
    name = "securemessage_cpp_protobuf",
    srcs = SECUREMESSAGE_CPP_PROTOBUF_SRCS,
    hdrs = SECUREMESSAGE_CPP_PROTOBUF_HDRS,
    deps = [
        ":securemessage_common",
        "//src/main/proto:cc_proto",
    ],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "securemessage_test",
    srcs = glob(["test/**/*.cc"]),
    deps = [
        ":securemessage_common",
        ":securemessage_cpp_protobuf",
        ":securemessage_openssl",
        "@com_google_googletest//:gtest_main",
    ],
)
