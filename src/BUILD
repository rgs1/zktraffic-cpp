cc_library(
    name = "zktraffic",
    copts = [
        "-std=c++14",
        "-Wall"
    ],
    linkopts = [
        "-lpcap",
        "-pthread"
    ],
    srcs = [
        "sniffer.cc",
        "tcp_packet.cc",
        "zkmessage.cc",
    ],
    hdrs = [
        "sniffer.h",
        "tcp_packet.h",
        "zkmessage.h",
    ],
)

cc_binary(
    name = "zkdump",
    srcs = ["zkdump.cc"],
    deps = [
        ":zktraffic",
    ],
)
