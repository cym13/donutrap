
import utils;

immutable IP_RF      = 0x8000; // Reserved fragment
immutable IP_DF      = 0x4000; // Don't fragment
immutable IP_MF      = 0x2000; // More fragments
immutable IP_OFFMASK = 0x1fff; // Mask for fragmenting bits

enum IpProto {
    ICMP =  1,
    TCP  =  6,
    UDP  = 17,
}

struct Ipv4Header {
    align(1):

    // We don't really care about the specifics here
    ubyte  v_h;

    ubyte  tos;
    ushort len;
    ushort id;
    ushort off;

    ubyte  ttl;
    ubyte  p;
    ushort sum;
    uint   src;
    uint   dst;

    mixin autoToString;
}

static assert(Ipv4Header.sizeof == 20u);
