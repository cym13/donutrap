
import utils;

struct UdpHeader {
    align(1):

    ushort sport;
    ushort dport;
    ushort len;
    ushort sum;

    mixin autoToString;
}

static assert(UdpHeader.sizeof == 8);
