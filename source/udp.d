
import utils;

struct UdpHeader {
    align(1):

    ushort src;
    ushort dst;
    ushort len;
    ushort sum;

    mixin autoToString;
}

static assert(UdpHeader.sizeof == 8);
