
import utils;

immutable ETHER_ADDR_LEN = 6;

enum EtherType {
    IPV4 = 0x0800,
}

struct EtherHeader {
    align(1):

    ubyte[ETHER_ADDR_LEN] dhost;
    ubyte[ETHER_ADDR_LEN] shost;
    ushort                type;

    mixin autoToString;
}

static assert(EtherHeader.sizeof == 14u);
