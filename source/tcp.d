
import utils;

immutable TH_FIN   = 0x01;
immutable TH_SYN   = 0x02;
immutable TH_RST   = 0x04;
immutable TH_PUSH  = 0x08;
immutable TH_ACK   = 0x10;
immutable TH_URG   = 0x20;
immutable TH_ECE   = 0x40;
immutable TH_CWR   = 0x80;
immutable TH_FLAGS = TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR;

struct TcpHeader {
    align(1):

    ushort src;
    ushort dst;

    uint seq;
    uint ack;

    // We don't really care about the specifics here
    ubyte off_x2;

    ubyte  flags;
    ushort win;
    ushort sum;
    ushort urp;

    mixin autoToString;
}

static assert(TcpHeader.sizeof == 20u);
