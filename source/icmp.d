
import utils;

immutable ICMP_ECHOREPLY      =  0;   /* Echo Reply              */
immutable ICMP_DEST_UNREACH   =  3;   /* Destination Unreachable */
immutable ICMP_SOURCE_QUENCH  =  4;   /* Source Quench           */
immutable ICMP_REDIRECT       =  5;   /* Redirect (change route) */
immutable ICMP_ECHO           =  8;   /* Echo Request            */
immutable ICMP_TIME_EXCEEDED  = 11;   /* Time Exceeded           */
immutable ICMP_PARAMETERPROB  = 12;   /* Parameter Problem       */
immutable ICMP_TIMESTAMP      = 13;   /* Timestamp Request       */
immutable ICMP_TIMESTAMPREPLY = 14;   /* Timestamp Reply         */
immutable ICMP_INFO_REQUEST   = 15;   /* Information Request     */
immutable ICMP_INFO_REPLY     = 16;   /* Information Reply       */
immutable ICMP_ADDRESS        = 17;   /* Address Mask Request    */
immutable ICMP_ADDRESSREPLY   = 18;   /* Address Mask Reply      */
immutable NR_ICMP_TYPES       = 18;

struct IcmpHeader {
    align(1):

    ubyte  type;
    ubyte  code;
    ushort sum;
    uint   gateway;

    mixin autoToString;
}

static assert(IcmpHeader.sizeof == 8);
