
import std.stdio;
import std.socket;
import std.concurrency;
import std.string: fromStringz, toStringz;
import std.conv: to;

import core.stdc.stdlib;
import libpcap.pcap;
import libpcap.bpf;

import eth;
import ip;
import tcp;
import udp;
import icmp;
import utils;
import attack;

import logger;

Logger   loggr;
string[] localhostIps;

auto hostIps() {
    import std.array;
    import std.string;
    import std.file: readText;
    import std.algorithm: map;

    return "/proc/net/dev".readText
                          .splitLines[2 .. $]
                          .map!(l => l.split(":")[0])
                          .map!(l => l.replace(" ", ""))
                          .map!(i => interfaceIp(i))
                          .array;
}

string interfaceIp(string iface) {
    auto s  = new Socket(AddressFamily.INET, SocketType.DGRAM);
    auto fd = s.handle;
    scope(exit) close(fd);

    ifreq ifr;
    ifr.ifr_addr.sa_family = AddressFamily.INET;
    auto name = iface.toStringz.to!(char[]);
    ifr.ifr_name[0 .. name.length] = iface.toStringz.to!(char[]);

    ioctl(fd, SIOCGIFADDR, &ifr);

    return inet_ntoa((cast(sockaddr_in *)&ifr.ifr_addr).sin_addr)
            .fromStringz
            .to!string;
}

extern (C) {
    alias ulong in_addr;
    alias int   ifmap;

    int   ioctl(int fd, ulong request, ...);
    char* inet_ntoa(in_addr);
    int   close(int);

    struct sockaddr_in {
        short   sin_family;
        ushort  sin_port;
        in_addr sin_addr;
        char[8] sin_zero;
    }

    immutable IFNAMSIZ    = 16;
    immutable SIOCGIFADDR = 0x8915;

    struct ifreq {
        char[IFNAMSIZ] ifr_name;
        sockaddr       ifr_addr;
    }

    struct sockaddr {
        ushort   sa_family;
        byte[14] sa_data;
    }
}

extern (C)
void packetHandler(ubyte* args, const pcap_pkthdr* header, const ubyte* pkt) {
    import std.algorithm: canFind;

    if (header.caplen < EtherHeader.sizeof)
        return;

    auto ethPkt = pkt[0 .. EtherHeader.sizeof].getHeader!EtherHeader;

    if (ethPkt.type != EtherType.IPV4)
        return;


    auto packet = pkt[EtherHeader.sizeof .. header.caplen].dup;
    auto iph    = packet.getHeader!Ipv4Header;

    auto ipdst = (new InternetAddress(iph.dst, 0)).toAddrString;
    if (localhostIps.canFind(ipdst))
        return;

    auto ipsrc = (new InternetAddress(iph.src, 0)).toAddrString;
    if (!localhostIps.canFind(ipsrc))
        return;

    IpProto protocol;
    ubyte[] data;
    InternetAddress source;
    InternetAddress destination;

    auto ipsize = Ipv4Header.sizeof;

    switch (iph.p) with (IpProto) {
        case (UDP):
            auto udpsize = UdpHeader.sizeof;
            auto udph    = packet[ipsize .. ipsize + udpsize]
                            .getHeader!UdpHeader;

            data        = packet[ipsize + udpsize .. $];
            protocol    = IpProto.UDP;
            source      = new InternetAddress(iph.src, udph.sport);
            destination = new InternetAddress(iph.dst, udph.dport);
            break;

        default:
            return;
    }

    loggr.log(Attack(source, destination, protocol, data));
}

void main(string[] args)
{
    import std.getopt;

    char* errbuf = cast(char*)(malloc(256 * char.sizeof));
    scope(exit) free(errbuf);

    string dev  = pcap_lookupdev(errbuf).fromStringz.to!string;
    string port = "";

    auto help = getopt(args,
                       "interface|i", "Device to listen to.", &dev,
                       "port|p",      "Port to listen to.",  &port);

    if (help.helpWanted) {
        defaultGetoptPrinter("A generic D honeypot\n", help.options);
        return;
    }

    writeln("Device: ", dev);

    loggr        = new Logger("/opt/donutrap");
    localhostIps = hostIps();

    pcap_t* handle = pcap_open_live(dev.toStringz, BUFSIZ, 1, 0, errbuf);
    assert(handle != null);
    scope(exit) pcap_close(handle);

    uint net;
    bpf_program filter;
    string filter_app;

    if (port != "")
        filter_app = "port " ~ port;

    pcap_compile(handle, &filter, filter_app.toStringz, 0, net);
    pcap_setfilter(handle, &filter);
    auto err = pcap_loop(handle, 0, &packetHandler, cast(ubyte*)null);
    writeln("An error occured: ", err);
}
