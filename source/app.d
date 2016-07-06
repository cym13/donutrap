
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

extern (C)
void packetHandler(ubyte* args, const pcap_pkthdr* header, const ubyte* pkt) {
    if (header.caplen < EtherHeader.sizeof)
        return;

    auto ethPkt = pkt[0 .. EtherHeader.sizeof].getHeader!EtherHeader;

    if (ethPkt.type != EtherType.IPV4)
        return;

    auto packet = pkt[EtherHeader.sizeof .. header.caplen].dup;
    auto iph    = packet.getHeader!Ipv4Header;

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
    import std.file;
    import std.format;
    import std.string: chomp, join;
    import std.algorithm: map;

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

    pcap_t* handle = pcap_open_live(dev.toStringz, BUFSIZ, 1, 0, errbuf);
    assert(handle != null);
    scope(exit) pcap_close(handle);

    uint net;
    bpf_program filter;

    string localhost  = "/etc/hostname".readText.chomp;
    string pcapFilter = "(dst localhost or dst "~ localhost ~")";

    if (port != "")
        pcapFilter ~= " and port " ~ port;

    debug pcapFilter.writeln;

    pcap_compile(handle, &filter, pcapFilter.toStringz, 0, net);
    pcap_setfilter(handle, &filter);
    auto err = pcap_loop(handle, 0, &packetHandler, cast(ubyte*)null);
    writeln("An error occured: ", err);
}
