
import std.stdio;
import std.socket;
import std.string: fromStringz, toStringz;
import std.conv: to;

import core.stdc.stdlib;

import eth;
import ip;
import tcp;
import udp;
import icmp;

import libpcap.pcap;
import libpcap.bpf;


}


}

extern (C)
void got_packet(ubyte* args, const pcap_pkthdr* header, const ubyte* packet) {
    auto tmp_packet = packet[0 .. header.caplen].dup;

    scope(exit) writeln;

    auto ethPkt = tmp_packet.consume!EtherHeader;
    ethPkt.writeln;

    if (ethPkt.type != EtherType.IPV4)
        return;

    auto ipPkt  = tmp_packet.consume!Ipv4Header;
    ipPkt.writeln;

    switch (ipPkt.p) with (IpProto) {
        case (TCP):
            tmp_packet.consume!TcpHeader.writeln;
            break;

        case (UDP):
            tmp_packet.consume!UdpHeader.writeln;
            break;

        case (ICMP):
            tmp_packet.consume!IcmpHeader.writeln;
            break;

        default: return;
    }
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
    pcap_loop(handle, 0, &got_packet, cast(ubyte*)null);
}
