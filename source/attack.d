
import std.socket;
import std.digest.md;
import std.digest.sha;
import std.datetime;

import utils;
import ip;

auto GMT() {
    version (Posix)
        alias TZProvider = PosixTimeZone;

    version (Windows)
        alias TZProvider = WindowsTimeZone;

    return TZProvider.getTimeZone("Etc/GMT");
};

/**
 * An attack event
 *
 * All times are converted to GMT for log consistency
 */
struct Attack {
    Address   src;
    Address   dst;
    string    md5sum;
    string    sha512sum;
    IpProto   proto;
    SysTime   time;
    ubyte[]   data;

    this(Address _src, Address _dst, IpProto _proto, ubyte[] _data,
            SysTime _time=SysTime.init) {

        import std.string: toLower;

        src   = _src;
        dst   = _dst;
        proto = _proto;
        data  = _data[];

        if (_time == SysTime.init)
            _time = Clock.currTime;

        time = _time.toOtherTZ(GMT);

        md5sum    = md5Of(data).toHexString.toLower;
        sha512sum = sha512Of(data).toHexString.toLower;
    }

    unittest {
        auto atk = Attack(new InternetAddress("12.34.56.78", 910),
                          new InternetAddress("109.87.65.43", 21),
                          IpProto.TCP,
                          cast(ubyte[])"Some data");

        assert(atk.md5sum == "5b82f8bf4df2bfb0e66ccaa7306fd024");
        assert(atk.sha512sum == "d45e05966e70133821e4e5b7d43932cfb"
                              ~ "e9bca4c1d6bacb12d63e6f56f20b4e52c"
                              ~ "db2e523a26266a412182553d980c661a9"
                              ~ "8b5e974793d1c221a162f2014ec47");
    }

    /**
     * Returns a filename suitable to log the attack.
     *
     *  One field is not filled corresponding to the daily attack counter as
     *  this can only be known when listing what files already exist.
     */
    string toFilenameFmt() {
        import std.format: format;

        string protocol;
        switch (proto) with (IpProto) {
            case(TCP):
                protocol = "tcp"; break;

            case(UDP):
                protocol = "udp"; break;

            default:
                protocol = "unk"; break;
        }

        auto beginning = format("from_port_%s-%s", dst.toPortString, protocol);

        return format("%s_%%d_%d-%d-%d_md5_%s",
                      beginning,
                      time.year,
                      time.month,
                      time.day,
                      md5sum);
    }

    unittest {
        auto atk = Attack(new InternetAddress("12.34.56.78", 910),
                          new InternetAddress("109.87.65.43", 21),
                          IpProto.TCP,
                          cast(ubyte[])"Some data",
                          SysTime(DateTime(2000, 10, 13, 12, 0), GMT));

        assert(atk.toFilenameFmt ==
         "from_port_21-tcp_%d_2000-10-13_md5_5b82f8bf4df2bfb0e66ccaa7306fd024");
    }

    /**
     * Returns a log file entry of the following format:
     *
     *     [ Time ] Protocol Source -> Destination MD5 SHA512
     */
    string toLog() {
        import std.format: format;

        string protocol;
        switch (proto) with (IpProto) {
            case(TCP):
                protocol = "tcp"; break;

            case(UDP):
                protocol = "udp"; break;

            default:
                protocol = "unk"; break;
        }

        return format("[ %d-%d-%d %0.2d:%0.2d:%0.2d:%0.5s GMT ] %s %s:%s -> %s:%s %s %s",
                      time.year,
                      time.month,
                      time.day,
                      time.hour,
                      time.minute,
                      time.second,
                      time.fracSecs.total!"hnsecs",
                      protocol,
                      src.toAddrString,
                      src.toPortString,
                      dst.toAddrString,
                      dst.toPortString,
                      md5sum,
                      sha512sum);
    }

    unittest {
        auto atk = Attack(new InternetAddress("12.34.56.78", 910),
                          new InternetAddress("109.87.65.43", 21),
                          IpProto.TCP,
                          cast(ubyte[])"Some data",
                          SysTime(DateTime(2000, 10, 13, 9, 0), GMT));

        assert(atk.toLog ==
             "[ 2000-10-13 09:00:00:00000 GMT ] "
           ~ "tcp 12.34.56.78:910 -> 109.87.65.43:21 "
           ~ "5b82f8bf4df2bfb0e66ccaa7306fd024 "
           ~ "d45e05966e70133821e4e5b7d43932cfbe9bca4c1d6bacb12d63e6f56f20b4e5"
           ~ "2cdb2e523a26266a412182553d980c661a98b5e974793d1c221a162f2014ec47");
    }
}
