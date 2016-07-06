
/**
 * Allow better default string representation
 */
mixin template autoToString() {
    import std.conv:  to;
    import std.array: join;
    import std.array: split;

    string toString() {
        alias typeof(this) T;

        string res = typeid(T).to!string.split(".")[$-1] ~ "(";

        string[] tmp;
        foreach (member ; __traits(derivedMembers, T)) {
            enum isMemberVariable =
                is(typeof(() {
                        __traits(getMember, T, member) =
                        __traits(getMember, T, member).init;
                }));

            static if(isMemberVariable) {
                tmp ~= member ~ "=" ~ mixin("this." ~ member ~ ".to!string");
            }
        }

        res ~= tmp.join(", ") ~ ")";

        return res;
    }
}

unittest {
    struct S {
        int  i;
        int  j = 42;
        char c = 'Y';

        mixin autoToString;
    }
    S s;

    assert(s.toString == "S(i=0, j=42, c=Y)");
}

T getHeader(T)(const ubyte[] packet) {
    import cerealed.decerealizer;

    auto decerealizer = Decerealizer(packet[0 .. T.sizeof]);
    return decerealizer.value!T;
}

unittest {
    struct S { uint i; char c; }
    auto data = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];

    assert(data.consume!S == S(0x10203040, 'P'));
    assert(data == [0x60, 0x70]);
}
