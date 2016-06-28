

/** Allow better default string representation */
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

    assert(s.toString = "S(i=0, j=42, c=Y)");
}
