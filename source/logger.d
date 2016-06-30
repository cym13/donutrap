
import std.file;
import std.concurrency: Mutex;

import attack;

struct Logger {
    string logdir;
    Mutex  atkMutex;
    Mutex  slfMutex;
    string attackFile;
    string atkLogFile;
    string slfLogFile;


    this(string _logdir) {
        import std.path: isDir, dirSeparator;

        assert (_logdir.isDir);

        logdir     = _logdir ~ dirSeparator;
        attackFile = logdir ~ "attacks";
        atkLogFile = logdir ~ "log" ~ dirSeparator ~ "attacker.log";
        slfLogFile = logdir ~ "log" ~ dirSeparator ~ "donutrap.log";
        atkMutex   = new Mutex();
        slfMutex   = new Mutex();
    }

    void log(Attack atk) {
        import std.format;
        import std.algorithm;

        string date = format("_%d-%d-%d_",
                             atk.time.year,
                             atk.time.month,
                             atk.time.day);

        auto fileCount = attackFile.dirEntries(SpanMode.shallow)
                                   .filter!((string f) => f.canFind(date))
                                   .count;

        auto filenameFmt = atk.toFilenameFmt;
        auto filename    = format(filenameFmt, fileCount);

        synchronized (atkMutex) {
            while (filename.exists) {
                filename = format(filenameFmt, fileCount);
                fileCount++;
            }

            filename.write(atk.data);
            atkLogFile.append(atk.toLog);
        }
    }

    void log(string str) {
        synchronized (slfMutex) {
            assert(slfLogFile.isFile);
            slfLogFile.append(str);
        }
    }
}
