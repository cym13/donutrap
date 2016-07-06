
import std.file;
import std.concurrency: Mutex;

import attack;

class Logger {
    static Mutex  atkMutex;
    static Mutex  slfMutex;
    string logdir;
    string attackDir;
    string atkLogFile;
    string slfLogFile;

    @disable this();

    this(string _logdir) {
        import std.path: isDir, chainPath;
        import std.array;

        assert (_logdir.isDir);

        logdir     = _logdir;
        attackDir  = logdir.chainPath("attacks").array;
        atkLogFile = logdir.chainPath("logs", "attacker.log").array;
        slfLogFile = logdir.chainPath("logs", "donutrap.log").array;

        if (!atkMutex) atkMutex = new Mutex();
        if (!slfMutex) slfMutex = new Mutex();
    }

    void log(Attack atk) {
        import std.array;
        import std.format;
        import std.algorithm;
        import std.path: chainPath;

        if (atk.data.length == 0)
            return;

        string date = format("_%d-%d-%d_",
                             atk.time.year,
                             atk.time.month,
                             atk.time.day);

        auto fileCount = attackDir.dirEntries(SpanMode.shallow)
                                  .filter!((string f) => f.canFind(date))
                                  .count;

        auto filenameFmt = atk.toFilenameFmt;
        auto filename    = format(filenameFmt, fileCount);

        synchronized (atkMutex) {
            while (filename.exists) {
                filename = format(filenameFmt, fileCount);
                fileCount++;
            }

            std.file.write(attackDir.chainPath(filename).array, atk.data);
            atkLogFile.append(atk.toLog);
            atkLogFile.append("\n");
        }
    }

    void log(string str) {
        synchronized (slfMutex) {
            assert(slfLogFile.isFile);
            slfLogFile.append(str);
        }
    }
}
