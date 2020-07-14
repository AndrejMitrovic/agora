#!/usr/bin/env rdmd
module unittest_runner;

private:

import std.algorithm;
import std.conv;
import std.file;
import std.format;
import std.path;
import std.process;
import std.stdio;

import core.sys.posix.signal;
import core.thread;
import core.time;
import std.datetime;

private int main (string[] args)
{
    //build unittests binary with:
    // dub build -c unittest -b unittest-cov --skip-registry=all --compiler=ldc2

    auto binary_pid = spawnProcess(["./build/agora-unittests"], std.stdio.stdin, std.stdio.stdout, std.stdio.stderr);

    import std.datetime.stopwatch : StopWatch;

    StopWatch sw;
    sw.start();
    writefln("Started at: %s", Clock.currTime);

    // timeout until SIGSEGV is sent
    const timeout = 6.minutes;
    while (1)
    {
        if (tryWait(binary_pid).terminated)
        {
            writeln("Unittests passed.");
            return 1;  // nothing to do
        }

        const sleep_interval = 6.seconds;
        writefln("Sleeping for %s..", sleep_interval);
        stdout.flush();
        Thread.sleep(sleep_interval);
        writefln("Slept for %s", sw.peek);
        stdout.flush();

        if (sw.peek > timeout)
            break;
    }

    writefln("-- Sending SIGSEGV");
    stdout.flush();
    kill(binary_pid, SIGSEGV);

    ulong getCoreSize ()
    {
        string core;
        foreach (string entry; dirEntries("/cores/", SpanMode.shallow))
        {
            core = entry;
            break;
        }

        if (core.length == 0)
            return 0;

        auto file = File(core, "r");
        return file.size();
    }

    ulong old_size = 0;
    while (1)
    {
        Thread.sleep(5.seconds);
        auto new_size = getCoreSize();
        if (new_size > old_size)
        {
            writefln("Core size increasing [%sM to %sM]", old_size / 1024 / 1024, new_size / 1024 / 1024);
            stdout.flush();
            old_size = new_size;
            continue;
        }
        else if (new_size == 0)
        {
            // not started dumping yet
            continue;
        }
        else
        {
            writefln("Core dump complete [%sM]", new_size / 1024 / 1024);
            stdout.flush();
            break;
        }
    }

    return 0;
}
