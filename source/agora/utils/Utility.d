/*******************************************************************************

    Utility functions that cannot be put anywhere else

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.utils.Utility;

import std.typecons;
import std.traits;

import core.time;

/***************************************************************************

        Retry executing a given delegate at most X times and wait between
        the retries. As soon as the delegate is executed successfully,
        the function immediately returns.

        Params:
            dg = the delegate we want to execute X times
            max_retry = maximum number of times the delegate is executed
            duration = the time between retrying to execute the delegate

        Returns:
            returns Nullable() in case the delegate cannot be executed after X
            retries, otherwise it returns the original return value of
            the delegate wrapped into a Nullable object

***************************************************************************/

Nullable!(ReturnType!dg) retry(alias dg, int max_retry, Duration duration, T)(T waiter)
{
    alias RetType = Nullable!(ReturnType!dg);
    foreach(i; 0 .. max_retry)
        if(auto res = dg())
            return RetType(res);
        else
            waiter.wait(duration);
    return RetType();
}
