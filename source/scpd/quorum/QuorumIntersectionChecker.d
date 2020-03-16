/*******************************************************************************

    Bindings for quorum/QuorumIntersectionChecker.h

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module scpd.quorum.QuorumIntersectionChecker;

import scpd.Cpp;
import scpd.types.Stellar_types;
import scpd.quorum.QuorumTracker;

extern (C++, `stellar`):

extern(C++) void printMapSize (void* ptr);

extern(C++, class) public abstract class QuorumIntersectionChecker
{
  public:
    extern(D) static shared_ptr!QuorumIntersectionChecker create (
        QuorumTracker.QuorumMap map) nothrow pure @trusted @nogc
    {
        return create(*cast(void**)&map);
    }

    private static shared_ptr!QuorumIntersectionChecker create (const(void)*) nothrow pure @trusted @nogc;
    abstract bool networkEnjoysQuorumIntersection ();
    abstract size_t getMaxQuorumsFound ();
    abstract pair!(vector!NodeID, vector!NodeID) getPotentialSplit ();
}
