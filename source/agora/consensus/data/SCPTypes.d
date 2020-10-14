/*******************************************************************************

    Defines the data structure of a block

    The design is influenced by Bitcoin, but will be ammended later.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.SCPTypes;

import agora.common.SCPHash : getHashOf;
import agora.common.Hash : Signature;
import agora.common.crypto.Key : PublicKey;
import agora.common.Hash;
import agora.common.Serializer;
import agora.consensus.data.ConsensusData;
import agora.utils.Log;

import dscp.SCP;
import dscp.Driver;
import dscp.Slot;
import dscp.Types;

import std.container : RedBlackTree, redBlackTree;
import std.traits;

public struct Wrapper (T)
{
    T t;
    alias t this;
    import std.conv;

    // workaround for dlang #21270
    public void toString (scope void delegate(const(char)[]) sink) const
    {
        sink(t.to!string);
    }
}

public alias Value = Wrapper!ConsensusData;
public alias NodeID = PublicKey;

private alias SetT (T) = RedBlackTree!(const(T));
private alias makeSetT (T) = redBlackTree!(const(T));

public Unqual!T duplicate (T)(T arg)
{
    return arg.serializeFull.deserializeFull!(Unqual!T);
}

struct LogWrapper
{
    Logger log;

    public void trace (T...)(T args)
    {
        import std.format;
        string msg = format(args[0], args[1 .. $]);
        this.log.trace(msg);
    }

    public void info (T...)(T args)
    {
        import std.format;
        string msg = format(args[0], args[1 .. $]);
        this.log.info(msg);
    }

    public void error (T...)(T args)
    {
        import std.format;
        string msg = format(args[0], args[1 .. $]);
        this.log.error(msg);
    }
}

public alias ValueSet = SetT!Value;

public struct Policy
{
    alias NodeID = .NodeID;
    alias Hash = .Hash;
    alias Value = .Value;
    alias Signature = .Signature;
    alias Set = .SetT;
    alias makeSet = .makeSetT;
    alias getHashOf = .getHashOf;
    alias hashPart = .hashPart;
    alias duplicate = .duplicate;
    alias Logger = .LogWrapper;
}

public alias Envelope = EnvelopeT!Policy;
public alias QuorumSet = QuorumSetT!Policy;
public alias Ballot = BallotT!Policy;
public alias Statement = StatementT!Policy;
public alias Nomination = NominationT!Policy;
public alias Driver = DriverT!Policy;
public alias SCP = SCPT!Policy;
public alias Slot = SlotT!Policy;

// convenience
public alias QuorumConfig = QuorumSet;
