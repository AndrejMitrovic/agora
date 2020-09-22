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

import dscp.scp.SCP;
import dscp.scp.SCPDriver;
import dscp.scp.Slot;
import dscp.xdr.Stellar_SCP;

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
public alias SCPEnvelope = SCPEnvelopeT!(NodeID, Hash, Value, Signature);
public alias SCPQuorumSet = SCPQuorumSetT!(NodeID, hashPart);
public alias SCPQuorumSetPtr = SCPQuorumSet*;
public alias SCPBallot = SCPBallotT!Value;
public alias SCPStatement = SCPStatementT!(NodeID, Hash, Value);
public alias SCPNomination = SCPNominationT!(Hash, Value);
public alias SCPDriver = SCPDriverT!(NodeID, Hash, Value, Signature, SetT, makeSetT, getHashOf, hashPart, duplicate, LogWrapper);
public alias SCP = SCPT!(NodeID, Hash, Value, Signature, SetT, makeSetT, getHashOf, hashPart, duplicate, LogWrapper);
public alias Slot = SlotT!(NodeID, Hash, Value, Signature, SetT, makeSetT, getHashOf, hashPart, duplicate, LogWrapper);
public alias QuorumConfig = SCPQuorumSet;
