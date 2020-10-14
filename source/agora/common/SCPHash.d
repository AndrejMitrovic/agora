/*******************************************************************************

    Contains definition of hashing routines which SCP uses.
    These just call the hashing routines from agora.common.Hash

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.SCPHash;

import agora.common.Hash;
import agora.consensus.data.SCPTypes;

import dscp.Types;

import core.stdc.inttypes;

/*******************************************************************************

    Implementation of the hashing routines as used by SCP

    Params:
        qset = the SCP quorum set to hash

    Returns:
        the 64-byte hash

*******************************************************************************/

public Hash getHashOf (ref const(QuorumSet) qset) @safe
{
    return hashFull(qset);
}

/// Ditto
public Hash getHashOf (ref const(Value) value) @safe
{
    return hashFull(value);
}

/// Ditto
public Hash getHashOf (ulong slot_idx, ref const(Value) prev, uint hash, int round_num, ref const(NodeID) node_id) @safe
{
    return hashMulti(slot_idx, prev, hash, round_num, node_id);
}

/// Ditto
public Hash getHashOf (ulong slot_idx, ref const(Value) prev, uint hash,
    int round_num, ref const(Value) value) @safe
{
    return hashMulti(slot_idx, prev, hash, round_num, value);
}
