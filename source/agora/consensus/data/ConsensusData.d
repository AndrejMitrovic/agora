/*******************************************************************************

    Defines the data used when reaching consensus.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.ConsensusData;

import agora.common.Hash;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;

/// Create a shorthash from a 64-byte blob for RNG initialization
private ulong toShortHash (const ref Hash hash) @trusted nothrow
{
    import libsodium.crypto_shorthash;
    import std.bitmanip;

    // using a once-generated initialization vector
    static immutable ubyte[crypto_shorthash_KEYBYTES] IV =
        [111, 165, 189, 80, 37, 5, 16, 194, 39, 214, 156, 169, 235, 221, 21, 126];
    ubyte[ulong.sizeof] short_hash;
    crypto_shorthash(short_hash.ptr, hash[].ptr, hash[].length, IV.ptr);

    // assume a specific endianess for consistency in how we convert to ulong
    return littleEndianToNative!ulong(short_hash[]);
}

/// Consensus data which is nominated & voted on
public struct ConsensusData
{
    /// The transaction set that is being nominated / voted on
    public Transaction[] tx_set;

    /// The enrollments that are being nominated / voted on
    public Enrollment[] enrolls;

    int opCmp (in ConsensusData data) const
    {
        const lhs_hash = hashFull(this);
        const rhs_hash = hashFull(data);

        return toShortHash(lhs_hash) < toShortHash(rhs_hash);
    }

    bool empty () const { return this == typeof(this).init; }
}

/// ConsensusData type testSymmetry check
unittest
{
    import agora.common.Serializer;
    import agora.common.Types;
    import agora.consensus.data.genesis.Test;

    testSymmetry!ConsensusData();

    Hash key = Hash("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f" ~
                    "1b60a8ce26f000000000019d6689c085ae165831e934ff763ae46a2" ~
                    "a6c172b3f1b60a8ce26f");
    Hash seed = Hash("0X4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB212" ~
                     "7B7AFDEDA33B4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E" ~
                     "2CC77AB2127B7AFDEDA33B");
    Signature sig = Signature("0x000000000000000000016f605ea9638d7bff58d2c0c" ~
                              "c2467c18e38b36367be78000000000000000000016f60" ~
                              "5ea9638d7bff58d2c0cc2467c18e38b36367be78");
    const Enrollment record = {
        utxo_key: key,
        random_seed: seed,
        cycle_length: 1008,
        enroll_sig: sig,
    };

    const(ConsensusData) data =
    {
        tx_set:  GenesisBlock.txs,
        enrolls: [ record, record, ],
    };

    testSymmetry(data);
}
