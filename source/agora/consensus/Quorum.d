/*******************************************************************************

    Contains the quorum generator algorithm.

    Note that if you use AscendingQuadratic for too many nodes it will
    Assert as you will quickly run out of BOA.

    Note thatintersection checks take roughly ~2 minutes for a configuration
    of 16 nodes with their quorums, by default we disable these checks for
    many nodes unless overriden with -version=EnableAllIntersectionChecks.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.Quorum;

/// Force intersection checks on all unittests
//version = EnableAllIntersectionChecks;

/// Generate new assertion blocks when calibrating the algorithm
//version = CalibrateQuorumBalancing;

import agora.common.Amount;
import agora.common.BitField;
import agora.common.Config;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Set;
import agora.common.Types;
import agora.consensus.data.Enrollment;
import agora.consensus.data.UTXOSetValue;
import agora.consensus.EnrollmentManager;
import agora.utils.PrettyPrinter;
import agora.utils.Test;

import scpd.Cpp;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types : uint256, NodeID;
import scpd.types.Utils;
import scpd.types.XDRBase;
import scpd.quorum.QuorumIntersectionChecker;
import scpd.quorum.QuorumTracker;

import std.algorithm;
import std.array;
import std.conv;
import std.exception;
import std.format;
import std.math;
import std.random;
import std.range;
import std.string;
import std.typecons;

version (unittest)
{
    import agora.utils.Log;
    import std.conv;
    import std.stdio;
}

/*******************************************************************************

    Minimum number of nodes to include in a quorum.
    The range is inclusive: length <= MIN_NODES_IN_QUORUM.

    As some nodes may have a large amount of stake compared to the
    rest of the network we want to ensure that other nodes get a chance of
    inclusion in a quorum set.

    For example, with nodes with this given stake
    (assume units are multiples of MinFreezeAmount):

    n1: 10, n2: 1, n3: 1, n4: 1, n5: 1

    Despite n1 having significantly more stake than the rest of the nodes
    we do not want to centralize the quorum configuration to only include
    this one node. This would lead to too much political (voting) power.

    The voting power of a holder may be increased by spawning multiple nodes,
    for example:

    [n1-1: 4, n1-2: 3, n1-3: 3], n2: 1, n3: 1

    This gives the nodes owner more political power, but less rewards if they
    started a single node with the collective sum of the stake.
    It's the operator's choice on how to distribute their voting power
    vs rewards ratio.

*******************************************************************************/

private enum MIN_NODES_IN_QUORUM = 3;

/*******************************************************************************

    Maximum number of nodes to include in a quorum.

    Note: this may be relaxed in the future.

*******************************************************************************/

private enum MAX_NODES_IN_QUORUM = 7;

/*******************************************************************************

    Build the quorum configuration for the given public key and the registered
    enrollment keys.

    Params:
        key = the key of the node for which to generate the quorum
        utxo_keys = the list of UTXO keys of all the active enrollments

*******************************************************************************/

public QuorumConfig buildQuorumConfig ( const ref PublicKey key,
    in Hash[] utxo_keys, UTXOFinder finder )
{
    NodeStake[] stakes = buildStakesDescending(key, utxo_keys, finder);

    QuorumConfig quorum;
    quorum.nodes ~= key;  // add ourself first

    // for filtering duplicates from dice()
    auto added = BitField!uint(stakes.length);
    auto rnd_gen = getGenerator(key);
    auto stake_amounts = stakes.map!(stake => stake.amount.integral);

    while (quorum.nodes.length < MIN_NODES_IN_QUORUM ||
        quorum.nodes.length < MAX_NODES_IN_QUORUM)
    {
        // todo: dice() should be replaced with something more efficient,
        // see https://issues.dlang.org/show_bug.cgi?id=5849
        auto idx = dice(rnd_gen, stake_amounts);
        if (added[idx])  // skip duplicate
            continue;

        quorum.nodes ~= stakes[idx].key;
        added[idx] = true;  // mark used

        if (quorum.nodes.length >= stakes.length + 1)  // our stake not included
            break;  // ran out of nodes
    }

    quorum.nodes.sort;
    quorum.threshold = quorum.nodes.length;
    return quorum;
}

/// Helper routine:
private void assertEq (
    in QuorumConfig actual, size_t threshold, KeyPair[] key_pairs,
    string file = __FILE__, size_t line = __LINE__)
{
    import core.exception;

    // we need to recreate the expected qc, as the nodes are sorted
    // by address, not by keypair
    QuorumConfig expected =
    {
        threshold : threshold,
        nodes : key_pairs.map!(p => cast()p.address).array
    };
    sort(expected.nodes);

    if (expected == actual)
        return;

    if (actual.threshold != actual.nodes.length)
        throw new AssertError(
            format("Threshold %s does not match node count %s",
                actual.threshold, actual.nodes.length));

    if (expected.threshold != actual.threshold)
        throw new AssertError(
            format("Actual threshold is: %s", actual.threshold),
            file, line);

    if (expected.nodes != actual.nodes)
    {
        //throw new AssertError(
            //format("Actual nodes are: %s", actual.nodes.map!(n => WK.Keys[WK.Keys[n]])),
            //file, line);
        auto nodes = actual.nodes.map!(n => WK.Keys[WK.Keys[n]]).map!(to!string).array;
        sort(nodes);
        writefln("%s(%s): Actual nodes are: %s", file, line, nodes);
    }

    //assert(0);
}

/// 3 nodes with equal stakes
unittest
{
    auto quorums = buildTestQuorums(3);
    verifyQuorumsSanity(quorums);
    verifyQuorumsIntersect(quorums);

    assertEq(quorums[WK.Keys.A.address], 3, [WK.Keys.A, WK.Keys.B, WK.Keys.C]);
    assertEq(quorums[WK.Keys.B.address], 3, [WK.Keys.A, WK.Keys.B, WK.Keys.C]);
    assertEq(quorums[WK.Keys.C.address], 3, [WK.Keys.A, WK.Keys.B, WK.Keys.C]);
}

/// 4 nodes with equal stakes
unittest
{
    auto quorums = buildTestQuorums(4);
    verifyQuorumsSanity(quorums);
    verifyQuorumsIntersect(quorums);

    assertEq(quorums[WK.Keys.A.address], 4, [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D]);
    assertEq(quorums[WK.Keys.B.address], 4, [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D]);
    assertEq(quorums[WK.Keys.C.address], 4, [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D]);
    assertEq(quorums[WK.Keys.D.address], 4, [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D]);
}

/// 8 nodes with equal stakes
unittest
{
    auto quorums = buildTestQuorums(8);
    verifyQuorumsSanity(quorums);
    verifyQuorumsIntersect(quorums);

    assertEq(quorums[WK.Keys.A.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D,
         WK.Keys.E, WK.Keys.F, WK.Keys.G]);

    assertEq(quorums[WK.Keys.B.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D,
         WK.Keys.E, WK.Keys.F, WK.Keys.G]);

    assertEq(quorums[WK.Keys.C.address], 7,
        [WK.Keys.A, WK.Keys.C, WK.Keys.D, WK.Keys.E,
         WK.Keys.F, WK.Keys.G, WK.Keys.H]);

    assertEq(quorums[WK.Keys.D.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.D, WK.Keys.E,
         WK.Keys.F, WK.Keys.G, WK.Keys.H]);

    assertEq(quorums[WK.Keys.E.address], 7,
        [WK.Keys.B, WK.Keys.C, WK.Keys.D, WK.Keys.E,
         WK.Keys.F, WK.Keys.G, WK.Keys.H]);

    assertEq(quorums[WK.Keys.F.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D,
         WK.Keys.E, WK.Keys.F, WK.Keys.H]);

    assertEq(quorums[WK.Keys.G.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.E,
         WK.Keys.F, WK.Keys.G, WK.Keys.H]);

    assertEq(quorums[WK.Keys.H.address], 7,
        [WK.Keys.A, WK.Keys.B, WK.Keys.C, WK.Keys.D,
         WK.Keys.F, WK.Keys.G, WK.Keys.H]);
}

///// 8 nodes with equal stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(8);
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 3, WK.Keys[1].address: 2,
//        WK.Keys[2].address: 2, WK.Keys[3].address: 3,
//        WK.Keys[4].address: 4, WK.Keys[5].address: 5,
//        WK.Keys[6].address: 4, WK.Keys[7].address: 1], counts.to!string);
//}

///// 8 nodes with ascending stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(8.mustAdd(Amount.MinFreezeAmount));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 134, WK.Keys[1].address: 206,
//        WK.Keys[2].address: 259, WK.Keys[3].address: 303,
//        WK.Keys[4].address: 345, WK.Keys[5].address: 398,
//        WK.Keys[6].address: 404, WK.Keys[7].address: 438], counts.to!string);
//}

///// 8 nodes with ascending quadratically increasing stakes
//// todo: fails with the quorum split check,
//// awaiting answer on https://stellar.stackexchange.com/q/3038/2227
//version (none)
//unittest
//{
//    auto enrolls = genKeysAndFinder(8.mustAdd(prev));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 110, WK.Keys[1].address: 134,
//        WK.Keys[2].address: 158, WK.Keys[3].address: 167,
//        WK.Keys[4].address: 216, WK.Keys[5].address: 253,
//        WK.Keys[6].address: 284, WK.Keys[7].address: 326,
//        WK.Keys[8].address: 347, WK.Keys[9].address: 405,
//        WK.Keys[10].address: 392, WK.Keys[11].address: 430,
//        WK.Keys[12].address: 429, WK.Keys[13].address: 480,
//        WK.Keys[14].address: 488, WK.Keys[15].address: 501], counts.to!string);
//}

///// 16 nodes with equal stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(16);
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 318, WK.Keys[1].address: 310,
//        WK.Keys[2].address: 308, WK.Keys[3].address: 328,
//        WK.Keys[4].address: 312, WK.Keys[5].address: 327,
//        WK.Keys[6].address: 317, WK.Keys[7].address: 303,
//        WK.Keys[8].address: 314, WK.Keys[9].address: 322,
//        WK.Keys[10].address: 327, WK.Keys[11].address: 337,
//        WK.Keys[12].address: 327, WK.Keys[13].address: 334,
//        WK.Keys[14].address: 285, WK.Keys[15].address: 351], counts.to!string);
//}

///// 16 nodes with ascending stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(16.mustAdd(Amount.MinFreezeAmount));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 90, WK.Keys[1].address: 125,
//        WK.Keys[2].address: 185, WK.Keys[3].address: 182,
//        WK.Keys[4].address: 222, WK.Keys[5].address: 246,
//        WK.Keys[6].address: 299, WK.Keys[7].address: 296,
//        WK.Keys[8].address: 345, WK.Keys[9].address: 358,
//        WK.Keys[10].address: 397, WK.Keys[11].address: 443,
//        WK.Keys[12].address: 467, WK.Keys[13].address: 441,
//        WK.Keys[14].address: 503, WK.Keys[15].address: 521], counts.to!string);
//}

///// 16 nodes with ascending stakes (Freeze * 2)
//unittest
//{
//    auto enrolls = genKeysAndFinder(16,
//        prev => prev.mustAdd(Amount.MinFreezeAmount.mul(2)));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 82, WK.Keys[1].address: 107,
//        WK.Keys[2].address: 157, WK.Keys[3].address: 182,
//        WK.Keys[4].address: 211, WK.Keys[5].address: 253,
//        WK.Keys[6].address: 280, WK.Keys[7].address: 321,
//        WK.Keys[8].address: 337, WK.Keys[9].address: 363,
//        WK.Keys[10].address: 386, WK.Keys[11].address: 461,
//        WK.Keys[12].address: 486, WK.Keys[13].address: 444,
//        WK.Keys[14].address: 513, WK.Keys[15].address: 537], counts.to!string);
//}

///// 16 nodes with ascending stakes (Freeze * 4)
//unittest
//{
//    auto enrolls = genKeysAndFinder(16,
//        prev => prev.mustAdd(Amount.MinFreezeAmount.mul(4)));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 75, WK.Keys[1].address: 106,
//        WK.Keys[2].address: 141, WK.Keys[3].address: 184,
//        WK.Keys[4].address: 195, WK.Keys[5].address: 263,
//        WK.Keys[6].address: 280, WK.Keys[7].address: 313,
//        WK.Keys[8].address: 328, WK.Keys[9].address: 376,
//        WK.Keys[10].address: 392, WK.Keys[11].address: 468,
//        WK.Keys[12].address: 479, WK.Keys[13].address: 456,
//        WK.Keys[14].address: 516, WK.Keys[15].address: 548], counts.to!string);
//}

///// 32 nodes with equal stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(32);
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 302, WK.Keys[1].address: 323,
//        WK.Keys[2].address: 307, WK.Keys[3].address: 328,
//        WK.Keys[4].address: 315, WK.Keys[5].address: 338,
//        WK.Keys[6].address: 295, WK.Keys[7].address: 310,
//        WK.Keys[8].address: 307, WK.Keys[9].address: 305,
//        WK.Keys[10].address: 312, WK.Keys[11].address: 332,
//        WK.Keys[12].address: 330, WK.Keys[13].address: 349,
//        WK.Keys[14].address: 321, WK.Keys[15].address: 355,
//        WK.Keys[16].address: 314, WK.Keys[17].address: 338,
//        WK.Keys[18].address: 303, WK.Keys[19].address: 312,
//        WK.Keys[20].address: 319, WK.Keys[21].address: 332,
//        WK.Keys[22].address: 306, WK.Keys[23].address: 313,
//        WK.Keys[24].address: 343, WK.Keys[25].address: 325,
//        WK.Keys[26].address: 309, WK.Keys[27].address: 268,
//        WK.Keys[28].address: 339, WK.Keys[29].address: 331,
//        WK.Keys[30].address: 319, WK.Keys[31].address: 340], counts.to!string);
//}

///// 32 nodes with ascending stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(32,
//        prev => prev.mustAdd(Amount.MinFreezeAmount));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 82, WK.Keys[1].address: 93,
//        WK.Keys[2].address: 111, WK.Keys[3].address: 129,
//        WK.Keys[4].address: 145, WK.Keys[5].address: 172,
//        WK.Keys[6].address: 176, WK.Keys[7].address: 186,
//        WK.Keys[8].address: 179, WK.Keys[9].address: 226,
//        WK.Keys[10].address: 249, WK.Keys[11].address: 248,
//        WK.Keys[12].address: 282, WK.Keys[13].address: 267,
//        WK.Keys[14].address: 285, WK.Keys[15].address: 307,
//        WK.Keys[16].address: 330, WK.Keys[17].address: 377,
//        WK.Keys[18].address: 352, WK.Keys[19].address: 382,
//        WK.Keys[20].address: 404, WK.Keys[21].address: 356,
//        WK.Keys[22].address: 427, WK.Keys[23].address: 440,
//        WK.Keys[24].address: 463, WK.Keys[25].address: 462,
//        WK.Keys[26].address: 483, WK.Keys[27].address: 464,
//        WK.Keys[28].address: 532, WK.Keys[29].address: 524,
//        WK.Keys[30].address: 545, WK.Keys[31].address: 562], counts.to!string);
//}

///// 64 nodes with equal stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(64);
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 336, WK.Keys[1].address: 294,
//        WK.Keys[2].address: 335, WK.Keys[3].address: 353,
//        WK.Keys[4].address: 312, WK.Keys[5].address: 314,
//        WK.Keys[6].address: 325, WK.Keys[7].address: 325,
//        WK.Keys[8].address: 296, WK.Keys[9].address: 314,
//        WK.Keys[10].address: 334, WK.Keys[11].address: 312,
//        WK.Keys[12].address: 319, WK.Keys[13].address: 303,
//        WK.Keys[14].address: 298, WK.Keys[15].address: 350,
//        WK.Keys[16].address: 318, WK.Keys[17].address: 333,
//        WK.Keys[18].address: 330, WK.Keys[19].address: 326,
//        WK.Keys[20].address: 334, WK.Keys[21].address: 325,
//        WK.Keys[22].address: 333, WK.Keys[23].address: 358,
//        WK.Keys[24].address: 344, WK.Keys[25].address: 297,
//        WK.Keys[26].address: 303, WK.Keys[27].address: 312,
//        WK.Keys[28].address: 324, WK.Keys[29].address: 328,
//        WK.Keys[30].address: 313, WK.Keys[31].address: 306,
//        WK.Keys[32].address: 324, WK.Keys[33].address: 320,
//        WK.Keys[34].address: 308, WK.Keys[35].address: 307,
//        WK.Keys[36].address: 313, WK.Keys[37].address: 285,
//        WK.Keys[38].address: 310, WK.Keys[39].address: 324,
//        WK.Keys[40].address: 316, WK.Keys[41].address: 349,
//        WK.Keys[42].address: 308, WK.Keys[43].address: 348,
//        WK.Keys[44].address: 307, WK.Keys[45].address: 312,
//        WK.Keys[46].address: 297, WK.Keys[47].address: 304,
//        WK.Keys[48].address: 317, WK.Keys[49].address: 321,
//        WK.Keys[50].address: 318, WK.Keys[51].address: 320,
//        WK.Keys[52].address: 334, WK.Keys[53].address: 287,
//        WK.Keys[54].address: 327, WK.Keys[55].address: 318,
//        WK.Keys[56].address: 329, WK.Keys[57].address: 286,
//        WK.Keys[58].address: 311, WK.Keys[59].address: 308,
//        WK.Keys[60].address: 346, WK.Keys[61].address: 346,
//        WK.Keys[62].address: 335, WK.Keys[63].address: 341], counts.to!string);
//}

///// 64 nodes with ascending stakes
//unittest
//{
//    auto enrolls = genKeysAndFinder(64,
//        prev => prev.mustAdd(Amount.MinFreezeAmount));
//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 72, WK.Keys[1].address: 78,
//        WK.Keys[2].address: 95, WK.Keys[3].address: 86,
//        WK.Keys[4].address: 99, WK.Keys[5].address: 120,
//        WK.Keys[6].address: 119, WK.Keys[7].address: 134,
//        WK.Keys[8].address: 139, WK.Keys[9].address: 136,
//        WK.Keys[10].address: 146, WK.Keys[11].address: 171,
//        WK.Keys[12].address: 177, WK.Keys[13].address: 175,
//        WK.Keys[14].address: 182, WK.Keys[15].address: 201,
//        WK.Keys[16].address: 187, WK.Keys[17].address: 194,
//        WK.Keys[18].address: 208, WK.Keys[19].address: 237,
//        WK.Keys[20].address: 231, WK.Keys[21].address: 242,
//        WK.Keys[22].address: 240, WK.Keys[23].address: 253,
//        WK.Keys[24].address: 245, WK.Keys[25].address: 273,
//        WK.Keys[26].address: 263, WK.Keys[27].address: 271,
//        WK.Keys[28].address: 301, WK.Keys[29].address: 257,
//        WK.Keys[30].address: 276, WK.Keys[31].address: 316,
//        WK.Keys[32].address: 329, WK.Keys[33].address: 320,
//        WK.Keys[34].address: 332, WK.Keys[35].address: 401,
//        WK.Keys[36].address: 365, WK.Keys[37].address: 360,
//        WK.Keys[38].address: 379, WK.Keys[39].address: 365,
//        WK.Keys[40].address: 431, WK.Keys[41].address: 382,
//        WK.Keys[42].address: 366, WK.Keys[43].address: 395,
//        WK.Keys[44].address: 422, WK.Keys[45].address: 442,
//        WK.Keys[46].address: 450, WK.Keys[47].address: 465,
//        WK.Keys[48].address: 469, WK.Keys[49].address: 484,
//        WK.Keys[50].address: 489, WK.Keys[51].address: 454,
//        WK.Keys[52].address: 516, WK.Keys[53].address: 448,
//        WK.Keys[54].address: 480, WK.Keys[55].address: 480,
//        WK.Keys[56].address: 503, WK.Keys[57].address: 539,
//        WK.Keys[58].address: 504, WK.Keys[59].address: 535,
//        WK.Keys[60].address: 547, WK.Keys[61].address: 568,
//        WK.Keys[62].address: 590, WK.Keys[63].address: 546], counts.to!string);
//}

///// Test buildQuorumConfig() manually with specific inputs
//unittest
//{
//    auto enrolls = genKeysAndFinder(64,
//        prev => prev.mustAdd(Amount.MinFreezeAmount));

//    auto q0_h1 = buildQuorumConfig(WK.Keys[0].address, enrolls.expand);
//    Assert(q0_h1 == QuorumConfig(4, [WK.Keys[20].address, WK.Keys[35].address,
//        WK.Keys[0].address, WK.Keys[60].address, WK.Keys[25].address]),
//        q0_h1.to!string);

//    auto q0_h2 = buildQuorumConfig(WK.Keys[0].address, enrolls.expand);
//    Assert(q0_h2 == QuorumConfig(4, [WK.Keys[41].address, WK.Keys[47].address,
//        WK.Keys[0].address, WK.Keys[62].address, WK.Keys[7].address]),
//        q0_h2.to!string);

//    auto q63_h1 = buildQuorumConfig(WK.Keys[63].address, enrolls.expand);
//    Assert(q63_h1 == QuorumConfig(4, [WK.Keys[57].address, WK.Keys[63].address,
//        WK.Keys[60].address, WK.Keys[58].address, WK.Keys[49].address]),
//        q63_h1.to!string);

//    auto q63_h2 = buildQuorumConfig(WK.Keys[63].address, enrolls.expand);
//    Assert(q63_h2 == QuorumConfig(4, [WK.Keys[57].address, WK.Keys[34].address,
//        WK.Keys[63].address, WK.Keys[61].address, WK.Keys[49].address]),
//        q63_h2.to!string);
//}

///// Test with outlier nodes with a large stake ratio
//unittest
//{
//    auto enrolls = genKeysAndFinder(64,
//        amount => Amount.MinFreezeAmount, // all other nodes have minimum stake
//        Amount.MinFreezeAmount.mul(10));  // first node has most stake

//    auto counts = countNodeInclusions(enrolls.expand);
//    Assert(counts == [WK.Keys[0].address: 1986, WK.Keys[1].address: 286,
//        WK.Keys[2].address: 273, WK.Keys[3].address: 299,
//        WK.Keys[4].address: 297, WK.Keys[5].address: 306,
//        WK.Keys[6].address: 291, WK.Keys[7].address: 272,
//        WK.Keys[8].address: 307, WK.Keys[9].address: 340,
//        WK.Keys[10].address: 305, WK.Keys[11].address: 294,
//        WK.Keys[12].address: 290, WK.Keys[13].address: 276,
//        WK.Keys[14].address: 288, WK.Keys[15].address: 292,
//        WK.Keys[16].address: 261, WK.Keys[17].address: 294,
//        WK.Keys[18].address: 293, WK.Keys[19].address: 295,
//        WK.Keys[20].address: 327, WK.Keys[21].address: 299,
//        WK.Keys[22].address: 294, WK.Keys[23].address: 312,
//        WK.Keys[24].address: 299, WK.Keys[25].address: 297,
//        WK.Keys[26].address: 301, WK.Keys[27].address: 306,
//        WK.Keys[28].address: 277, WK.Keys[29].address: 318,
//        WK.Keys[30].address: 265, WK.Keys[31].address: 287,
//        WK.Keys[32].address: 286, WK.Keys[33].address: 301,
//        WK.Keys[34].address: 298, WK.Keys[35].address: 304,
//        WK.Keys[36].address: 287, WK.Keys[37].address: 262,
//        WK.Keys[38].address: 290, WK.Keys[39].address: 281,
//        WK.Keys[40].address: 302, WK.Keys[41].address: 314,
//        WK.Keys[42].address: 291, WK.Keys[43].address: 314,
//        WK.Keys[44].address: 284, WK.Keys[45].address: 319,
//        WK.Keys[46].address: 286, WK.Keys[47].address: 291,
//        WK.Keys[48].address: 286, WK.Keys[49].address: 254,
//        WK.Keys[50].address: 304, WK.Keys[51].address: 272,
//        WK.Keys[52].address: 301, WK.Keys[53].address: 313,
//        WK.Keys[54].address: 306, WK.Keys[55].address: 289,
//        WK.Keys[56].address: 287, WK.Keys[57].address: 283,
//        WK.Keys[58].address: 290, WK.Keys[59].address: 308,
//        WK.Keys[60].address: 299, WK.Keys[61].address: 261,
//        WK.Keys[62].address: 279, WK.Keys[63].address: 311], counts.to!string);
//}

/*******************************************************************************

    Verify that the provided quorum sets are considered sane by SCP.

    The quorums are checked both pre and post-normalization,
    with extra safety checks enabled.

    Params:
        quorums = the quorum map of (node => quorum) to verify

    Throws:
        AssertError if the quorum is not considered sane by SCP.

*******************************************************************************/

private void verifyQuorumsSanity (QuorumConfig[PublicKey] quorums)
{
    import scpd.scp.QuorumSetUtils;

    foreach (key, quorum; quorums)
    {
        auto scp_quorum = toSCPQuorumSet(quorum);
        const(char)* reason;
        enforce(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check before normalization: %s",
                    key, quorum, reason.to!string));

        normalizeQSet(scp_quorum);
        enforce(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check after normalization: %s",
                    key, quorum, reason.to!string));
    }
}

/*******************************************************************************

    Verify that all the quorums intersect according to the quorum checker
    routines designed by Stellar

    Params:
        quorums = the quorums to check

    Returns:
        true if all the quorums enjoy quorum intersection

*******************************************************************************/

private bool verifyQuorumsIntersect (QuorumConfig[PublicKey] quorums)
{
    auto qm = QuorumTracker.QuorumMap.create();
    foreach (key, quorum; quorums)
    {
        auto scp = toSCPQuorumSet(quorum);
        auto scp_quorum = makeSharedSCPQuorumSet(scp);
        auto scp_key = NodeID(uint256(key));
        qm[scp_key] = scp_quorum;
    }

    auto qic = QuorumIntersectionChecker.create(qm);
    if (!qic.networkEnjoysQuorumIntersection())
        return false;

    auto splits = qic.getPotentialSplit();

    // todo: log these
    return splits.first.length != 0 && splits.second.length != 0;
}

/// Create a shorthash from a 64-byte blob to initialize the rnd generator
private ulong toShortHash (const ref Hash hash) @trusted
{
    import libsodium.crypto_shorthash;
    import std.bitmanip;

    // generated once with 'crypto_shorthash_keygen'
    static immutable ubyte[crypto_shorthash_KEYBYTES] PublicKey =
        [111, 165, 189, 80, 37, 5, 16, 194, 39, 214, 156, 169, 235, 221, 21, 126];

    ubyte[ulong.sizeof] short_hash;
    crypto_shorthash(short_hash.ptr, hash[].ptr, 64, PublicKey.ptr);

    // endianess: need to be consistent how ubyte[4] is interpreted as a ulong
    return littleEndianToNative!ulong(short_hash[]);
}

///
unittest
{
    const hash = Hash(
        "0xe0343d063b14c52630563ec81b0f91a84ddb05f2cf05a2e4330ddc79bd3a06e57" ~
        "c2e756f276c112342ff1d6f1e74d05bdb9bf880abd74a2e512654e12d171a74");
    Assert(toShortHash(hash) == 7283894889895411012uL);
}

/*******************************************************************************

    Create a random number generator which uses the node's public key as an
    initializer for the RNG engine.

    Using the Mersene Twister 19937 64-bit random number generator.
    The public key is reduced to a short hash of 8 bytes,
    which is then fed to the RND generator.

    Params
        key = the public key of a node

    Returns:
        a Mersenne Twister 64bit random generator

*******************************************************************************/

private auto getGenerator (PublicKey key)
{
    Mt19937_64 gen;
    auto hash = hashFull(key[]);  // key is only 32 bytes, hash is 64
    gen.seed(toShortHash(hash));
    return gen;
}

/// The pair of (key, stake) for each node
private struct NodeStake
{
    /// the node key
    private PublicKey key;

    /// the node stake
    private Amount amount;
}

/*******************************************************************************

    Build a list of NodeStake's in descending stake order

    Params
        filter = the node's own key should be filtered here
        utxo_keys = the list of enrollments' UTXO keys
        finder = utxo to stake & public key lookup delegate

    Returns:
        the list of stakes in descending stake order

*******************************************************************************/

private NodeStake[] buildStakesDescending (const ref PublicKey filter,
    in Hash[] utxo_keys, UTXOFinder finder)
{
    static NodeStake[] stakes;
    stakes.length = 0;
    assumeSafeAppend(stakes);

    foreach (utxo_key; utxo_keys)
    {
        UTXOSetValue value;
        assert(finder(utxo_key, size_t.max, value),
            "UTXO for validator not found!");

        if (value.output.address != filter)
            stakes ~= NodeStake(value.output.address, value.output.value);
    }

    stakes.sort!((a, b) => a.amount > b.amount);
    return stakes;
}

version (unittest):

/*******************************************************************************

    Build the quorum configs for the given enrollments and range of seeds,
    and return a map of the number of times each node was included in
    another node's quorum set.

    Returns:
        the map of node => quorum set inclusion counts

*******************************************************************************/

private QuorumConfig[PublicKey] buildTestQuorums (size_t node_count,
    const(Amount) delegate (Amount) getAmount = null,
    Amount initial_amount = Amount.MinFreezeAmount)
{
    QuorumConfig[PublicKey] quorums;
    auto enrolls = genKeysAndFinder(node_count, getAmount, initial_amount);

    foreach (idx; 0 .. node_count)
    {
        quorums[WK.Keys[idx].address] = buildQuorumConfig(
            WK.Keys[idx].address, enrolls.expand);
    }

    return quorums;
}

/// convenience, since Amount does not implement multiplication
private Amount mul (in Amount amount, in size_t multiplier)
{
    if (multiplier == 0)
        return Amount.init;

    Amount result = Amount(0);
    foreach (_; 0 .. multiplier)
        result.mustAdd(amount);
    return result;
}

/// Generate a tuple pair of (Hash[], UTXOFinder)
private auto genKeysAndFinder (size_t enroll_count,
    const(Amount) delegate (Amount) getAmount = null,
    Amount initial_amount = Amount.MinFreezeAmount,
    size_t line = __LINE__)
{
    import agora.common.Amount;
    import agora.consensus.data.Transaction;
    import agora.consensus.Genesis;

    TestUTXOSet storage = new TestUTXOSet;
    Hash[] keys;

    Amount prev_amount;
    foreach (idx; 0 .. enroll_count)
    {
        Amount amount;
        if (idx == 0)
            amount = initial_amount;
        else
            amount = getAmount is null ? prev_amount : getAmount(prev_amount);

        Transaction tx =
        {
            type : TxType.Freeze,
            outputs: [Output(amount, WK.Keys[idx].address)]
        };

        storage.put(tx);
        prev_amount = amount;
    }

    return tuple(storage.keys, &storage.findUTXO);
}

void Assert (string file = __FILE__, size_t line = __LINE__)(bool cond, string error)
{
    if (!cond)
        stderr.writefln("%s(%s,0): Error: %s", file, line, error);
}

void Assert (string file = __FILE__, size_t line = __LINE__)(bool cond)
{
    if (!cond)
        stderr.writefln("%s(%s,0): Error", file, line);
}
