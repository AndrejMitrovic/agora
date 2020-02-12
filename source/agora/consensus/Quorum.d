/*******************************************************************************

    Contains the quorum generator algorithm.

    Note that if you use AscendingQuadratic for too many nodes it will
    assert as you will quickly run out of BOA.

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

    Build the quorum configuration for the entire network of the given
    registered enrollments. The random seed is used to shuffle the quorums.

    Params:
        keys = the keys of all the enrolled validators
        finder = the delegate to find UTXOs with
        rand_seed = the source of randomness

    Returns:
        the map of all quorum configurations

*******************************************************************************/

version (unittest) private QuorumConfig[PublicKey] buildQuorumConfigs (
    in Hash[] keys, UTXOFinder finder, const ref Hash rand_seed )
{
    Amount[PublicKey] all_stakes = buildStakes(keys, finder);

    QuorumConfig[PublicKey] quorums;
    foreach (node, amount; all_stakes)
        quorums[node] = buildQuorumConfig(node, keys, finder, rand_seed);

    return quorums;
}

/*******************************************************************************

    Build the quorum configuration for the given node key and the registered
    enrollments. The random seed is used to shuffle the quorum config.

    Params:
        node_key = the key of the node
        keys = the keys of all the enrolled validators
        finder = the delegate to find UTXOs with
        rand_seed = the source of randomness

    Returns:
        the map of all quorum configurations

*******************************************************************************/

public QuorumConfig buildQuorumConfig ( const ref PublicKey node_key,
    in Hash[] keys, UTXOFinder finder, const ref Hash rand_seed )
{
    Amount[PublicKey] all_stakes = buildStakes(keys, finder);
    NodeStake[] stakes_by_price = orderStakesDescending(all_stakes);

    const Amount min_quorum_amount = Amount(
        cast(ulong)(0.67 *
            stakes_by_price.map!(stake => stake.amount.getRaw).sum));

    auto node_stake = node_key in all_stakes;
    assert(node_stake !is null);

    return buildQuorumImpl(node_key, *node_stake, stakes_by_price,
        min_quorum_amount, rand_seed);
}

/// 2 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(2, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 128, WK.Keys[1].address: 128],
        counts.to!string);
}

/// 3 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(3, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 192, WK.Keys[1].address: 192,
        WK.Keys[2].address: 192], counts.to!string);
}

/// 3 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(3,
        prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 100, WK.Keys[1].address: 192,
        WK.Keys[2].address: 192], counts.to!string);
}

/// 3 nodes with descending stakes
unittest
{
    auto enrolls = genKeysAndFinder(3,
        prev => prev.mustSub(Amount.MinFreezeAmount),
        Amount.MinFreezeAmount.mul(3));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 192, WK.Keys[1].address: 192,
        WK.Keys[2].address: 95], counts.to!string);
}

/// 3 nodes with ascending quadratic stakes
unittest
{
    auto enrolls = genKeysAndFinder(3, prev => prev.mustAdd(prev));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 96, WK.Keys[1].address: 134,
        WK.Keys[2].address: 192], counts.to!string);
}

/// 4 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(4, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 193, WK.Keys[1].address: 196,
        WK.Keys[2].address: 196, WK.Keys[3].address: 183], counts.to!string);
}

/// 4 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(4, prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 111, WK.Keys[1].address: 139,
        WK.Keys[2].address: 217, WK.Keys[3].address: 256], counts.to!string);
}

/// 4 nodes with ascending quadratically increasing stakes
unittest
{
    auto enrolls = genKeysAndFinder(4, prev => prev.mustAdd(prev));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 96, WK.Keys[1].address: 117,
        WK.Keys[2].address: 219, WK.Keys[3].address: 256], counts.to!string);
}

/// 8 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(8, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 331, WK.Keys[1].address: 315,
        WK.Keys[2].address: 309, WK.Keys[3].address: 333,
        WK.Keys[4].address: 321, WK.Keys[5].address: 316,
        WK.Keys[6].address: 319, WK.Keys[7].address: 316], counts.to!string);
}

/// 8 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(8, prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 134, WK.Keys[1].address: 206,
        WK.Keys[2].address: 259, WK.Keys[3].address: 303,
        WK.Keys[4].address: 345, WK.Keys[5].address: 398,
        WK.Keys[6].address: 404, WK.Keys[7].address: 438], counts.to!string);
}

/// 8 nodes with ascending quadratically increasing stakes
// todo: fails with the quorum split check,
// awaiting answer on https://stellar.stackexchange.com/q/3038/2227
version (none)
unittest
{
    auto enrolls = genKeysAndFinder(8, prev => prev.mustAdd(prev));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 110, WK.Keys[1].address: 134,
        WK.Keys[2].address: 158, WK.Keys[3].address: 167,
        WK.Keys[4].address: 216, WK.Keys[5].address: 253,
        WK.Keys[6].address: 284, WK.Keys[7].address: 326,
        WK.Keys[8].address: 347, WK.Keys[9].address: 405,
        WK.Keys[10].address: 392, WK.Keys[11].address: 430,
        WK.Keys[12].address: 429, WK.Keys[13].address: 480,
        WK.Keys[14].address: 488, WK.Keys[15].address: 501], counts.to!string);
}

/// 16 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(16, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 318, WK.Keys[1].address: 310,
        WK.Keys[2].address: 308, WK.Keys[3].address: 328,
        WK.Keys[4].address: 312, WK.Keys[5].address: 327,
        WK.Keys[6].address: 317, WK.Keys[7].address: 303,
        WK.Keys[8].address: 314, WK.Keys[9].address: 322,
        WK.Keys[10].address: 327, WK.Keys[11].address: 337,
        WK.Keys[12].address: 327, WK.Keys[13].address: 334,
        WK.Keys[14].address: 285, WK.Keys[15].address: 351], counts.to!string);
}

/// 16 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(16, prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 90, WK.Keys[1].address: 125,
        WK.Keys[2].address: 185, WK.Keys[3].address: 182,
        WK.Keys[4].address: 222, WK.Keys[5].address: 246,
        WK.Keys[6].address: 299, WK.Keys[7].address: 296,
        WK.Keys[8].address: 345, WK.Keys[9].address: 358,
        WK.Keys[10].address: 397, WK.Keys[11].address: 443,
        WK.Keys[12].address: 467, WK.Keys[13].address: 441,
        WK.Keys[14].address: 503, WK.Keys[15].address: 521], counts.to!string);
}

/// 16 nodes with ascending stakes (Freeze * 2)
unittest
{
    auto enrolls = genKeysAndFinder(16,
        prev => prev.mustAdd(Amount.MinFreezeAmount.mul(2)));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 82, WK.Keys[1].address: 107,
        WK.Keys[2].address: 157, WK.Keys[3].address: 182,
        WK.Keys[4].address: 211, WK.Keys[5].address: 253,
        WK.Keys[6].address: 280, WK.Keys[7].address: 321,
        WK.Keys[8].address: 337, WK.Keys[9].address: 363,
        WK.Keys[10].address: 386, WK.Keys[11].address: 461,
        WK.Keys[12].address: 486, WK.Keys[13].address: 444,
        WK.Keys[14].address: 513, WK.Keys[15].address: 537], counts.to!string);
}

/// 16 nodes with ascending stakes (Freeze * 4)
unittest
{
    auto enrolls = genKeysAndFinder(16,
        prev => prev.mustAdd(Amount.MinFreezeAmount.mul(4)));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 75, WK.Keys[1].address: 106,
        WK.Keys[2].address: 141, WK.Keys[3].address: 184,
        WK.Keys[4].address: 195, WK.Keys[5].address: 263,
        WK.Keys[6].address: 280, WK.Keys[7].address: 313,
        WK.Keys[8].address: 328, WK.Keys[9].address: 376,
        WK.Keys[10].address: 392, WK.Keys[11].address: 468,
        WK.Keys[12].address: 479, WK.Keys[13].address: 456,
        WK.Keys[14].address: 516, WK.Keys[15].address: 548], counts.to!string);
}

/// 32 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(32, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 302, WK.Keys[1].address: 323,
        WK.Keys[2].address: 307, WK.Keys[3].address: 328,
        WK.Keys[4].address: 315, WK.Keys[5].address: 338,
        WK.Keys[6].address: 295, WK.Keys[7].address: 310,
        WK.Keys[8].address: 307, WK.Keys[9].address: 305,
        WK.Keys[10].address: 312, WK.Keys[11].address: 332,
        WK.Keys[12].address: 330, WK.Keys[13].address: 349,
        WK.Keys[14].address: 321, WK.Keys[15].address: 355,
        WK.Keys[16].address: 314, WK.Keys[17].address: 338,
        WK.Keys[18].address: 303, WK.Keys[19].address: 312,
        WK.Keys[20].address: 319, WK.Keys[21].address: 332,
        WK.Keys[22].address: 306, WK.Keys[23].address: 313,
        WK.Keys[24].address: 343, WK.Keys[25].address: 325,
        WK.Keys[26].address: 309, WK.Keys[27].address: 268,
        WK.Keys[28].address: 339, WK.Keys[29].address: 331,
        WK.Keys[30].address: 319, WK.Keys[31].address: 340], counts.to!string);
}

/// 32 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(32,
        prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 82, WK.Keys[1].address: 93,
        WK.Keys[2].address: 111, WK.Keys[3].address: 129,
        WK.Keys[4].address: 145, WK.Keys[5].address: 172,
        WK.Keys[6].address: 176, WK.Keys[7].address: 186,
        WK.Keys[8].address: 179, WK.Keys[9].address: 226,
        WK.Keys[10].address: 249, WK.Keys[11].address: 248,
        WK.Keys[12].address: 282, WK.Keys[13].address: 267,
        WK.Keys[14].address: 285, WK.Keys[15].address: 307,
        WK.Keys[16].address: 330, WK.Keys[17].address: 377,
        WK.Keys[18].address: 352, WK.Keys[19].address: 382,
        WK.Keys[20].address: 404, WK.Keys[21].address: 356,
        WK.Keys[22].address: 427, WK.Keys[23].address: 440,
        WK.Keys[24].address: 463, WK.Keys[25].address: 462,
        WK.Keys[26].address: 483, WK.Keys[27].address: 464,
        WK.Keys[28].address: 532, WK.Keys[29].address: 524,
        WK.Keys[30].address: 545, WK.Keys[31].address: 562], counts.to!string);
}

/// 64 nodes with equal stakes
unittest
{
    auto enrolls = genKeysAndFinder(64, prev => prev);
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 336, WK.Keys[1].address: 294,
        WK.Keys[2].address: 335, WK.Keys[3].address: 353,
        WK.Keys[4].address: 312, WK.Keys[5].address: 314,
        WK.Keys[6].address: 325, WK.Keys[7].address: 325,
        WK.Keys[8].address: 296, WK.Keys[9].address: 314,
        WK.Keys[10].address: 334, WK.Keys[11].address: 312,
        WK.Keys[12].address: 319, WK.Keys[13].address: 303,
        WK.Keys[14].address: 298, WK.Keys[15].address: 350,
        WK.Keys[16].address: 318, WK.Keys[17].address: 333,
        WK.Keys[18].address: 330, WK.Keys[19].address: 326,
        WK.Keys[20].address: 334, WK.Keys[21].address: 325,
        WK.Keys[22].address: 333, WK.Keys[23].address: 358,
        WK.Keys[24].address: 344, WK.Keys[25].address: 297,
        WK.Keys[26].address: 303, WK.Keys[27].address: 312,
        WK.Keys[28].address: 324, WK.Keys[29].address: 328,
        WK.Keys[30].address: 313, WK.Keys[31].address: 306,
        WK.Keys[32].address: 324, WK.Keys[33].address: 320,
        WK.Keys[34].address: 308, WK.Keys[35].address: 307,
        WK.Keys[36].address: 313, WK.Keys[37].address: 285,
        WK.Keys[38].address: 310, WK.Keys[39].address: 324,
        WK.Keys[40].address: 316, WK.Keys[41].address: 349,
        WK.Keys[42].address: 308, WK.Keys[43].address: 348,
        WK.Keys[44].address: 307, WK.Keys[45].address: 312,
        WK.Keys[46].address: 297, WK.Keys[47].address: 304,
        WK.Keys[48].address: 317, WK.Keys[49].address: 321,
        WK.Keys[50].address: 318, WK.Keys[51].address: 320,
        WK.Keys[52].address: 334, WK.Keys[53].address: 287,
        WK.Keys[54].address: 327, WK.Keys[55].address: 318,
        WK.Keys[56].address: 329, WK.Keys[57].address: 286,
        WK.Keys[58].address: 311, WK.Keys[59].address: 308,
        WK.Keys[60].address: 346, WK.Keys[61].address: 346,
        WK.Keys[62].address: 335, WK.Keys[63].address: 341], counts.to!string);
}

/// 64 nodes with ascending stakes
unittest
{
    auto enrolls = genKeysAndFinder(64,
        prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 72, WK.Keys[1].address: 78,
        WK.Keys[2].address: 95, WK.Keys[3].address: 86,
        WK.Keys[4].address: 99, WK.Keys[5].address: 120,
        WK.Keys[6].address: 119, WK.Keys[7].address: 134,
        WK.Keys[8].address: 139, WK.Keys[9].address: 136,
        WK.Keys[10].address: 146, WK.Keys[11].address: 171,
        WK.Keys[12].address: 177, WK.Keys[13].address: 175,
        WK.Keys[14].address: 182, WK.Keys[15].address: 201,
        WK.Keys[16].address: 187, WK.Keys[17].address: 194,
        WK.Keys[18].address: 208, WK.Keys[19].address: 237,
        WK.Keys[20].address: 231, WK.Keys[21].address: 242,
        WK.Keys[22].address: 240, WK.Keys[23].address: 253,
        WK.Keys[24].address: 245, WK.Keys[25].address: 273,
        WK.Keys[26].address: 263, WK.Keys[27].address: 271,
        WK.Keys[28].address: 301, WK.Keys[29].address: 257,
        WK.Keys[30].address: 276, WK.Keys[31].address: 316,
        WK.Keys[32].address: 329, WK.Keys[33].address: 320,
        WK.Keys[34].address: 332, WK.Keys[35].address: 401,
        WK.Keys[36].address: 365, WK.Keys[37].address: 360,
        WK.Keys[38].address: 379, WK.Keys[39].address: 365,
        WK.Keys[40].address: 431, WK.Keys[41].address: 382,
        WK.Keys[42].address: 366, WK.Keys[43].address: 395,
        WK.Keys[44].address: 422, WK.Keys[45].address: 442,
        WK.Keys[46].address: 450, WK.Keys[47].address: 465,
        WK.Keys[48].address: 469, WK.Keys[49].address: 484,
        WK.Keys[50].address: 489, WK.Keys[51].address: 454,
        WK.Keys[52].address: 516, WK.Keys[53].address: 448,
        WK.Keys[54].address: 480, WK.Keys[55].address: 480,
        WK.Keys[56].address: 503, WK.Keys[57].address: 539,
        WK.Keys[58].address: 504, WK.Keys[59].address: 535,
        WK.Keys[60].address: 547, WK.Keys[61].address: 568,
        WK.Keys[62].address: 590, WK.Keys[63].address: 546], counts.to!string);
}

/// Test buildQuorumConfig() manually with specific inputs
unittest
{
    auto enrolls = genKeysAndFinder(64,
        prev => prev.mustAdd(Amount.MinFreezeAmount));
    auto rand_seed = hashFull(0);

    auto q0_h1 = buildQuorumConfig(WK.Keys[0].address, enrolls.expand, rand_seed);
    assert(q0_h1 == QuorumConfig(4, [WK.Keys[20].address, WK.Keys[35].address,
        WK.Keys[0].address, WK.Keys[60].address, WK.Keys[25].address]),
        q0_h1.to!string);

    auto q0_h2 = buildQuorumConfig(WK.Keys[0].address, enrolls.expand,
        hashFull(rand_seed));
    assert(q0_h2 == QuorumConfig(4, [WK.Keys[41].address, WK.Keys[47].address,
        WK.Keys[0].address, WK.Keys[62].address, WK.Keys[7].address]),
        q0_h2.to!string);

    auto q63_h1 = buildQuorumConfig(WK.Keys[63].address, enrolls.expand,
        rand_seed);
    assert(q63_h1 == QuorumConfig(4, [WK.Keys[57].address, WK.Keys[63].address,
        WK.Keys[60].address, WK.Keys[58].address, WK.Keys[49].address]),
        q63_h1.to!string);

    auto q63_h2 = buildQuorumConfig(WK.Keys[63].address, enrolls.expand,
        hashFull(rand_seed));
    assert(q63_h2 == QuorumConfig(4, [WK.Keys[57].address, WK.Keys[34].address,
        WK.Keys[63].address, WK.Keys[61].address, WK.Keys[49].address]),
        q63_h2.to!string);
}

/// Test with outlier nodes with a large stake ratio
unittest
{
    auto enrolls = genKeysAndFinder(64,
        amount => Amount.MinFreezeAmount, // all other nodes have minimum stake
        Amount.MinFreezeAmount.mul(10));  // first node has most stake

    auto counts = countNodeInclusions(enrolls, getRandSeeds(64));
    assert(counts == [WK.Keys[0].address: 1986, WK.Keys[1].address: 286,
        WK.Keys[2].address: 273, WK.Keys[3].address: 299,
        WK.Keys[4].address: 297, WK.Keys[5].address: 306,
        WK.Keys[6].address: 291, WK.Keys[7].address: 272,
        WK.Keys[8].address: 307, WK.Keys[9].address: 340,
        WK.Keys[10].address: 305, WK.Keys[11].address: 294,
        WK.Keys[12].address: 290, WK.Keys[13].address: 276,
        WK.Keys[14].address: 288, WK.Keys[15].address: 292,
        WK.Keys[16].address: 261, WK.Keys[17].address: 294,
        WK.Keys[18].address: 293, WK.Keys[19].address: 295,
        WK.Keys[20].address: 327, WK.Keys[21].address: 299,
        WK.Keys[22].address: 294, WK.Keys[23].address: 312,
        WK.Keys[24].address: 299, WK.Keys[25].address: 297,
        WK.Keys[26].address: 301, WK.Keys[27].address: 306,
        WK.Keys[28].address: 277, WK.Keys[29].address: 318,
        WK.Keys[30].address: 265, WK.Keys[31].address: 287,
        WK.Keys[32].address: 286, WK.Keys[33].address: 301,
        WK.Keys[34].address: 298, WK.Keys[35].address: 304,
        WK.Keys[36].address: 287, WK.Keys[37].address: 262,
        WK.Keys[38].address: 290, WK.Keys[39].address: 281,
        WK.Keys[40].address: 302, WK.Keys[41].address: 314,
        WK.Keys[42].address: 291, WK.Keys[43].address: 314,
        WK.Keys[44].address: 284, WK.Keys[45].address: 319,
        WK.Keys[46].address: 286, WK.Keys[47].address: 291,
        WK.Keys[48].address: 286, WK.Keys[49].address: 254,
        WK.Keys[50].address: 304, WK.Keys[51].address: 272,
        WK.Keys[52].address: 301, WK.Keys[53].address: 313,
        WK.Keys[54].address: 306, WK.Keys[55].address: 289,
        WK.Keys[56].address: 287, WK.Keys[57].address: 283,
        WK.Keys[58].address: 290, WK.Keys[59].address: 308,
        WK.Keys[60].address: 299, WK.Keys[61].address: 261,
        WK.Keys[62].address: 279, WK.Keys[63].address: 311], counts.to!string);
}

/*******************************************************************************

    Build the quorum configuration for the given public key and the staked
    enrollments. The random seed is used to shuffle the quorum.

    The node's quorum will consist of nodes whos sum of stakes will
    be at least min_amount, or less if MAX_NODES_IN_QUORUM has been reached.

    Params:
        node_key = the key of the node for which to generate the quorum
        node_stake = the stake of the node for which to generate the quorum
        stakes = the list of stakes in descending order
        min_amount = the minimum amount a node's quorum's sum of stake should
                     be reached (unless MAX_NODES_IN_QUORUM is reached first)
        rand_seed = the source of randomness

    Notes:
        dice() should be replaced / improved to be more efficient,
        see also https://issues.dlang.org/show_bug.cgi?id=5849

*******************************************************************************/

private QuorumConfig buildQuorumImpl (PublicKey node_key, Amount node_stake,
    in NodeStake[] stakes, const Amount min_amount, in Hash rand_seed)
{
    QuorumConfig quorum;
    Amount quorum_sum;  // sum of the staked amount of the quorum for this node

    // to filter out duplicates generated by dice()
    auto added_nodes = BitField!uint(stakes.length);
    auto rnd_gen = getGenerator(node_key, rand_seed);

    // node must have itself in the quorum set
    quorum.nodes ~= node_key;
    if (!quorum_sum.add(node_stake))
        assert(0);

    // there may be less total nodes in the network than MIN_NODES_IN_QUORUM
    const MIN_NODES = min(MIN_NODES_IN_QUORUM, stakes.length);

    while (quorum.nodes.length < MIN_NODES &&
        quorum_sum < min_amount &&
        quorum.nodes.length < MAX_NODES_IN_QUORUM)
    {
        const idx = dice(rnd_gen, stakes.map!(stake => stake.amount.integral));
        auto qnode = stakes[idx];
        if (qnode.key == node_key || added_nodes[idx]) // skip self or duplicate
            continue;

        // we want a predictable order of nodes
        auto insert_idx = quorum.nodes.countUntil!(node => node >= qnode.key);
        if (insert_idx == -1)
            quorum.nodes ~= qnode.key;
        else
            quorum.nodes.insertInPlace(insert_idx, qnode.key);

        added_nodes[idx] = true;
        if (!quorum_sum.add(qnode.amount))
            assert(0);
    }

    const majority = max(1, cast(size_t)ceil(0.67 * quorum.nodes.length));
    quorum.threshold = majority;

    return quorum;
}

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
                    key, quorum.toToml, reason.to!string));

        normalizeQSet(scp_quorum);
        enforce(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check after normalization: %s",
                    key, quorum.toToml, reason.to!string));
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
    assert(toShortHash(hash) == 7283894889895411012uL);
}

/*******************************************************************************

    Create a random number generator which uses the hash of the random seed
    and a node's public key as an initializer for the engine.

    Using the Mersene Twister 19937 64-bit random number generator.
    The source of randomness is hashed together with the public key of the node,
    and then reduced from 64-bytes to to a short hash of 8 bytes,
    which is then fed to the RND generator.

    Params
        node_key = the public key of a node
        rand_seed = the source of randomness

    Returns:
        a Mersenne Twister 64bit random generator

*******************************************************************************/

private auto getGenerator (PublicKey node_key, Hash rand_seed)
{
    auto hash = hashMulti(node_key, rand_seed);
    Mt19937_64 gen;
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

    For each enrollment's UTXO key find the staked amount,
    and build a key => amount map.

    Params
        utxo_keys = the list of enrollments' UTXO keys
        finder = UTXO finder delegate

    Returns:
        a mapping of all keys => stakes

*******************************************************************************/

private Amount[PublicKey] buildStakes (in Hash[] utxo_keys, UTXOFinder finder)
{
    Amount[PublicKey] stakes;
    foreach (utxo_key; utxo_keys)
    {
        UTXOSetValue value;
        assert(finder(utxo_key, size_t.max, value),
            "UTXO for validator not found!");
        assert(value.output.address !in stakes,
            "Cannot have multiple enrollments for one validator!");

        stakes[value.output.address] = value.output.value;
    }

    return stakes;
}

/*******************************************************************************

    Params:
        stake_map = the map of node keys => their stake

    Returns:
        a descending set of nodes based on their stakes

*******************************************************************************/

private NodeStake[] orderStakesDescending (Amount[PublicKey] stake_map)
{
    auto stakes = stake_map
        .byKeyValue
        .map!(pair => NodeStake(pair.key, pair.value))
        .array;

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

private int[const(PublicKey)] countNodeInclusions (Enrolls, Range)(
    Enrolls enrolls, Range seeds)
{
    int[PublicKey] counts;
    foreach (rand_seed; seeds)
    {
        auto quorums = buildQuorumConfigs(enrolls.expand, rand_seed);
        verifyQuorumsSanity(quorums);

        // Intersection checks take roughly ~2 minutes for a configuration
        // of 16 node quorums, and grows exponentially after that.
        // By default we disable these checks unless overriden with
        // -version=EnableAllIntersectionChecks
        version (EnableAllIntersectionChecks)
            const bool check_intersections = true;
        else
            const bool check_intersections = quorums.length <= 8;

        //if (check_intersections && !verifyQuorumsIntersect(quorums))
        //    assert(false);

        foreach (key, quorum; quorums)
        {
            foreach (node; quorum.nodes)
                counts[node]++;
        }
    }

    return counts;
}

/// Generate random seeds by hashing a range of numbers: [0 .. count)
private auto getRandSeeds (size_t count)
{
    // using 'ulong' to get consistent hashes
    return iota(0, count).map!(idx => hashFull(cast(ulong)idx));
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
    const(Amount) delegate (Amount) getAmount,
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
            amount = getAmount(prev_amount);

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
