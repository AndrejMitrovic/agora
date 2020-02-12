/*******************************************************************************

    Contains the quorum generator algorithm.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.Quorum;

import agora.common.Amount;
import agora.common.BitField;
import agora.common.Config;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Set;
import agora.consensus.data.Enrollment;
import agora.consensus.data.UTXOSet;
import agora.consensus.EnrollmentManager;
import agora.utils.PrettyPrinter;

import scpd.Cpp;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types : StellarHash = Hash, NodeID;
import scpd.types.Utils;
import scpd.types.XDRBase;

import scpd.quorum.QuorumIntersectionChecker;
import scpd.quorum.QuorumTracker;

import std.algorithm;
import std.array;
import std.conv;
import std.format;
import std.math;
import std.random;
import std.range;
import std.string;
import std.typecons;

import std.stdio;

/// limits the number of nodes in a quorum set
private enum MAX_NODES_IN_QUORUM = 7;

/*******************************************************************************

    Build the quorum configuration for the entire network of the given
    registered enrollments. The random seed is used to shuffle the quorums.

    Params:
        enrolls = the array of registered enrollments
        finder = the delegate to find UTXOs with
        rand_seed = the source of randomness

    Returns:
        the map of all quorum configurations

*******************************************************************************/

public QuorumConfig[PublicKey] buildQuorumConfigs ( Enrollment[] enrolls,
    UTXOFinder finder, Hash rand_seed )
{
    Amount[PublicKey] all_stakes = buildStakes(enrolls, finder);
    NodeStake[] stakes_by_price = orderStakesDescending(all_stakes);

    const Amount min_quorum_amount = Amount(
        cast(ulong)(10_000_000 * (0.67 *  // todo: add multiply() support
            stakes_by_price.map!(stake => stake.amount.integral)
                .sum)));

    auto quorums = buildQuorums(stakes_by_price, min_quorum_amount, rand_seed);
    verifyQuorumsSanity(quorums);
    verifyQuorumsIntersect(quorums);

    return quorums;
}

///
unittest
{
    foreach (seed; 0 .. 128)
    {
        auto rand_seed = hashFull(seed);
        auto quorums = buildQuorumConfigs(genEnrollments(10).expand, rand_seed);
        // writeln(quorums.toToml);  // for testing with go-scp
    }
}

/*******************************************************************************

    Build the quorum configuration for the entire network of the given
    the provided stakes enrollments. The random seed is used to shuffle the
    quorums.

    Each node will assign nodes to its quorum until either the minimum
    staken amount is reached, or MAX_NODES_IN_QUORUM has been reached.

    Params:
        stakes = the list of stakes, in descending order
        min_amount = the minimum amount a node's quorum's sum of stake should
                     be reached (unless MAX_NODES_IN_QUORUM is reached first)
        rand_seed = the source of randomness

    Notes:
        dice() should be replaced / improved to be more efficient,
        see also https://issues.dlang.org/show_bug.cgi?id=5849

*******************************************************************************/

private QuorumConfig[PublicKey] buildQuorums (in NodeStake[] stakes,
    const Amount min_amount, in Hash rand_seed)
{
    QuorumConfig[PublicKey] result;
    Set!PublicKey used_qnodes;
    auto assigned_nodes = BitField!uint(stakes.length);

    foreach (node; stakes)
    {
        Amount quorum_sum;  // sum of the staked amount of the quorum for this node

        // dice() can return duplicates
        auto added_nodes = BitField!uint(stakes.length);
        auto rnd_gen = getGenerator(node.key, rand_seed);
        auto quorum = &result.require(node.key, QuorumConfig.init);

        while (quorum_sum < min_amount &&
            quorum.nodes.length < MAX_NODES_IN_QUORUM)
        {
            const idx = dice(rnd_gen,
                stakes.map!(stake => stake.amount.integral));

            if (added_nodes[idx])
                continue;

            auto qnode = stakes[idx];
            quorum.nodes ~= qnode.key;
            assigned_nodes[idx] = true;
            added_nodes[idx] = true;

            if (!quorum_sum.add(qnode.amount))
                assert(0);
        }

        // +1 because the node itself also counts as one
        const majority = max(1, cast(size_t)floor(0.67 * (1 + quorum.nodes.length)));
        quorum.threshold = majority;
    }

    assignLeftoverNodes(rand_seed, stakes, assigned_nodes, result);
    return result;
}

/*******************************************************************************

    For any unassigned nodes, assign each to a random node's quorum.

    Params:
        rand_seed = the source of randomness
        stakes = all the node stakes
        assigned_nodes = all assigned nodes
        quorums = existing quorums which might be updated

*******************************************************************************/

private void assignLeftoverNodes (in Hash rand_seed, in NodeStake[] stakes,
    /*in*/ BitField!uint assigned_nodes, QuorumConfig[PublicKey] quorums)
{
    foreach (idx; 0 .. assigned_nodes.length)
    {
        if (!assigned_nodes[idx])
            continue;

        auto qnode = stakes[idx];

        auto lucky_node = stakes
            .randomCover(getGenerator(qnode.key, rand_seed))
            .filter!(node => node.key != qnode.key)  // filter the node itself
            .front.key;

        auto lucky = lucky_node in quorums;
        assert(lucky !is null);

        // update threshold for the new majority
        const majority = max(1, cast(size_t)floor(0.67 * (1 + lucky.nodes.length)));
        lucky.threshold = majority;
    }
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

        assert(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check before normalization: %s",
                    key.nice, quorum.toToml, reason.to!string));

        normalizeQSet(scp_quorum);
        assert(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check after normalization: %s",
                    key.nice, quorum.toToml, reason.to!string));
    }
}

/*******************************************************************************

    Verify that all the quorums intersect according to the quorum checker tool

    Params:
        quorums = the quorums to check

    Throws:
        AssertError if the quorum is not considered sane by SCP.

*******************************************************************************/

private void verifyQuorumsIntersect (QuorumConfig[PublicKey] quorums)
{
    auto qm = QuorumTracker.QuorumMap.create();

    foreach (key, quorum; quorums)
    {
        auto scp = toSCPQuorumSet(quorum);
        auto scp_quorum = makeSharedSCPQuorumSet(scp);

        auto hash = StellarHash(key);
        auto scp_key = NodeID(hash);

        qm[scp_key] = scp_quorum;
    }

    auto qic = QuorumIntersectionChecker.create(qm);
    assert(qic.networkEnjoysQuorumIntersection());

    auto splits = qic.getPotentialSplit();

    if (splits.first.length != 0 ||
        splits.second.length != 0)
    {
        writefln("Splits: first: %s second: %s",
            splits.first[].map!(node_id => PublicKey(node_id).prettify),
            splits.second[].map!(node_id => PublicKey(node_id).prettify));

        //CircularAppender().printConsole();
        assert(0);  // should not happen
    }
}

/*******************************************************************************

    Create a random number generator which uses the hash of the random seed
    and a node's public key as an initializer for the engine.

    Params
        node_key = the public key of a node
        rand_seed = the source of randomness

    Returns:
        a Mersenne Twister 64bit random generator

*******************************************************************************/

private auto getGenerator (PublicKey node_key, Hash rand_seed)
{
    /// very simplistic way of reducing a 64-byte blob to an 8-byte seed
    static ulong toSeed (Hash hash)
    {
        return (cast(ulong[])hash[]).reduce!((a, b) => a ^ b);
    }

    Mt19937_64 gen;
    gen.seed(toSeed(hashMulti(node_key, rand_seed)));
    return gen;
}

/// The pair of (key, stake) for each node
private struct NodeStake
{
    /// the node key
    private PublicKey key;

    /// the staken amount
    private Amount amount;
}

/*******************************************************************************

    For each enrollment find the staked amount from the associated UTXO
    in the Enrollment, and build a key => amount map.

    Params
        enrolls = the list of enrollments
        finder = UTXO finder delegate

    Returns:
        a mapping of all keys => staken amount

*******************************************************************************/

private Amount[PublicKey] buildStakes (Enrollment[] enrolls, UTXOFinder finder)
{
    Amount[PublicKey] stakes;
    foreach (enroll; enrolls)
    {
        UTXOSetValue value;
        assert(finder(enroll.utxo_key, size_t.max, value),
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

/*******************************************************************************

    Generates a .toml syntax file that can be used with the go-scp
    tool in https://github.com/bobg/scp/blob/master/cmd/lunch/lunch.go
    for easy testing.

    Format example:

        [alice]
        Q = {t = 2, m = [{n = "bob"}, {n = "carol"}]}

        [bob]
        Q = {t = 2, m = [{n = "alice"}, {n = "carol"}]}

        [carol]
        Q = {t = 2, m = [{n = "alice"}, {n = "bob"}]}

    Or nested:

        [alice]
        Q = {t = 1, m = [{q = {t = 2, m = [{n = "bob"}, {n = "carol"}]}},
                         {q = {t = 2, m = [{n = "dave"}, {n = "elsie"}]}}]}

    Params:
        quorums = the quorum set
        level = indentation level

*******************************************************************************/

private string toToml (QuorumConfig[PublicKey] quorums)
{
    return quorums.byKeyValue.map!(pair =>
        format("[%s]\n%s", pair.key.nice, toToml(pair.value)))
            .join("\n\n");
}

/// ditto
private string toToml (QuorumConfig config, size_t level = 0)
{
    string result;

    result ~= format("%s = {t = %s, m = [",
        level == 0 ? "Q" : "q",
        config.threshold);

    // nodes
    auto nodes = config.nodes
        .map!(qnode => format(`{n = "%s"}`, qnode.nice))
        .join(", ");

    result ~= nodes.to!string;

    // subquorums (recursive)
    if (config.quorums.length > 0)
    {
        result ~= ", ";
        auto subq = config.quorums
            .map!(qsub => format("{ %s}", toToml(qsub, level + 1)))
            .join(", ");

        result ~= subq.to!string;
    }

    result ~= "]}";
    return result;
}

/// Nicer formatting for [sets of] public keys
private auto nice (Set!PublicKey input)
{
    return input._set.byKey.map!(key => key.nice);
}

/// ditto
private string nice (PublicKey input)
{
    // convert arbitrary hashes into user-readable strings like "Andrew, Dave, etc"
    static string toUserReadable (Hash hash)
    {
        const names =
        [
            "Aaron",
            "Adam",
            "Alex",
            "Andrew",
            "Anthony",
            "Austin",
            "Ben",
            "Brandon",
            "Brian",
            "Charles",
            "Chris",
            "Daniel",
            "David",
            "Edward",
            "Eric",
            "Ethan",
            "Fred",
            "George",
            "Iain",
            "Jack",
            "Jacob",
            "James",
            "Jason",
            "Jeremy",
            "John",
            "Jonathan",
            "Joseph",
            "Josh",
            "Justin",
            "Kevin",
            "Kyle",
            "Luke",
            "Mark",
            "Martin",
            "Mathew",
            "Matthew",
            "Michael",
            "Nathan",
            "Nicholas",
            "Nick",
            "Patrick",
            "Paul",
            "Peter",
            "Philip",
            "Richard",
            "Robert",
            "Ryan",
            "Samuel",
            "Scott",
            "Sean",
            "Simon",
            "Stephen",
            "Steven",
            "Thomas",
            "Timothy",
            "Tyler",
            "William",
            "Zach",
        ];

        static size_t last_used;
        static string[Hash] hashToName;

        if (auto name = hash in hashToName)
        {
            return *name;
        }
        else
        {
            string name = names[last_used];
            last_used++;

            if (last_used >= names.length)
                assert(0);  // add more names plz

            hashToName[hash] = name;
            return name;
        }
    }

    return toUserReadable(input[].hashFull());
}

/// Generate a tuple pair of (Enrollment[], UTXOFinder)
version (unittest)
private auto genEnrollments (size_t enroll_count)
{
    import agora.common.Amount;
    import agora.consensus.data.Transaction;
    import agora.consensus.Genesis;

    TestUTXOSet storage = new TestUTXOSet;
    Enrollment[] enrolls;

    foreach (idx; 0 .. enroll_count)
    {
        // increasing amount of values, for the test
        Amount amount = Amount.MinFreezeAmount;
        foreach (i; 0 .. idx + 1)
            amount.add(Amount.MinFreezeAmount);

        Transaction tx =
        {
            type : TxType.Freeze,
            outputs: [Output(amount, KeyPair.random().address)]
        };

        storage.put(tx);
    }

    foreach (utxo; storage.keys)
    {
        Enrollment enroll =
        {
            utxo_key : utxo,
            cycle_length : 1008
        };

        enrolls ~= enroll;
    }

    return tuple(enrolls, &storage.findUTXO);
}
