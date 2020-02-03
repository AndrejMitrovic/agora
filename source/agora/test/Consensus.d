/*******************************************************************************

    Contains consensus tests for various types of quorum configurations.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Consensus;

version (unittest):

import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXOSet;
import agora.consensus.Genesis;
import agora.test.Base;

///
unittest
{
    import std.algorithm;
    import std.conv;
    import std.format;
    import std.range;
    import core.time;

    const NodeCount = 3;
    auto network = makeTestNetwork(NetworkTopology.Simple, NodeCount);
    network.start();
    scope(exit) network.shutdown();
    //scope(failure) network.printLogs();
    assert(network.getDiscoveredNodes().length == NodeCount);

    auto nodes = network.apis.values;
    auto node_1 = nodes[0];

    // create enough tx's for a single block
    auto txs = makeChainedTransactions(getGenesisKeyPair(), null, 1);

    // send it to one node
    txs.each!(tx => node_1.putTransaction(tx));

    nodes.enumerate.each!((idx, node) =>
        retryFor(node.getBlockHeight() == 1,
            4.seconds,
            format("Node %s has block height %s. Expected: 1",
                idx, node.getBlockHeight().to!string)));
}
