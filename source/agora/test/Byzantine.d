/*******************************************************************************

    Contains Byzantine node tests, which refuse to co-operate in the
    SCP consensus protocol in various ways.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Byzantine;

version (unittest):

import agora.api.Validator;
import agora.common.Config;
import agora.common.Task;
import agora.common.crypto.Key;
import agora.consensus.Genesis;
import agora.consensus.data.Transaction;
import agora.consensus.protocol.Nominator;
import agora.network.NetworkClient;
import agora.node.Ledger;
import agora.test.Base;

import scpd.types.Stellar_SCP;

import geod24.LocalRest;
import geod24.Registry;

import std.algorithm;
import std.datetime;
import std.exception;
import std.format;
import std.range;
import std.stdio;
import core.exception;

/// node which refuses to co-operate: doesn't sign / forges the signature / etc
public extern (C++) class ByzantineNominator : Nominator
{
    extern(D) this (KeyPair key_pair, Ledger ledger,
        TaskManager taskman, NetworkClient[PublicKey] peers,
        SCPQuorumSet quorum_set)
    {
        super(key_pair, ledger, taskman, peers, quorum_set);
    }

    // refuse to sign
    extern(C++) override void signEnvelope (ref SCPEnvelope envelope)
    {
    }
}

class BynzantineNode : TestNode
{
    this (Config config, Registry* reg)
    {
        super(config, reg);
    }

    override Nominator getNominator (KeyPair key_pair, Ledger ledger,
        TaskManager taskman, NetworkClient[PublicKey] quorum_peers,
        SCPQuorumSet quorum_set)
    {
        return new ByzantineNominator(key_pair, ledger, taskman,
            quorum_peers, quorum_set);
    }
}

class ByzantineManager : TestAPIManager
{
    RemoteAPI!TestAPI[] nodes;

    override void createNewNode (PublicKey address, Config conf)
    {
        RemoteAPI!TestAPI api;
        if (this.nodes.length == 0)  // first node is byzantine
            api = RemoteAPI!TestAPI.spawn!(BynzantineNode)(conf, &this.reg);
        else
            api = RemoteAPI!TestAPI.spawn!(TestNode)(conf, &this.reg);

        this.reg.register(address.toString(), api.tid());
        this.apis[address] = api;
        this.nodes ~= api;
    }
}

/// 3/4 threshold with 1 byzantine => ok
unittest
{
    TestConf conf = { nodes : 4, threshold : 3 };
    auto network = makeTestNetwork!ByzantineManager(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.nodes;
    auto node_1 = nodes[$ - 1];

    auto txes = makeChainedTransactions(getGenesisKeyPair(), null, 1);
    txes.each!(tx => node_1.putTransaction(tx));

    nodes.enumerate.each!((idx, node) =>
        retryFor(node.getBlockHeight() == 1,
            4.seconds,
            format("Node %s has block height %s. Expected: %s",
                idx, node.getBlockHeight(), 1)));
}

/// 4/4 threshold with 1 byzantine => fail
unittest
{
    TestConf conf = { nodes : 4, threshold : 4 };
    auto network = makeTestNetwork!ByzantineManager(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.nodes;
    auto node_1 = nodes[$ - 1];

    auto txes = makeChainedTransactions(getGenesisKeyPair(), null, 1);
    txes.each!(tx => node_1.putTransaction(tx));

    assertThrown!AssertError(
        nodes.enumerate.each!((idx, node) =>
            retryFor(node.getBlockHeight() == 1,
                4.seconds,
                format("Node %s has block height %s. Expected: %s",
                    idx, node.getBlockHeight(), 1))));
}
