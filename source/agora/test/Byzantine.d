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

import agora.api.Validator;
import agora.common.Config;
import agora.common.Task;
import agora.common.Types;
import agora.common.crypto.Key;
import agora.consensus.data.Block;
import agora.consensus.data.ConsensusParams;
import agora.consensus.data.Transaction;
import agora.consensus.protocol.Nominator;
import agora.network.Clock;
import agora.network.NetworkClient;
import agora.network.NetworkManager;
import agora.node.Ledger;
import agora.test.Base;

import scpd.types.Stellar_SCP;

import geod24.Registry;

import std.algorithm;
import std.exception;
import std.format;
import std.range;
import std.stdio;

import core.exception;
import core.stdc.time;

/// node which refuses to co-operate: doesn't sign / forges the signature / etc
class ByzantineNode : TestValidatorNode
{
    public this (Config config, Registry* reg, immutable(Block)[] blocks,
        ulong txs_to_nominate, shared(time_t)* cur_time)
    {
        super(config, reg, blocks, txs_to_nominate, cur_time);
    }

    protected override TestNominator getNominator (immutable(ConsensusParams) params,
        Clock clock, NetworkManager network, KeyPair key_pair, Ledger ledger,
        TaskManager taskman)
    {
        return new class TestNominator
        {
            public this ()
            {
                super(params, clock, network, key_pair, ledger,
                    taskman, this.txs_to_nominate);
            }
        };
    }
}

/// creates `bad_count` nodes which will refuse to sign
class ByzantineManager (size_t bad_count) : TestAPIManager
{
    ///
    public this (immutable(Block)[] blocks, TestConf test_conf,
        time_t genesis_start_time)
    {
        super(blocks, test_conf, genesis_start_time);
    }

    public override void createNewNode (Config conf,
        string file = __FILE__, int line = __LINE__)
    {
        if (this.nodes.length < bad_count)
        {
            auto time = new shared(time_t)(this.initial_time);
            assert(conf.node.is_validator);
            auto node = RemoteAPI!TestAPI.spawn!ByzantineNode(
                conf, &this.reg, this.blocks, this.test_conf.txs_to_nominate,
                time, conf.node.timeout);
            this.reg.register(conf.node.address, node.ctrl.tid());
            this.nodes ~= NodePair(conf.node.address, node, time);
        }
        else
            super.createNewNode(conf, file, line);
    }
}

///
unittest
{
    TestConf conf = { validators : 4, quorum_threshold : 66 };
    auto network = makeTestNetwork!(ByzantineManager!1)(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();
    auto nodes = network.clients;
    auto node_1 = nodes[$ - 1];
    auto txes = genesisSpendable().map!(txb => txb.sign()).array();
    txes.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(1), 5.seconds);
}

///
unittest
{
    TestConf conf = { validators : 4, quorum_threshold : 66 };
    auto network = makeTestNetwork!(ByzantineManager!2)(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();
    auto nodes = network.clients;
    auto node_1 = nodes[$ - 1];
    auto txes = genesisSpendable().map!(txb => txb.sign()).array();
    txes.each!(tx => node_1.putTransaction(tx));
    assertThrown!AssertError(network.expectBlock(Height(1), 5.seconds));
}
