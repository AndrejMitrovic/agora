/*******************************************************************************

    Contains flash layer tests.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Flash;

version (unittest):

import agora.api.Validator;
import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.test.Base;

import geod24.Registry;

import std.conv;
import std.format;

import std.exception;

import core.thread;

// todo: there needs to be an invoice-based API like in c-lightning
// something like: `cli invoice <amount> <label>` which produces <UUID>
// and then `cli pay <UUID>`
// todo: a channel should be a struct. maybe it should have an ID like a Hash.

// todo: call each node a "peer" for better terminology.

// todo: for intermediary HTLC nodes we would call them "hops", or a "hop".

// todo: we might not need HTLC's if we use channel factories
// todo: we also might not need HTLC's if we can use multi-cosigners for the
// funding transaction

// todo: encryption

// todo: extensibility (and therefore backwards compatibility) of the protocol
// lightning uses "TLV stream"

// channel IDs are temporary (ephemeral) until the funding transaction is
// externalized. Then, we can easily derive a unique channel ID using the hash
// of the funding transaction.

// todo: base many things on https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md

// benefit to list in the demo: we don't have to wait for many confirmations
// before using a channel, but only 10 minutes until the first block is
// externalized.
// however: with channel factories we'll be able to reduce this to zero wait
// time. we should at least make a note of that.

// todo: use the hash of the genesis block as the chain_hash like in LN.

/// This is the API that each flash-aware node must implement.
public interface FlashAPI
{
    /// Called when another party wants to open a channel with us.
    /// If we agree with the terms, we return null and wait for the
    /// user to initiate the next steps. Alternatively we return a string
    /// reason if we don't agree with the terms.
    public string openChannelRequest (in Amount amount, in uint settle_time,
        in Point creator);
}

/// Contains a key and a signature using that key to proove ownership of this key
public struct KeyProof
{
    public Point key;
    public Signature signature;
}

/// In addition to the Flash API, we provide controller methods to initiate
/// the channel creation procedures, and control each flash node's behavior.
public interface TestFlashAPI : FlashAPI
{
    public void wait ();

    /***************************************************************************

        Open a channel with another flash node.

        Params:
            utxo = the UTXO that will be used to fund the channel
                   Note: in reality wallets may use any number of UTXOs for the
                   inputs of the funding transaction.
            funding_amount = the total funding amount. May not exceed the UTXO's
                output value. If less than the UTXO's total amount then the rest
                is just discarded (becomes the fee).
            settle_time = the number of blocks during which an
                update / settlement transaction can be emitted,
                after the trigger transaction is initially externalized
            node_key = the key of the other flash node.
                Note: since funds can move both ways in this channel, the
                destination is actually two-way.

    ***************************************************************************/

    public string ctrlOpenChannel (in Hash utxo, in Amount funding_amount,
        in uint settle_time, in Point node_key);

    /***************************************************************************

        Exchange the update public keys.

        The caller provides their update key and the signature. The challenge
        for the signature is the public key.

        If the signature is valid, we create our own signature, signing our
        update public key, and returning this update key and the signature

        Params:
            point = the caller's public key
            signature = signature which signed the public key with the
                associated private key

        Returns:
            a key proof consisting of the node's own update key an the signature
            which signed this update key as its challenge

    ***************************************************************************/

    public KeyProof exchangeUpdateKeys (in Point point, in Signature signature);
}

/// Could be a payer, or a merchant. funds can go either way in the channel.
/// There may be any number of channels between two parties
/// (e.g. think multiple different micropayment services)
/// In this test we assume there may only be one payment channel between two parties.
public class User : TestFlashAPI
{
    /// Schnorr key-pair belonging to this user
    const Pair kp;
    Registry* registry;

    /// Ctor
    public this (const Pair kp, Registry* registry)
    {
        this.kp = kp;
        this.registry = registry;
    }

    /// Control API
    public override void wait ()
    {
        writefln("%s: spawned & waiting..", this.kp.V.prettify);
    }

    /// Control API
    public override string ctrlOpenChannel (in Hash utxo,
        in Amount funding_amount, in uint settle_time, in Point node_key)
    {
        writefln("%s: ctrlOpenChannel(%s, %s, %s)", this.kp.V.prettify,
            funding_amount, settle_time, node_key.prettify);

        auto tid = this.registry.locate(node_key.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");

        Duration timeout;
        auto node = new RemoteAPI!TestFlashAPI(tid, timeout);

        // check if the node is willing to open a channel with us
        if (auto error = node.openChannelRequest(
            funding_amount, settle_time, this.kp.V))
            return error;

        const Pair update_kp = Pair.random();
        const Signature sig = sign(update_kp, update_kp.V);

        auto proof = node.exchangeUpdateKeys(update_kp.V, sig);
        if (!verify(proof.key, proof.signature, challenge))
            return format("Node %s has provided invalid signature " ~
                "for update key-pair challenge", node_key.prettify);

        // now exchange update key-pairs

        //auto funding = this.createFundingTx();

        return null;
    }

    public override KeyProof exchangeUpdateKeys (in Point point,
        in Signature signature)
    {

    }

    /// Flash API
    public override string openChannelRequest (
        in Amount amount, in uint settle_time, in Point creator)
    {
        writefln("%s: openChannelRequest(%s, %s, %s)", this.kp.V.prettify,
            amount, settle_time, creator.prettify);
        return null;
    }

    /// Utility
    private Transaction createFundingTx (in UTXO utxo, in Amount funding_amount,
        Point update_key)
    {
        Transaction funding_tx = {
            type: TxType.Payment,
            inputs: [Input(utxo)],
            outputs: [
                Output(funding_amount,
                    Lock(LockType.Key, update_key[].dup))]
        };

        return funding_tx;
    }
}

/// Is in charge of spawning the flash nodes
public class UserFactory
{
    /// we keep a separate LocalRest registry of the flash "nodes"
    private Registry registry;

    /// list of flash addresses
    private Point[] addresses;

    /// list of flash nodes
    private RemoteAPI!TestFlashAPI[] nodes;

    /// Ctor
    public this ()
    {
        this.registry.initialize();
    }

    /// Create a new flash node user
    public RemoteAPI!TestFlashAPI create (const Pair pair)
    {
        RemoteAPI!TestFlashAPI api = RemoteAPI!TestFlashAPI.spawn!User(pair,
            &this.registry);
        api.wait();  // wait for the ctor to finish

        this.addresses ~= pair.V;
        this.nodes ~= api;
        this.registry.register(pair.V.to!string, api.tid());

        return api;
    }

    /// Shut down all the nodes
    public void shutdown ()
    {
        foreach (address; this.addresses)
            enforce(this.registry.unregister(address.to!string));

        foreach (node; this.nodes)
            node.ctrl.shutdown();
    }
}

private string prettify (T)(T input)
{
    return input.to!string[0 .. 6];
}

/// Ditto
unittest
{
    TestConf conf = TestConf.init;
    auto network = makeTestNetwork(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(1));

    auto factory = new UserFactory();
    scope (exit) factory.shutdown();

    // use Schnorr
    const alice_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys.A.secret));
    const bob_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys.B.secret));

    // two users
    auto alice = factory.create(alice_pair);
    auto bob = factory.create(bob_pair);

    // 10 blocks settle time after / when trigger tx is published
    const Settle_10_Blocks = 10;

    // alice opens a new bi-directional channel with bob
    const alice_utxo = UTXO.getHash(hashFull(txs[0]), 0);
    alice.ctrlOpenChannel(alice_utxo, Amount(10_000), Settle_10_Blocks,
        bob_pair.V);

    // todo: use LocalRest to spawn "Flash" nodes.

    Thread.sleep(1.seconds);
}
