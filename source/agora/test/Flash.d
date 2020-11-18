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
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.flash.tests.OffChainEltoo;
import agora.script.Engine;
import agora.script.Lock;
import agora.test.Base;

import geod24.Registry;

import libsodium.randombytes;

import std.conv;
import std.exception;
import std.format;

import core.thread;

alias LockType = agora.script.Lock.LockType;

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

// todo: need to guard against replay attacks.

///
private struct PendingChannel
{
    Hash gen_hash;
    Hash temp_chan_id;

    Point funder_pk;
    Point peer_pk;

    Hash utxo;
    Amount funding_amount;
    uint settle_time;

    Pair our_update_kp;
    Point their_update_pk;

    Pair our_settle_origin_kp;
    Point their_settle_origin_pk;
}

///
private struct PendingSettlement
{
    Hash chan_id;
    uint seq_id;
    Pair our_nonce_kp;
    Point their_nonce_pk;
    Transaction prev_tx;
    Output[] outputs;
}

/// This is the API that each flash-aware node must implement.
public interface FlashAPI
{
    /***************************************************************************

        Requests opening a channel with this node.

        Params:
            gen_hash = The hash of the genesis block. Since the node may
                be a testnet / livenet / othernet node we need to know if we're
                following the same blockchain before establishing a channel
                with the funder node.
            temp_chan_id = A randomly generated temporary and unique channel ID.
                It only has to be unique per-peer, in this case per funding key.
                Once the channel is accepted and a funding transaction is
                created, a new channel ID derived from the funding transaction
                hash will be created and used in place of the temporary ID.
            funder_pk = the public key of the funding transaction
            funding_amount = the total funding amount. May not exceed the UTXO's
                output value. If less than the UTXO's total amount then the rest
                is just discarded (becomes the fee).
            settle_time = how many blocks the node has to publish the latest
                state after a trigger transaction has been published &
                externalized in the blockchain
            funder_update_pk = the channel funder update public key.
                This update pk will be combined with our own generated pk
                to generate the schnorr sum pk that will be used for 2/2
                Schnorr signatures.
                TODO: Provide proof that funder owns this key.
            funder_settle_origin_pk = the channel funder settlement origin
                public key. All further settlement keys will be derived
                from this origin based on the sequence ID of the transaction.
                TODO: Provide proof that funder owns this key.

    ***************************************************************************/

    public string openChannel (in Hash gen_hash, in Hash temp_chan_id,
        in Point funder_pk, in Amount funding_amount, in uint settle_time,
        in Point funder_update_pk, in Point funder_settle_origin_pk);

    /***************************************************************************

        Accepts opening a channel for the given temporary channel ID which
        was previously proposed by the funder node with a call to `openChannel()`.

        If the given pending channel ID does not exist,
        an error string is returned.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            accepter_update_pk = the update public key of the accepter of the
                initial receiving end of the channel
            accepter_settle_origin_pk = the settlement origin public key of the
                accepter of the initial receiving end of the channel

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string acceptChannel (in Hash temp_chan_id,
        in Point accepter_update_pk, in Point accepter_settle_origin_pk);

    /***************************************************************************

        Request the peer to create a floating settlement transaction that spends
        the outputs of the provided previous transaction, and creates the given
        new outputs and encodes the given signed sequence ID in the
        unlock script.

        The peer may reject to create such a settlement, for example if the
        sequence ID is outdated, or if the peer disagrees with the allocation
        of the funds in the new outputs, or if the outputs try to spend more
        than the allocated amount.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            prev_tx = the transaction whose outputs should be spent
            outputs = the outputs reallocating the funds
            seq_id = the sequence ID

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string requestSettlementSig (in Hash temp_chan_id,
        in Transaction prev_tx, in Output[] outputs, in uint seq_id,
        in Point peer_nonce_pk);

    /***************************************************************************

        Provide a settlement transaction that was requested by another peer
        through the `requestSettlementSig()`.

        Note that the settlement transaction itself is not sent back,
        because the requester already knows what the settlement transaction
        should look like. Only the signature should be sent back.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            seq_id = the sequence ID
            peer_nonce_pk = the nonce the other peer is using
            sig = the partial signature that needs to be complimented by
                the second half of the settlement requester

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string receiveSettlementSig (in Hash temp_chan_id, in uint seq_id,
        in Point peer_nonce_pk, in Signature sig);
}

/// In addition to the Flash API, we provide controller methods to initiate
/// the channel creation procedures, and control each flash node's behavior.
public interface TestFlashAPI : FlashAPI
{
    /// Used for waiting until node finished booting up.
    public void wait ();

    /// Open a channel with another flash node.
    public string ctrlOpenChannel (in Hash utxo, in Amount funding_amount,
        in uint settle_time, in Point peer_pk);
}

///
private Hash randomHash ()
{
    Hash rand_hash;
    randombytes_buf(&rand_hash, Hash.sizeof);
    return rand_hash;
}

///
private class SchedulingTaskManager : LocalRestTaskManager
{
    ///
    public void schedule (void delegate() dg) nothrow
    {
        super.setTimer(0.seconds, dg);
    }
}

/// Could be a payer, or a merchant. funds can go either way in the channel.
/// There may be any number of channels between two parties
/// (e.g. think multiple different micropayment services)
/// In this test we assume there may only be one payment channel between two parties.
public class User : TestFlashAPI
{
    /// Schnorr key-pair belonging to this user
    private const Pair kp;
    private Registry* registry;
    private SchedulingTaskManager taskman;  // for scheduling

    /// Channels which are pending and not accepted yet.
    /// Once the channel handshake is complete and only after the funding
    /// transaction is externalized, the PendingChannel channel gets promoted
    /// to a Channel with a unique ID derived from the hash of the funding tx.
    private PendingChannel[Hash] pending_channels;

    private PendingSettlement[Hash] pending_settlements;

    /// Ctor
    public this (const Pair kp, Registry* registry)
    {
        this.kp = kp;
        this.registry = registry;
        this.taskman = new SchedulingTaskManager();
    }

    /// Control API
    public override void wait ()
    {
        //writefln("%s: spawned & waiting..", this.kp.V.prettify);
    }

    /// Control API
    public override string ctrlOpenChannel (in Hash utxo,
        in Amount funding_amount, in uint settle_time, in Point peer_pk)
    {
        writefln("%s: ctrlOpenChannel(%s, %s, %s)", this.kp.V.prettify,
            funding_amount, settle_time, peer_pk.prettify);

        auto peer = this.getClient(peer_pk);
        const gen_hash = hashFull(GenesisBlock);
        const Hash temp_chan_id = randomHash();

        Pair our_update_kp = Pair.random();
        Pair our_settle_origin_kp = Pair.random();

        auto pending = PendingChannel(gen_hash, temp_chan_id, this.kp.V,
            peer_pk, utxo, funding_amount, settle_time, our_update_kp,
            Point.init,  // set later when we receive it from counter-party
            our_settle_origin_kp,
            Point.init); // ditto

        // add it to the pending before the openChannel() request is even
        // issued to avoid data races
        this.pending_channels[temp_chan_id] = pending;

        // check if the node is willing to open a channel with us
        if (auto error = peer.openChannel(
            gen_hash, temp_chan_id, this.kp.V, funding_amount, settle_time,
            our_update_kp.V, our_settle_origin_kp.V))
        {
            this.pending_channels.remove(temp_chan_id);
            return error;
        }

        //const Pair update_kp = Pair.random();
        //const Signature sig = sign(update_kp, update_kp.V);

        //auto proof = node.exchangeUpdateKeys(update_kp.V, sig);
        //if (!verify(proof.key, proof.signature, challenge))
        //    return format("Node %s has provided invalid signature " ~
        //        "for update key-pair challenge", peer_pk.prettify);

        // now exchange update key-pairs

        //auto funding = this.createFundingTx();

        return null;
    }

    //public override KeyProof exchangeUpdateKeys (in Point point,
    //    in Signature signature)
    //{

    //}


    /// Flash API
    public override string openChannel (in Hash gen_hash,
        in Hash temp_chan_id, in Point funder_pk, in Amount funding_amount,
        in uint settle_time, in Point funder_update_pk,
        in Point funder_settle_origin_pk)
    {
        writefln("%s: openChannel()", this.kp.V.prettify);

        // todo: need replay attack protection. adversary could feed us
        // a dupe temporary channel ID once it's removed from
        // `this.pending_channels`
        if (temp_chan_id in this.pending_channels)
            return "Pending channel with the given ID already exists";

        auto peer = this.getClient(funder_pk);

        const our_gen_hash = hashFull(GenesisBlock);
        if (gen_hash != our_gen_hash)
            return "Unrecognized blockchain genesis hash";

        const min_funding = Amount(1000);
        if (funding_amount < min_funding)
            return "Funding amount is too low";

        const min_settle_time = 5;
        const max_settle_time = 10;
        if (settle_time < min_settle_time || settle_time > max_settle_time)
            return "Settle time is not within acceptable limits";

        /* todo: verify proof that funder owns `funder_update_pk` */

        // todo: find an appropriate UTXO to fund the channel with
        Hash utxo;

        Pair our_update_kp = Pair.random();
        Pair our_settle_origin_kp = Pair.random();
        auto pending = PendingChannel(gen_hash, temp_chan_id, funder_pk,
            this.kp.V, utxo, funding_amount, settle_time, our_update_kp,
            funder_update_pk, our_settle_origin_kp, funder_settle_origin_pk);

        this.pending_channels[temp_chan_id] = pending;

        this.taskman.schedule({
            peer.acceptChannel(temp_chan_id, our_update_kp.V,
                our_settle_origin_kp.V);
        });

        return null;
    }

    /// Flash API
    public override string acceptChannel (in Hash temp_chan_id,
        in Point their_update_pk, in Point their_settle_origin_pk)
    {
        writefln("%s: acceptChannel(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto pending = temp_chan_id in this.pending_channels;
        if (pending is null)
            return "PendingChannel channel ID not found";

        /* todo: verify proof that other party owns `their_update_pk` */
        /* todo: verify `their_update_pk` is not ours (edge-case) */

        pending.their_update_pk = their_update_pk;
        pending.their_settle_origin_pk = their_settle_origin_pk;
        this.prepareChannel(*pending);
        return null;
    }

    /// prepare everything
    private void prepareChannel (ref PendingChannel pending)
    {
        auto peer = this.getClient(pending.peer_pk);

        const Point update_pair_pk = pending.our_update_kp.V
            + pending.their_update_pk;

        // create funding, don't sign and don't share yet
        const funding_tx = this.createFundingTx(update_pair_pk, pending.utxo,
            pending.funding_amount);
        //pending.funding_tx = funding_tx;

        const Point settle_origin_pair_pk = pending.our_settle_origin_kp.V
            + pending.their_settle_origin_pk;

        // create trigger, don't sign yet but do share it
        auto trigger_tx = this.createTriggerTx(update_pair_pk, funding_tx,
            pending.funding_amount, pending.settle_time, settle_origin_pair_pk);
        //pending.trigger_tx = trigger_tx;

        // initial output allocates all the funds back to the channel creator
        Output output = Output(pending.funding_amount,
            PublicKey(pending.funder_pk[]));
        Output[] initial_outputs = [output];

        // first nonce for the settlement
        const nonce_kp = Pair.random();
        const seq_id_1 = 1;

        this.pending_settlements[pending.temp_chan_id] = PendingSettlement(
            pending.temp_chan_id, seq_id_1, nonce_kp,
            Point.init, // set later when we receive it from counter-party
            trigger_tx,
            initial_outputs);

        // request the peer to create a signed settlement transaction spending
        // from the trigger tx.
        this.taskman.schedule(
        {
            if (auto error = peer.requestSettlementSig(pending.temp_chan_id,
                trigger_tx, initial_outputs, seq_id_1, nonce_kp.V))
            {
                // todo: retry?
                writefln("Requested settlement rejected: %s", error);
                this.pending_settlements.remove(pending.temp_chan_id);
            }
        });

        // share trigger with counter-party and wait for their signature
    }

    /// Flash API
    public override string requestSettlementSig (in Hash temp_chan_id,
        in Transaction prev_tx, in Output[] outputs, in uint seq_id,
        in Point peer_nonce_pk)
    {
        writefln("%s: requestSettlementSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto pending = temp_chan_id in this.pending_channels;
        if (pending is null)
            return "PendingChannel channel ID not found";

        // todo: since the sequence ID is pushed on the stack, we can allow
        // making it have sequence ID zero! fix the code in OffChainEltoo.d
        if (seq_id == 0)
            return "Settlement sequence ID cannot be 0";

        /* todo: verify sequence ID is not an older sequence ID */
        /* todo: verify prev_tx is not one of our own transactions */

        const our_nonce_kp = Pair.random();

        const settle_tx = this.createSettleTx(prev_tx, pending.settle_time,
            outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        const settle_pair_pk = pending.our_settle_origin_kp.V
            + pending.their_settle_origin_pk;

        const nonce_pair_pk = our_nonce_kp.V + peer_nonce_pk;

        const sig = sign(pending.our_settle_origin_kp.v,
            settle_pair_pk, nonce_pair_pk, our_nonce_kp.v, challenge_settle);

        auto peer = this.getClient(pending.funder_pk);

        this.taskman.schedule(
        {
            if (auto error = peer.receiveSettlementSig(temp_chan_id, seq_id,
                our_nonce_kp.V, sig))
            {
                // todo: retry?
                writefln("Peer rejected settlement tx: %s", error);
            }
        });

        return null;
    }

    public override string receiveSettlementSig (in Hash temp_chan_id,
        in uint seq_id, in Point peer_nonce_pk, in Signature peer_sig)
    {
        auto pending = temp_chan_id in this.pending_channels;
        if (pending is null)
            return "Pending channel with this ID not found";

        auto settle = temp_chan_id in this.pending_settlements;
        if (settle is null)
            return "Pending settlement with this channel ID not found";

        settle.their_nonce_pk = peer_nonce_pk;

        // recreate the settlement tx
        const settle_tx = this.createSettleTx(settle.prev_tx,
            pending.settle_time, settle.outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        // todo: send the signature back via receiveSettlementSig()
        // todo: add pending settlement to the other peer's pending settlements

        // Kim received the <settlement, signature> tuple.
        // he signs it, and finishes the multisig.
        Pair our_settle_origin_kp;
        Point their_settle_origin_pk;

        const settle_pair_pk = pending.our_settle_origin_kp.V
            + pending.their_settle_origin_pk;

        const nonce_pair_pk = settle.our_nonce_kp.V + settle.their_nonce_pk;

        const our_sig = sign(pending.our_settle_origin_kp.v,
            settle_pair_pk, nonce_pair_pk, settle.our_nonce_kp.v,
            challenge_settle);

        const settle_sig_pair = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        if (!verify(settle_pair_pk, settle_sig_pair, challenge_settle))
            return "Settlement signature is invalid";

        // now we can proceed

        return null;
    }

    ///
    private Transaction createSettleTx (in Transaction prev_tx,
        in uint settle_age, in Output[] outputs)
    {
        Transaction settle_tx = {
            type: TxType.Payment,
            inputs: [Input(prev_tx, 0 /* index */, settle_age)],
            outputs: outputs.dup,
        };

        return settle_tx;
    }

    ///
    private Transaction createFundingTx (in Point update_pair_pk, in Hash utxo,
        in Amount funding_amount)
    {
        Transaction funding_tx = {
            type: TxType.Payment,
            inputs: [Input(utxo)],
            outputs: [
                Output(funding_amount,
                    Lock(LockType.Key, update_pair_pk[].dup))]
        };

        return funding_tx;
    }

    ///
    private Transaction createTriggerTx (in Point update_pair_pk,
        in Transaction funding_tx, in Amount funding_amount,
        in uint settle_time, in Point settle_origin_pair_pk)
    {
        const seq_id_1 = uint(1);
        const FundingLockSeq_1 = createLockEltoo(settle_time,
            settle_origin_pair_pk, update_pair_pk, seq_id_1);

        Transaction trigger_tx = {
            type: TxType.Payment,
            inputs: [Input(funding_tx, 0 /* index */, 0 /* unlock age */)],
            outputs: [
                Output(funding_amount,
                    FundingLockSeq_1)]  // bind to next sequence (seq 1)
        };

        return trigger_tx;
    }

    private RemoteAPI!FlashAPI getClient (in Point peer_pk)
    {
        auto tid = this.registry.locate(peer_pk.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");
        Duration timeout;
        return new RemoteAPI!FlashAPI(tid, timeout);
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
    //scope(failure) network.printLogs();
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

    Thread.sleep(1.seconds);
}
