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
import agora.common.Serializer;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.script.Engine;
import agora.script.Lock;
import agora.script.Opcodes;
import agora.script.Script;
import agora.test.Base;

import geod24.Registry;

import libsodium.randombytes;

import std.bitmanip;
import std.conv;
import std.exception;
import std.format;

import core.thread;

alias LockType = agora.script.Lock.LockType;

// todo: add ability to renegotiate update TXs.
// but the trigger tx should be non-negotiable

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

// todo: we need a state transition here:
// we need to track the funding UTXO, and then when the following is true
// we know the channel is read:
// - we have a valid trigger tx
// - we have a valid settlement tx
// - the funding utxo was published to the blockchain

///
private struct Channel
{
    Hash gen_hash;
    Hash temp_chan_id;

    Point funder_pk;
    Point peer_pk;
    Point pair_pk;  // sum of the above

    Point update_pair_pk;  // the update pair for this channel

    Hash utxo;  // note: may be multiple UTXOs for funding,
                // but we use a single one for simplicity now
    Amount funding_amount;
    uint settle_time;

    Transaction funding_tx;  // stored by both parties, except the peer
                             // does not have the signature
    Hash funding_tx_hash;    // stored by both

    // need it in order to publish to begin closing the channel
    //Transaction trigger_tx;

    Trigger pending_trigger;
    Settlement pending_settlement;
    Update pending_update;

    // all of these must be set before channel is considered opened
    Trigger trigger;
    Settlement last_settlement;
    Update last_update;
    bool funding_externalized;
}

///
private struct Trigger
{
    Hash chan_id;
    Pair our_trigger_nonce_kp;
    Point their_trigger_nonce_pk;
    Transaction trigger_tx;
}

///
private struct Update
{
    Hash chan_id;
    uint seq_id;
    Pair our_update_nonce_kp;
    Point their_update_nonce_pk;
    Transaction update_tx;
}

///
private struct Settlement
{
    Hash chan_id;
    uint seq_id;
    Pair our_settle_nonce_kp;
    Point their_settle_nonce_pk;
    Transaction prev_tx;
    Output[] outputs;

    /// 1 of 2 signature that belongs to us. funder needs this so he can
    /// send it to the peer once the trigger tx is signed and validated.
    Signature our_sig;
}

// type-safe number of channel owners
public struct NumPeers
{
    ///
    public ulong value;

    ///
    public alias value this;
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

    public string openChannel (in Hash gen_hash, in Hash utxo,
        in Hash temp_chan_id, in Point funder_pk, in Amount funding_amount,
        in uint settle_time);

    /***************************************************************************

        Accepts opening a channel for the given temporary channel ID which
        was previously proposed by the funder node with a call to `openChannel()`.

        If the given pending channel ID does not exist,
        an error string is returned.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string acceptChannel (in Hash temp_chan_id);

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
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string requestSettlementSig (in Hash temp_chan_id,
        in Transaction prev_tx, Output[] outputs, in uint seq_id,
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
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            peer_sig = the partial signature that needs to be complimented by
                the second half of the settlement requester

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string receiveSettlementSig (in Hash temp_chan_id, in uint seq_id,
        in Point peer_nonce_pk, in Signature peer_sig);

    /***************************************************************************

        Request the peer to sign the trigger transaction, from which the
        settlement transaction spends.

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveTriggerSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveTriggerSig()`,
        making the symmetry complete.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            funding_tx = the non-signed funding transaction whose hash
                the peer will listen for in the blockchain to determine
                when the channel has opened

        Returns:
            null, or an error string if the peer could not sign the trigger
            transaction for whatever reason

    ***************************************************************************/

    public string requestTriggerSig (in Hash temp_chan_id,
        in Point peer_nonce_pk, Transaction trigger_tx,
        Transaction funding_tx);

    /***************************************************************************

        Return a signature for the trigger transaction for the previously
        requested one via requestTriggerSig().

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveTriggerSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveTriggerSig()`,
        making the symmetry complete.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            peer_sig = the signature of the calling peer

        Returns:
            null, or an error string if the peer could not accept this signature

    ***************************************************************************/

    public string receiveTriggerSig (in Hash temp_chan_id,
        in Point peer_nonce_pk, in Signature peer_sig);

    /***************************************************************************

        Request the peer to sign the trigger transaction, from which the
        settlement transaction spends.

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveTriggerSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveTriggerSig()`,
        making the symmetry complete.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the peer could not sign the trigger
            transaction for whatever reason

    ***************************************************************************/

    public string requestUpdateSig (in Hash chan_id, in uint seq_id,
        in Point peer_nonce_pk, Transaction trigger_tx);

    /***************************************************************************

        Return a signature for the trigger transaction for the previously
        requested one via requestTriggerSig().

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveTriggerSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveTriggerSig()`,
        making the symmetry complete.

        Params:
            temp_chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            peer_sig = the signature of the calling peer

        Returns:
            null, or an error string if the peer could not accept this signature

    ***************************************************************************/

    public string receiveUpdateSig (in Hash chan_id, in uint seq_id,
        in Point peer_nonce_pk, in Signature peer_sig);
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

    public void sendFlash (in Amount amount);

    /// used to signal back to the main thread to create more txs
    public bool readyToExternalize ();

    public bool channelOpen ();
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
    private RemoteAPI!TestAPI agora_node;  // random agora node
    private Registry* flash_registry;
    private SchedulingTaskManager taskman;  // for scheduling

    // for sending tx's to the network
    private TestAPIManager api_manager;

    /// Channels which are pending and not accepted yet.
    /// Once the channel handshake is complete and only after the funding
    /// transaction is externalized, the Channel channel gets promoted
    /// to a Channel with a unique ID derived from the hash of the funding tx.
    private Channel[Hash] pending_channels;

    /// channels which were promoted into open channels
    private Channel[Hash] open_channels;

    private bool ready_to_externalize;

    public override bool readyToExternalize ()
    {
        return this.ready_to_externalize;
    }

    public override bool channelOpen ()
    {
        return this.open_channels.length > 0;
    }

    /// Ctor
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        this.kp = kp;
        this.flash_registry = flash_registry;
        this.taskman = new SchedulingTaskManager();
        this.api_manager = api_manager;

        auto tid = agora_registry.locate(agora_address);
        assert(tid != typeof(tid).init, "Agora node not initialized");
        Duration timeout;
        this.agora_node = new RemoteAPI!TestAPI(tid, timeout);
    }

    /// listen for any funding transactions reaching the blockchain
    /// If we have the funding tx, and the signatures for the trigger and
    /// settlement transaction, it means the channel is open and may
    /// be promoted to a full channel.
    public void listenFundingEvent ()
    {
        // todo: we actually need a getUTXO API
        // we would probably have to contact Stoa,
        // for now we simulate it through getBlocksFrom(),
        // we could provide this in the TestAPI

        auto last_block = this.agora_node.getBlocksFrom(0, 1024)[$ - 1];

        Hash[] pending_chans_to_remove;
        foreach (hash, ref channel; this.pending_channels)
        {
            if (channel.funding_externalized
                && channel.last_settlement != Settlement.init
                && channel.trigger != Trigger.init)
            {
                writefln("%s: Channel open(%s)", this.kp.V.prettify,
                    hash.prettify);
                open_channels[channel.funding_tx_hash] = channel;
                pending_chans_to_remove ~= hash;
                continue;
            }

            if (!channel.funding_externalized)
            foreach (tx; last_block.txs)
            {
                if (tx.hashFull() == channel.funding_tx_hash)
                {
                    channel.funding_tx  // not strictly necessary
                        = tx.serializeFull.deserializeFull!Transaction;

                    channel.funding_externalized = true;
                    writefln("%s: Funding tx externalized(%s)",
                        this.kp.V.prettify, channel.funding_tx_hash.prettify);
                    break;
                }
            }
        }

        foreach (id; pending_chans_to_remove)
            this.pending_channels.remove(id);
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
        // todo: this should only be done once, but we can't call it
        // from the ctor because in LocalRest the ctor blabla etc etc
        this.taskman.setTimer(200.msecs, &this.listenFundingEvent, Periodic.Yes);

        writefln("%s: ctrlOpenChannel(%s, %s, %s)", this.kp.V.prettify,
            funding_amount, settle_time, peer_pk.prettify);

        auto peer = this.getFlashClient(peer_pk);
        const gen_hash = hashFull(GenesisBlock);
        const Hash temp_chan_id = randomHash();

        const pair_pk = this.kp.V + peer_pk;
        const num_peers = NumPeers(2);  // hardcoded for now
        const update_pair_pk = getUpdatePk(pair_pk, utxo, num_peers);

        auto channel = Channel(gen_hash, temp_chan_id, this.kp.V, peer_pk,
            pair_pk, update_pair_pk, utxo, funding_amount, settle_time);

        // add it to the pending before the openChannel() request is even
        // issued to avoid data races
        this.pending_channels[temp_chan_id] = channel;

        this.taskman.schedule({
            // check if the node is willing to open a channel with us
            if (auto error = peer.openChannel(
                gen_hash, utxo, temp_chan_id, this.kp.V, funding_amount,
                settle_time))
            {
                this.pending_channels.remove(temp_chan_id);
            }
        });

        // todo: we don't have a real error message here because this function
        // is non-blocking
        return null;
    }

    public void sendFlash (in Amount amount)
    {
        writefln("%s: sendFlash()", this.kp.V.prettify);

        //// todo: use actual channel IDs, or perhaps an invoice API
        auto channel = this.open_channels[this.open_channels.byKey.front];

        //auto update_tx = this.createUpdateTx(channel.update_pair_pk,
        //    channel.trigger_tx,
        //    channel.funding_amount, channel.settle_time,
        //    channel.settle_origin_pair_pk);

        //auto peer = this.getFlashClient(channel.peer_pk);

        //peer.requestSettlementSig (in Hash temp_chan_id,
        //    in Transaction prev_tx, Output[] outputs, in uint seq_id,
        //    in Point peer_nonce_pk)

        //this.taskman.schedule({
        //    if (auto error = peer.acceptChannel(temp_chan_id))
        //    {
        //        // todo: handle this
        //        writefln("Error after acceptChannel() call: %s", error);
        //    }
        //});
    }

    /// Flash API
    public override string openChannel (in Hash gen_hash,
        in Hash utxo, in Hash temp_chan_id, in Point funder_pk,
        in Amount funding_amount, in uint settle_time)
    {
        // todo: this should only be done once, but we can't call it
        // from the ctor because in LocalRest the ctor blabla etc etc
        this.taskman.setTimer(200.msecs, &this.listenFundingEvent, Periodic.Yes);

        writefln("%s: openChannel()", this.kp.V.prettify);

        // todo: need replay attack protection. adversary could feed us
        // a dupe temporary channel ID once it's removed from
        // `this.pending_channels`
        if (temp_chan_id in this.pending_channels)
            return "Pending channel with the given ID already exists";

        auto peer = this.getFlashClient(funder_pk);

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
        const pair_pk = this.kp.V + funder_pk;
        const num_peers = NumPeers(2);  // hardcoded for now
        const update_pair_pk = getUpdatePk(pair_pk, utxo, num_peers);

        auto channel = Channel(gen_hash, temp_chan_id, funder_pk, this.kp.V,
            pair_pk, update_pair_pk, utxo, funding_amount, settle_time);

        this.pending_channels[temp_chan_id] = channel;

        this.taskman.schedule({
            if (auto error = peer.acceptChannel(temp_chan_id))
            {
                // todo: handle this
                writefln("Error after acceptChannel() call: %s", error);
            }
        });

        return null;
    }

    /// Flash API
    public override string acceptChannel (in Hash temp_chan_id)
    {
        writefln("%s: acceptChannel(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Channel channel ID not found";

        this.prepareChannel(*channel);
        return null;
    }

    /// prepare everything for this channel
    private void prepareChannel (ref Channel channel)
    {
        auto peer = this.getFlashClient(channel.peer_pk);

        // create funding, we can sign it but we shouldn't share it yet
        auto funding_tx = this.createFundingTx(channel);

        channel.funding_tx = funding_tx;
        channel.funding_tx_hash = hashFull(funding_tx);

        // create trigger, don't sign yet but do share it
        const next_seq_id = 0;
        auto trigger_tx = this.createUpdateTx(channel, funding_tx, next_seq_id);

        // initial output allocates all the funds back to the channel creator
        Output output = Output(channel.funding_amount,
            PublicKey(channel.funder_pk[]));
        Output[] initial_outputs = [output];

        // first nonce for the settlement
        const nonce_kp = Pair.random();
        const seq_id_0 = 0;

        channel.pending_settlement = Settlement(
            channel.temp_chan_id, seq_id_0, nonce_kp,
            Point.init, // set later when we receive it from counter-party
            trigger_tx,
            initial_outputs);

        // request the peer to create a signed settlement transaction spending
        // from the trigger tx.
        this.taskman.schedule(
        {
            if (auto error = peer.requestSettlementSig(channel.temp_chan_id,
                trigger_tx, initial_outputs, seq_id_0, nonce_kp.V))
            {
                // todo: retry?
                writefln("Requested settlement rejected: %s", error);
                //this.pending_settlement.remove(channel.temp_chan_id);
            }
        });

        // share trigger with counter-party and wait for their signature
    }

    /// Flash API
    public override string requestSettlementSig (in Hash temp_chan_id,
        in Transaction prev_tx, Output[] outputs, in uint seq_id,
        in Point peer_nonce_pk)
    {
        // todo: should not accept this unless acceptsChannel() was called
        writefln("%s: requestSettlementSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Channel channel ID not found";

        /* todo: verify sequence ID is not an older sequence ID */
        /* todo: verify prev_tx is not one of our own transactions */

        const our_settle_nonce_kp = Pair.random();

        const settle_tx = this.createSettleTx(prev_tx, channel.settle_time,
            outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        const our_settle_scalar = getSettleScalar(this.kp.v, channel.utxo,
            seq_id);
        const num_peers = NumPeers(2);  // hardcoded for now
        const settle_pair_pk = getSettlePk(channel.pair_pk, channel.utxo,
            seq_id, num_peers);
        const nonce_pair_pk = our_settle_nonce_kp.V + peer_nonce_pk;

        const sig = sign(our_settle_scalar, settle_pair_pk, nonce_pair_pk,
            our_settle_nonce_kp.v, challenge_settle);

        channel.pending_settlement = Settlement(
            channel.temp_chan_id, seq_id, our_settle_nonce_kp,
            peer_nonce_pk,
            Transaction.init,  // trigger tx is revealed later
            outputs);

        auto peer = this.getFlashClient(channel.funder_pk);

        this.taskman.schedule(
        {
            if (auto error = peer.receiveSettlementSig(temp_chan_id, seq_id,
                our_settle_nonce_kp.V, sig))
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
        writefln("%s: receiveSettlementSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        // todo: should not accept this unless acceptsChannel() was called
        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Pending channel with this ID not found";

        auto settle = &channel.pending_settlement;
        settle.their_settle_nonce_pk = peer_nonce_pk;

        // recreate the settlement tx
        auto settle_tx = this.createSettleTx(settle.prev_tx,
            channel.settle_time, settle.outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        // todo: send the signature back via receiveSettlementSig()
        // todo: add pending settlement to the other peer's pending settlements

        // Kim received the <settlement, signature> tuple.
        // he signs it, and finishes the multisig.
        Pair our_settle_origin_kp;
        Point their_settle_origin_pk;

        const our_settle_scalar = getSettleScalar(this.kp.v, channel.utxo,
            seq_id);
        const num_peers = NumPeers(2);  // hardcoded for now
        const settle_pair_pk = getSettlePk(channel.pair_pk, channel.utxo,
            seq_id, num_peers);
        const nonce_pair_pk = settle.our_settle_nonce_kp.V
            + settle.their_settle_nonce_pk;

        const our_sig = sign(our_settle_scalar, settle_pair_pk, nonce_pair_pk,
            settle.our_settle_nonce_kp.v, challenge_settle);
        settle.our_sig = our_sig;

        const settle_sig_pair = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        if (!verify(settle_pair_pk, settle_sig_pair, challenge_settle))
            return "Settlement signature is invalid";

        writefln("%s: receiveSettlementSig(%s) VALIDATED for seq id %s",
            this.kp.V.prettify, temp_chan_id.prettify, seq_id);

        // unlock script set
        const Unlock settle_unlock = createUnlockSettle(settle_sig_pair, seq_id);
        settle_tx.inputs[0].unlock = settle_unlock;

        // note: this step may not look necessary but it can fail if there are
        // any incompatibilities with the script generators and the engine
        // (e.g. sequence ID being 4 bytes instead of 8)
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            settle.prev_tx.outputs[0].lock, settle_unlock, settle_tx,
                settle_tx.inputs[0]))
        {
            assert(0, error);
        }

        channel.last_settlement = *settle;

        // todo: protect against replay attacks. we do not want an infinite
        // loop scenario
        if (channel.funder_pk == this.kp.V)
        {
            if (seq_id == 0)
            {
                auto trigger_tx = settle.prev_tx;
                const our_trigger_nonce_kp = Pair.random();
                auto peer = this.getFlashClient(channel.peer_pk);

                channel.pending_trigger = Trigger(
                    channel.temp_chan_id,
                    our_trigger_nonce_kp,
                    Point.init,  // set later when we receive it from counter-party
                    trigger_tx);

                this.taskman.schedule({
                    if (auto error = peer.requestTriggerSig(channel.temp_chan_id,
                        our_trigger_nonce_kp.V, trigger_tx, channel.funding_tx))
                    {
                        writefln("Error calling requestTriggerSig(): %s", error);
                    }
                });
            }
            else
            {
                // settlement with seq id 1 attaches to update with seq id 1
            }
        }

        return null;
    }

    public override string requestTriggerSig (in Hash temp_chan_id,
        in Point peer_nonce_pk, Transaction trigger_tx,
        Transaction funding_tx)  // not signed yet
    {
        writefln("%s: requestTriggerSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        // todo: should not accept this call unless we already signed
        // a settlement transaction. Although there's no danger in accepting it.
        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Pending channel with this ID not found";

        // todo: if this is called again, we should just return the existing
        // signature which would be encoded in the Update
        // todo: we should just keep the old signatures in case the other
        // node needs it (technically we should just return the latest update tx
        // and the sequence ID)
        if (channel.pending_trigger != Trigger.init)
            return "Error: Multiple calls to requestTriggerSig() not supported";

        auto settle = &channel.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        if (channel.funding_tx != Transaction.init &&
            channel.funding_tx != funding_tx)
            return "Cannot request trigger for multiple funding txs";

        channel.funding_tx = funding_tx;
        channel.funding_tx_hash = funding_tx.hashFull();

        // todo: the semantics of the trigger tx need to be validated properly
        if (trigger_tx.inputs.length == 0)
            return "Invalid trigger tx";

        const funding_utxo = UTXO.getHash(channel.funding_tx_hash, 0);
        if (trigger_tx.inputs[0].utxo != funding_utxo)
            return "Trigger transaction does not reference the funding tx hash";

        settle.prev_tx = trigger_tx;

        const our_trigger_nonce_kp = Pair.random();

        auto peer = this.getFlashClient(channel.funder_pk);
        const nonce_pair_pk = our_trigger_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(this.kp.v, channel.pair_pk,
            nonce_pair_pk, our_trigger_nonce_kp.v, trigger_tx);

        channel.pending_trigger = Trigger(
            channel.temp_chan_id,
            our_trigger_nonce_kp,
            peer_nonce_pk,
            trigger_tx);

        this.taskman.schedule({
            peer.receiveTriggerSig(channel.temp_chan_id, our_trigger_nonce_kp.V,
                our_sig);
        });

        return null;
    }

    public override string receiveTriggerSig (in Hash temp_chan_id,
        in Point peer_nonce_pk, in Signature peer_sig)
    {
        writefln("%s: receiveTriggerSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Pending channel with this ID not found";

        auto trigger = &channel.pending_trigger;
        if (*trigger == Trigger.init)
            return "Could not find this pending trigger tx";

        auto settle = &channel.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        trigger.their_trigger_nonce_pk = peer_nonce_pk;
        const nonce_pair_pk = trigger.our_trigger_nonce_kp.V + peer_nonce_pk;

        auto peer = this.getFlashClient(channel.peer_pk);
        const our_sig = sign(this.kp.v, channel.pair_pk,
            nonce_pair_pk, trigger.our_trigger_nonce_kp.v, trigger.trigger_tx);

        // verify signature first
        const trigger_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock trigger_unlock = genKeyUnlock(trigger_multi_sig);
        trigger.trigger_tx.inputs[0].unlock = trigger_unlock;

        // when receiving the trigger transaction only the funder knows
        // the full funding transaction definition. Therefore the funder
        // should send us a non-signed funding tx here.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            channel.funding_tx.outputs[0].lock, trigger_unlock,
            trigger.trigger_tx, trigger.trigger_tx.inputs[0]))
        {
            assert(0, error);
        }

        channel.trigger = *trigger;

        writefln("%s: receiveTriggerSig(%s) VALIDATED", this.kp.V.prettify,
            temp_chan_id.prettify);

        // this prevents infinite loops, we may want to optimize this
        if (channel.funder_pk == this.kp.V)
        {
            // send the trigger signature
            this.taskman.schedule({
                if (auto error = peer.receiveTriggerSig(
                    channel.temp_chan_id, trigger.our_trigger_nonce_kp.V,
                    our_sig))
                {
                    writefln("Error sending trigger signature back: %s", error);
                }
            });

            // also safe to finally send the settlement signature
            const seq_id_0 = 0;
            this.taskman.schedule({
                if (auto error = peer.receiveSettlementSig(
                    channel.temp_chan_id, seq_id_0,
                    settle.our_settle_nonce_kp.V, settle.our_sig))
                {
                    writefln("Error sending settlement signature back: %s", error);
                }
            });

            // now ok to sign and publish funding tx
            writefln("%s: Sending funding tx(%s): %s", this.kp.V.prettify,
                temp_chan_id.prettify, hashFull(channel.funding_tx).prettify);
            channel.funding_tx.inputs[0].unlock
                = genKeyUnlock(sign(this.kp, channel.funding_tx));
            this.agora_node.putTransaction(channel.funding_tx);
            this.ready_to_externalize = true;

            //auto last_block = this.agora_node.getBlocksFrom(0, 1024)[$ - 1];
            //auto txs = last_block.spendable
            //    .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
            //    .array();
            //txs[0] = channel.funding_tx;  // rewrite this one
            //network.expectBlock(Height(2));
        }

        return null;
    }

    public override string requestUpdateSig (in Hash temp_chan_id,
        in uint seq_id, in Point peer_nonce_pk, Transaction update_tx)
    {
        writefln("%s: requestUpdateSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        // todo: should not accept this call unless we already signed
        // a settlement transaction. Although there's no danger in accepting it.
        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Pending channel with this ID not found";

        // todo: if this is called again, we should just return the existing
        // signature which would be encoded in the Update
        // todo: we should just keep the old signatures in case the other
        // node needs it (technically we should just return the latest update tx
        // and the sequence ID)
        if (channel.pending_update != Update.init)
            return "Error: Multiple calls to requestUpdateSig() not supported";

        auto settle = &channel.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        if (channel.funding_tx_hash == Hash.init)
            return "Funder has not sent us the funding transaction hash. "
                ~ "Refusing to sign update transaction";

        // todo: the semantics of the update tx need to be validated properly
        if (update_tx.inputs.length == 0)
            return "Invalid update tx";

        const funding_utxo = UTXO.getHash(channel.funding_tx_hash, 0);
        if (update_tx.inputs[0].utxo != funding_utxo)
            return "Update transaction does not reference the funding tx hash";

        settle.prev_tx = update_tx;

        const our_update_nonce_kp = Pair.random();

        auto peer = this.getFlashClient(channel.funder_pk);

        const our_update_scalar = getUpdateScalar(this.kp.v, channel.utxo);
        const num_peers = NumPeers(2);  // hardcoded for now
        const update_pair_pk = getUpdatePk(channel.pair_pk, channel.utxo,
            num_peers);

        const nonce_pair_pk = our_update_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(our_update_scalar, update_pair_pk,
            nonce_pair_pk, our_update_nonce_kp.v, update_tx);

        channel.pending_update = Update(
            channel.temp_chan_id,
            seq_id,
            our_update_nonce_kp,
            peer_nonce_pk,
            settle.prev_tx);

        this.taskman.schedule({
            peer.receiveUpdateSig(channel.temp_chan_id, seq_id,
                our_update_nonce_kp.V, our_sig);
        });

        return null;
    }

    public override string receiveUpdateSig (in Hash temp_chan_id,
        in uint seq_id, in Point peer_nonce_pk, in Signature peer_sig)
    {
        writefln("%s: receiveUpdateSig(%s)", this.kp.V.prettify,
            temp_chan_id.prettify);

        auto channel = temp_chan_id in this.pending_channels;
        if (channel is null)
            return "Pending channel with this ID not found";

        auto update = &channel.pending_update;
        if (*update == Update.init)
            return "Could not find this pending update tx";

        auto settle = &channel.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        if (update.seq_id != seq_id)
            return "Wrong sequence ID";

        update.their_update_nonce_pk = peer_nonce_pk;

        auto peer = this.getFlashClient(channel.peer_pk);

        const our_update_scalar = getUpdateScalar(this.kp.v, channel.utxo);
        const nonce_pair_pk = update.our_update_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(our_update_scalar, channel.update_pair_pk,
            nonce_pair_pk, update.our_update_nonce_kp.v, update.update_tx);

        // verify signature first
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        // todo: this is wrong, we should check if update can be attached
        // to the funding tx (it can't, it's the wrong signature)
        if (!verify(channel.update_pair_pk, update_multi_sig, update.update_tx))
            return "Signature does not validate!";

        const Unlock update_unlock = createUnlockUpdate(update_multi_sig,
            update.seq_id);
        settle.prev_tx.inputs[0].unlock = update_unlock;

        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            channel.funding_tx.outputs[0].lock, update_unlock,
            settle.prev_tx, settle.prev_tx.inputs[0]))
        {
            assert(0, error);
        }

        writefln("%s: receiveUpdateSig(%s) VALIDATED", this.kp.V.prettify,
            temp_chan_id.prettify);

        channel.last_update = *update;

        // this prevents infinite loops, we may want to optimize this
        if (channel.funder_pk == this.kp.V)
        {
            // send the update signature
            this.taskman.schedule({
                if (auto error = peer.receiveUpdateSig(
                    channel.temp_chan_id, seq_id, update.our_update_nonce_kp.V,
                    our_sig))
                {
                    writefln("Error sending update signature back: %s", error);
                }
            });
        }

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
    private Transaction createFundingTx (in Channel channel)
    {
        Transaction funding_tx = {
            type: TxType.Payment,
            inputs: [Input(channel.utxo)],
            outputs: [
                Output(channel.funding_amount,
                    Lock(LockType.Key, channel.pair_pk[].dup))]
        };

        return funding_tx;
    }

    /// Also used for the first trigger tx (using next_seq_id of 0)
    private Transaction createUpdateTx (in Channel channel,
        Transaction funding_tx, in uint next_seq_id)
    {
        const num_peers = NumPeers(2);  // hardcoded for now
        const Lock = createLockEltoo(channel.settle_time,
            channel.utxo, channel.pair_pk, next_seq_id, num_peers);

        Transaction update_tx = {
            type: TxType.Payment,
            inputs: [Input(funding_tx, 0 /* index */, 0 /* unlock age */)],
            outputs: [
                Output(channel.funding_amount, Lock)]  // bind to next sequence
        };

        return update_tx;
    }

    private RemoteAPI!FlashAPI getFlashClient (in Point peer_pk)
    {
        auto tid = this.flash_registry.locate(peer_pk.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");
        Duration timeout;
        return new RemoteAPI!FlashAPI(tid, timeout);
    }
}

/// Is in charge of spawning the flash nodes
public class UserFactory
{
    /// Registry of nodes
    private Registry* agora_registry;

    /// we keep a separate LocalRest registry of the flash "nodes"
    private Registry flash_registry;

    /// list of flash addresses
    private Point[] addresses;

    /// list of flash nodes
    private RemoteAPI!TestFlashAPI[] nodes;

    /// Ctor
    public this (Registry* agora_registry)
    {
        this.agora_registry = agora_registry;
        this.flash_registry.initialize();
    }

    /// Create a new flash node user
    public RemoteAPI!TestFlashAPI create (const Pair pair, string agora_address)
    {
        RemoteAPI!TestFlashAPI api = RemoteAPI!TestFlashAPI.spawn!User(pair,
            this.agora_registry, agora_address, &this.flash_registry);
        api.wait();  // wait for the ctor to finish

        this.addresses ~= pair.V;
        this.nodes ~= api;
        this.flash_registry.register(pair.V.to!string, api.tid());

        return api;
    }

    /// Shut down all the nodes
    public void shutdown ()
    {
        foreach (address; this.addresses)
            enforce(this.flash_registry.unregister(address.to!string));

        foreach (node; this.nodes)
            node.ctrl.shutdown();
    }
}

private string prettify (T)(T input)
{
    return input.to!string[0 .. 6];
}

/*******************************************************************************

    Create an Eltoo lock script based on Figure 4 from the whitepaper.

    Params:
        age = the age constraint for using the settlement keypair
        first_utxo = the first input's UTXO of the funding transaction.
                     used to be able to derive unique update & settlement
                     keypairs by using the UTXO as an offset.
        pair_pk = the Schnorr sum of the multi-party public keys.
                  The update an settlement keys will be derived from this
                  origin.
        next_seq_id = the sequence ID to lock to for the update spend branch

    Returns:
        a lock script which can be unlocked instantly with an update key-pair,
        or with a settlement key-pair if the age constraint of the input
        is satisfied.

*******************************************************************************/

public Lock createLockEltoo (uint age, Hash first_utxo, Point pair_pk,
    ulong next_seq_id, NumPeers count)
    //pure nothrow @safe
{
    /*
        Eltoo whitepaper Figure 4:

        Key pairs must be different for the if/else branch,
        otherwise an attacker could just steal the signature
        and use a different PUSH to evaluate the other branch.

        To force only a specific settlement tx to be valid, we need to make
        the settle key derived for each sequence ID. That way an attacker
        cannot attach any arbitrary settlement to any other update.

        Differences to whitepaper:
        - we use naive schnorr multisig for simplicity
        - we use VERIFY_SIG rather than CHECK_SIG, it improves testing
          reliability by ensuring the right failure reason is emitted.
          We manually push OP.TRUE to the stack after the verify.
        - VERIFY_SEQ_SIG expects a push of the sequence on the stack by
          the unlock script, and hashes the sequence to produce a signature.

        Explanation:
        [sig] - signature pushed by the unlock script.
        [new_seq] - sequence ID pushed by the unlock script.
        <seq + 1> - minimum sequence ID as set by the lock script. It's +1
            to allow binding of the next update TX (or any future update TX).
        OP.VERIFY_SEQ_SIG - verifies that [new_seq] >= <seq + 1>.
            Hashes the blanked Input together with the [new_seq] that was
            pushed to the stack. Then verifies the signature.

        OP.IF
            <age> OP.VERIFY_UNLOCK_AGE
            [sig] [new_seq] <seq + 1> <settle_pub_multi[new_seq]> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ELSE
            [sig] [new_seq] <seq + 1> <update_pub_multi> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ENDIF
    */

    const update_pair_pk = getUpdatePk(pair_pk, first_utxo, count);
    const next_settle_pair_pk = getSettlePk(pair_pk, first_utxo,
        next_seq_id, count);
    const age_bytes = nativeToLittleEndian(age);
    const ubyte[8] seq_id_bytes = nativeToLittleEndian(next_seq_id);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_UNLOCK_AGE)]
            ~ [ubyte(32)] ~ next_settle_pair_pk[] ~ toPushOpcode(seq_id_bytes)
                ~ [ubyte(OP.VERIFY_SEQ_SIG), ubyte(OP.TRUE),
         ubyte(OP.ELSE)]
            ~ [ubyte(32)] ~ update_pair_pk[] ~ toPushOpcode(seq_id_bytes)
                ~ [ubyte(OP.VERIFY_SEQ_SIG), ubyte(OP.TRUE),
         ubyte(OP.END_IF)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockSettle (Signature sig, in ulong sequence)
    pure nothrow @safe
{
    // remember it's LIFO when popping, TRUE goes last
    const seq_bytes = nativeToLittleEndian(sequence);
    return Unlock([ubyte(64)] ~ sig[] ~ toPushOpcode(seq_bytes)
        ~ [ubyte(OP.TRUE)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockUpdate (Signature sig, in ulong sequence)
    pure nothrow @safe
{
    // remember it's LIFO when popping, FALSE goes last
    const seq_bytes = nativeToLittleEndian(sequence);
    return Unlock([ubyte(64)] ~ sig[] ~ toPushOpcode(seq_bytes)
        ~ [ubyte(OP.FALSE)]);
}

//
public Scalar getUpdateScalar (in Scalar origin, in Hash utxo)
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getUpdatePk (in Point origin, in Hash utxo, NumPeers count)
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);

    import std.stdio;
    Scalar sum_scalar = seq_scalar;
    while (--count.value)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

//
public Scalar getSettleScalar (in Scalar origin, in Hash utxo, in ulong seq_id)
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getSettlePk (in Point origin, in Hash utxo, in ulong seq_id,
    NumPeers count)
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;

    Scalar sum_scalar = seq_scalar;
    while (--count.value)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

/// Ditto
unittest
{
    TestConf conf = TestConf.init;
    auto network = makeTestNetwork(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (exit) network.printLogs();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(1), network.blocks[0].header);

    // a little awkward, but we need the addresses
    //auto

    auto factory = new UserFactory(network.getRegistry());
    scope (exit) factory.shutdown();

    // use Schnorr
    const alice_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys[0].secret));
    const bob_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys[1].secret));

    // workaround to get a handle to the node from another registry thread
    const string address = format("Validator #%s (%s)", 0,
        WK.Keys.NODE2.address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);

    // 10 blocks settle time after / when trigger tx is published
    const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only really important for the funder)
    const utxo = UTXO.getHash(hashFull(txs[0]), 0);
    alice.ctrlOpenChannel(utxo, Amount(10_000), Settle_10_Blocks, bob_pair.V);

    while (!alice.readyToExternalize())
    {
        // there should be an infinite loop here which keeps creating txs
        Thread.sleep(100.msecs);
    }

    // one of these txs will be a double-spend
    txs = txs.map!(tx => TxBuilder(tx, 0))
        .enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(2), network.blocks[0].header);

    while (!alice.channelOpen())
    {
        // there should be an infinite loop here which keeps creating txs
        Thread.sleep(100.msecs);
    }

    writefln("Sending flash..");
    alice.sendFlash(Amount(10_000));

    Thread.sleep(1.seconds);
}
