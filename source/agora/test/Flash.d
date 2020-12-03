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

// todo 'connect()' should be a separate API point. We need to connect to
// a node before establishing channels.

// todo: invoice() and pay(). should be usable both-ways
// see readme in https://github.com/ElementsProject/lightning

/// Channel configuration. These fields remain static throughout the
/// lifetime of the channel. All of these fields are public and there
/// is no risk of sensitive data leakage when handling this struct.
public struct ChannelConfig
{
    /// Hash of the genesis block, used to determine which blockchain this
    /// channel belongs to
    public Hash gen_hash;

    /// Public key of the funder of the channel
    public Point funder_pk;

    /// Public key of the counter-party to the channel
    public Point peer_pk;

    /// Sum of `funder_pk + peer_pk`
    public Point pair_pk;

    /// Total number of co-signers needed to make update/settlement transactions
    /// in this channel. This does not include any HTLC intermediary peers.
    public const uint num_peers;

    /// The public key sum used for validating Update transactions.
    /// This key is derived and remains static throughout the
    /// lifetime of the channel.
    public const Point update_pair_pk;

    /// The funding transaction from which the trigger transaction may spend.
    /// This transaction is unsigned - only the funder may opt to send it
    /// to the agora network for externalization. The peer may opt to retrieve
    /// the signature when it detects this transaction is in the blockchain,
    /// but should prefer just using simple merkle root validation.
    public Transaction funding_tx;

    /// Hash of the funding transaction above.
    public Hash funding_tx_hash;

    /// The total amount funded in this channel. This information is
    /// derived from the Outputs of the funding transaction.
    public Amount funding_amount;

    /// The settle time to use for the settlement branch. This time is verified
    /// with the `OP.VERIFY_UNLOCK_AGE` opcode.
    public uint settle_time;

    /// The channel's ID is derived from the hash of the funding transaction
    public alias chan_id = funding_tx_hash;
}

/// Tracks the current stage of the channel.
/// Stages can only move forwards, and never back.
public enum Stage
{
    /// The channel has been accepted. The funding tx is known.
    Initializing = 1,

    /// start() was called
    Starting,

    /// Whether we've received the signed settlement transaction
    /// which attaches to the trigger transaction
    ReceivedInitialSettlement,

    /// Whether we've received the signed trigger transaction
    /// which attaches to the funding transaction
    ReceivedInitialTrigger,

    /// Whether the funding transaction was externalized in the blockchain.
    /// This signals the channel is now open.
    FundingExternalized,
}

/// Tracks the current state of the channel
public struct ChannelState
{
    /// Current stage in the channel.
    public Stage stage = Stage.Initializing;

    /// The current update / settlement sequence ID. Only valid if
    /// TODO: `stage` >= `Stage.`
    public uint seq_id = 0;
}

///
public class Channel
{
    /// The static information about this channel
    public const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Whether we are the funder of this channel (`funder_pk == this.kp.V`)
    public const bool is_funder;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Task manager to spawn fibers with
    public SchedulingTaskManager taskman;

    /// Used to publish funding / trigger / update / settlement tx's to blockchain
    public void delegate (in Transaction) txPublisher;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// Current state of the channel
    public ChannelState state;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, FlashAPI peer,
        SchedulingTaskManager taskman,
        void delegate (in Transaction) txPublisher)
    {
        this.conf = conf;
        this.kp = kp;
        this.is_funder = conf.funder_pk == kp.V;
        this.peer = peer;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
    }

    /// Start routine for the channel funder
    public void start ()
    {
        assert(this.is_funder);  // only funder initiates the channel
        assert(this.state.stage < Stage.Starting);  // start() should be called once

        this.state.stage = Stage.Starting;

        // create trigger, don't sign yet but do share it
        const next_seq_id = 0;
        auto trigger_tx = createUpdateTx(this.conf, next_seq_id);

        // initial output allocates all the funds back to the channel creator
        Output output = Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]));
        Output[] initial_outputs = [output];

        // first nonce for the settlement
        const nonce_kp = Pair.random();
        const seq_id_0 = 0;

        // todo: let's move the first settlement and trigger here,
        // and make all the calls blocking?
        // then after channel is set up, we just exit the fiber here
        // (this would be a fiber),
        // and let the FlashAPI dispatch to the appropriate routine

        this.pending_settlement = Settlement(
            this.conf.chan_id, seq_id_0, nonce_kp,
            Point.init, // set later when we receive it from counter-party
            trigger_tx,
            initial_outputs);

        this.taskman.schedule(
        {
            // request the peer to create a signed settlement transaction spending
            // from the trigger tx.
            if (auto error = this.peer.requestSettlementSig(this.conf.chan_id,
                trigger_tx, initial_outputs, seq_id_0, nonce_kp.V))
            {
                // todo: retry?
                writefln("Requested settlement rejected: %s", error);
                assert(0);
            }
        }

        while (!)
    }

    /// Flash API
    public string requestSettlementSig (in Transaction prev_tx,
        Output[] outputs, in uint seq_id, in Point peer_nonce_pk)
    {
        // todo: should not accept this unless acceptsChannel() was called
        writefln("%s: requestSettlementSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        /* todo: verify sequence ID is not an older sequence ID */
        /* todo: verify prev_tx is not one of our own transactions */

        const our_settle_nonce_kp = Pair.random();

        const settle_tx = createSettleTx(prev_tx, this.conf.settle_time,
            outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        const our_settle_scalar = getSettleScalar(this.kp.v, this.conf.funding_tx_hash,
            seq_id);
        const settle_pair_pk = getSettlePk(this.conf.pair_pk, this.conf.funding_tx_hash,
            seq_id, this.conf.num_peers);
        const nonce_pair_pk = our_settle_nonce_kp.V + peer_nonce_pk;

        const sig = sign(our_settle_scalar, settle_pair_pk, nonce_pair_pk,
            our_settle_nonce_kp.v, challenge_settle);

        // we also expect the counter-party to give us their signature
        this.pending_settlement = Settlement(
            this.conf.chan_id, seq_id, our_settle_nonce_kp,
            peer_nonce_pk,
            Transaction.init,  // trigger tx is revealed later
            outputs);

        this.taskman.schedule(
        {
            if (auto error = this.peer.receiveSettlementSig(this.conf.chan_id,
                seq_id, our_settle_nonce_kp.V, sig))
            {
                // todo: retry?
                writefln("Peer rejected settlement tx: %s", error);
            }
        });

        return null;
    }

    public string receiveSettlementSig (in uint seq_id, in Point peer_nonce_pk,
        in Signature peer_sig)
    {
        writefln("%s: receiveSettlementSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        auto settle = &this.pending_settlement;
        settle.their_settle_nonce_pk = peer_nonce_pk;

        // recreate the settlement tx
        auto settle_tx = createSettleTx(settle.prev_tx,
            this.conf.settle_time, settle.outputs);
        const uint input_idx = 0;
        const challenge_settle = getSequenceChallenge(settle_tx, seq_id,
            input_idx);

        // todo: send the signature back via receiveSettlementSig()
        // todo: add pending settlement to the other peer's pending settlements

        // Kim received the <settlement, signature> tuple.
        // he signs it, and finishes the multisig.
        Pair our_settle_origin_kp;
        Point their_settle_origin_pk;

        const our_settle_scalar = getSettleScalar(this.kp.v, this.conf.funding_tx_hash,
            seq_id);
        const settle_pair_pk = getSettlePk(this.conf.pair_pk, this.conf.funding_tx_hash,
            seq_id, this.conf.num_peers);
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
            this.kp.V.prettify, this.conf.chan_id.prettify, seq_id);

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

        this.last_settlement = *settle;

        // todo: protect against replay attacks. we do not want an infinite
        // loop scenario
        if (this.conf.funder_pk == this.kp.V)
        {
            if (seq_id == 0)
            {
                auto trigger_tx = settle.prev_tx;
                const our_trigger_nonce_kp = Pair.random();

                this.pending_trigger = Trigger(
                    this.conf.chan_id,
                    our_trigger_nonce_kp,
                    Point.init,  // set later when we receive it from counter-party
                    trigger_tx);

                this.taskman.schedule(
                {
                    if (auto error = this.peer.requestTriggerSig(this.conf.chan_id,
                        our_trigger_nonce_kp.V, trigger_tx))
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

    public string requestTriggerSig (in Point peer_nonce_pk,
        Transaction trigger_tx)
    {
        writefln("%s: requestTriggerSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        // todo: if this is called again, we should just return the existing
        // signature which would be encoded in the Update
        // todo: we should just keep the old signatures in case the other
        // node needs it (technically we should just return the latest update tx
        // and the sequence ID)
        if (this.pending_trigger != Trigger.init)
            return "Error: Multiple calls to requestTriggerSig() not supported";

        auto settle = &this.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        // todo: the semantics of the trigger tx need to be validated properly
        if (trigger_tx.inputs.length == 0)
            return "Invalid trigger tx";

        const funding_utxo = UTXO.getHash(this.conf.funding_tx_hash, 0);
        if (trigger_tx.inputs[0].utxo != funding_utxo)
            return "Trigger transaction does not reference the funding tx hash";

        settle.prev_tx = trigger_tx;

        const our_trigger_nonce_kp = Pair.random();

        const nonce_pair_pk = our_trigger_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(this.kp.v, this.conf.pair_pk,
            nonce_pair_pk, our_trigger_nonce_kp.v, trigger_tx);

        this.pending_trigger = Trigger(
            this.conf.chan_id,
            our_trigger_nonce_kp,
            peer_nonce_pk,
            trigger_tx);

        this.taskman.schedule(
        {
            this.peer.receiveTriggerSig(this.conf.chan_id, our_trigger_nonce_kp.V,
                our_sig);
        });

        return null;
    }

    public string receiveTriggerSig (in Point peer_nonce_pk,
        in Signature peer_sig)
    {
        writefln("%s: receiveTriggerSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        auto trigger = &this.pending_trigger;
        if (*trigger == Trigger.init)
            return "Could not find this pending trigger tx";

        auto settle = &this.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        trigger.their_trigger_nonce_pk = peer_nonce_pk;
        const nonce_pair_pk = trigger.our_trigger_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(this.kp.v, this.conf.pair_pk,
            nonce_pair_pk, trigger.our_trigger_nonce_kp.v, trigger.tx);

        // verify signature first
        const trigger_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock trigger_unlock = genKeyUnlock(trigger_multi_sig);
        trigger.tx.inputs[0].unlock = trigger_unlock;

        // when receiving the trigger transaction only the funder knows
        // the full funding transaction definition. Therefore the funder
        // should send us a non-signed funding tx here.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            this.conf.funding_tx.outputs[0].lock, trigger_unlock,
            trigger.tx, trigger.tx.inputs[0]))
        {
            assert(0, error);
        }

        this.trigger = *trigger;

        writefln("%s: receiveTriggerSig(%s) VALIDATED", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        // this prevents infinite loops, we may want to optimize this
        if (this.is_funder)
        {
            // send the trigger signature
            this.taskman.schedule(
            {
                if (auto error = this.peer.receiveTriggerSig(
                    this.conf.chan_id, trigger.our_trigger_nonce_kp.V,
                    our_sig))
                {
                    writefln("Error sending trigger signature back: %s", error);
                }
            });

            // also safe to finally send the settlement signature
            const seq_id_0 = 0;
            this.taskman.schedule(
            {
                if (auto error = this.peer.receiveSettlementSig(
                    this.conf.chan_id, seq_id_0,
                    settle.our_settle_nonce_kp.V, settle.our_sig))
                {
                    writefln("Error sending settlement signature back: %s", error);
                }
            });

            // now ok to sign and publish funding tx
            writefln("%s: Sending funding tx(%s): %s", this.kp.V.prettify,
                this.conf.chan_id.prettify,
                this.conf.funding_tx.hashFull.prettify);

            /// Store the funding so we can retry sending in case of failure
            this.funding_tx_signed = this.conf.funding_tx
                .serializeFull.deserializeFull!Transaction;
            this.funding_tx_signed.inputs[0].unlock
                = genKeyUnlock(sign(this.kp, this.conf.funding_tx));

            this.txPublisher(this.funding_tx_signed);
        }

        return null;
    }

    public string requestUpdateSig (in uint seq_id, in Point peer_nonce_pk,
        Transaction update_tx)
    {
        writefln("%s: requestUpdateSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        // todo: if this is called again, we should just return the existing
        // signature which would be encoded in the Update
        // todo: we should just keep the old signatures in case the other
        // node needs it (technically we should just return the latest update tx
        // and the sequence ID)
        if (this.pending_update != Update.init)
            return "Error: Multiple calls to requestUpdateSig() not supported";

        auto settle = &this.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        if (this.conf.funding_tx_hash == Hash.init)
            return "Funder has not sent us the funding transaction hash. "
                ~ "Refusing to sign update transaction";

        // todo: the semantics of the update tx need to be validated properly
        if (update_tx.inputs.length == 0)
            return "Invalid update tx";

        const funding_utxo = UTXO.getHash(this.conf.funding_tx_hash, 0);
        if (update_tx.inputs[0].utxo != funding_utxo)
            return "Update transaction does not reference the funding tx hash";

        settle.prev_tx = update_tx;

        const our_update_nonce_kp = Pair.random();

        const our_update_scalar = getUpdateScalar(this.kp.v, this.conf.funding_tx_hash);
        const update_pair_pk = getUpdatePk(this.conf.pair_pk,
            this.conf.funding_tx_hash, this.conf.num_peers);

        const nonce_pair_pk = our_update_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(our_update_scalar, update_pair_pk,
            nonce_pair_pk, our_update_nonce_kp.v, update_tx);

        this.pending_update = Update(
            this.conf.chan_id,
            seq_id,
            our_update_nonce_kp,
            peer_nonce_pk,
            settle.prev_tx);

        this.taskman.schedule(
        {
            this.peer.receiveUpdateSig(this.conf.chan_id, seq_id,
                our_update_nonce_kp.V, our_sig);
        });

        return null;
    }

    public string receiveUpdateSig (in uint seq_id, in Point peer_nonce_pk,
        in Signature peer_sig)
    {
        writefln("%s: receiveUpdateSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        auto update = &this.pending_update;
        if (*update == Update.init)
            return "Could not find this pending update tx";

        auto settle = &this.pending_settlement;
        if (*settle == Settlement.init)
            return "Pending settlement with this channel ID not found";

        if (update.seq_id != seq_id)
            return "Wrong sequence ID";

        update.their_update_nonce_pk = peer_nonce_pk;

        const our_update_scalar = getUpdateScalar(this.kp.v, this.conf.funding_tx_hash);
        const nonce_pair_pk = update.our_update_nonce_kp.V + peer_nonce_pk;

        const our_sig = sign(our_update_scalar, this.conf.update_pair_pk,
            nonce_pair_pk, update.our_update_nonce_kp.v, update.update_tx);

        // verify signature first
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock update_unlock = createUnlockUpdate(update_multi_sig,
            update.seq_id);
        settle.prev_tx.inputs[0].unlock = update_unlock;

        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            this.conf.funding_tx.outputs[0].lock, update_unlock,
            settle.prev_tx, settle.prev_tx.inputs[0]))
        {
            assert(0, error);
        }

        writefln("%s: receiveUpdateSig(%s) VALIDATED", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        this.last_update = *update;

        // this prevents infinite loops, we may want to optimize this
        if (this.is_funder)
        {
            // send the update signature
            this.taskman.schedule(
            {
                if (auto error = this.peer.receiveUpdateSig(
                    this.conf.chan_id, seq_id, update.our_update_nonce_kp.V,
                    our_sig))
                {
                    writefln("Error sending update signature back: %s", error);
                }
            });
        }

        return null;
    }

    // need it in order to publish to begin closing the channel
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
public struct Trigger
{
    Hash chan_id;
    Pair our_trigger_nonce_kp;
    Point their_trigger_nonce_pk;
    Transaction tx;
}

///
public struct Update
{
    Hash chan_id;
    uint seq_id;
    Pair our_update_nonce_kp;
    Point their_update_nonce_pk;
    Transaction update_tx;
}

///
public struct Settlement
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

/// This is the API that each flash-aware node must implement.
public interface FlashAPI
{
    /***************************************************************************

        Requests opening a channel with this node.

        Params:
            chan_conf = contains all the static configuration for this channel.

        Returns:
            null if agreed to open this channel, otherwise an error

    ***************************************************************************/

    public string openChannel (in ChannelConfig chan_conf);

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
            chan_id = A previously seen pending channel ID provided
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

    public string requestTriggerSig (in Hash chan_id,
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
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            peer_sig = the signature of the calling peer

        Returns:
            null, or an error string if the peer could not accept this signature

    ***************************************************************************/

    public string receiveTriggerSig (in Hash chan_id,
        in Point peer_nonce_pk, in Signature peer_sig);

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
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            prev_tx = the transaction whose outputs should be spent
            outputs = the outputs reallocating the funds
            seq_id = the sequence ID
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string requestSettlementSig (in Hash chan_id,
        in Transaction prev_tx, Output[] outputs, in uint seq_id,
        in Point peer_nonce_pk);

    /***************************************************************************

        Provide a settlement transaction that was requested by another peer
        through the `requestSettlementSig()`.

        Note that the settlement transaction itself is not sent back,
        because the requester already knows what the settlement transaction
        should look like. Only the signature should be sent back.

        Params:
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            seq_id = the sequence ID
            peer_nonce_pk = the nonce the calling peer is using for its
                own signature
            peer_sig = the partial signature that needs to be complimented by
                the second half of the settlement requester

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public string receiveSettlementSig (in Hash chan_id, in uint seq_id,
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
            chan_id = A previously seen pending channel ID provided
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
            chan_id = A previously seen pending channel ID provided
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
public interface ControlAPI : FlashAPI
{
    /// Prepare timers
    public void prepare ();

    /// Open a channel with another flash node.
    public string ctrlOpenChannel (in Hash funding_hash,
        in Amount funding_amount, in uint settle_time, in Point peer_pk);

    public void sendFlash (in Amount amount);

    /// convenience
    public bool readyToExternalize ();

    /// ditto
    public bool channelOpen ();
}

/// Could be a payer, or a merchant. funds can go either way in the channel.
/// There may be any number of channels between two parties
/// (e.g. think multiple different micropayment services)
/// In this test we assume there may only be one payment channel between two parties.
public abstract class FlashNode : FlashAPI
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
    private Channel[Hash] channels;

    private bool ready_to_externalize;

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

    /// publishes a transaction to the blockchain
    private void txPublisher (in Transaction tx)
    {
        this.agora_node.putTransaction(cast()tx);
        this.ready_to_externalize = true;
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
        foreach (hash, ref channel; this.channels)
        {
            if (channel.funding_externalized
                && channel.last_settlement != Settlement.init
                && channel.trigger != Trigger.init)
            {
                writefln("%s: Channel open(%s)", this.kp.V.prettify,
                    hash.prettify);
                //open_channels[channel.conf.funding_tx_hash] = channel;
                pending_chans_to_remove ~= hash;
                continue;
            }

            if (!channel.funding_externalized)
            foreach (tx; last_block.txs)
            {
                if (tx.hashFull() == channel.conf.funding_tx_hash)
                {
                    if (channel.funding_tx_signed != Transaction.init)
                        channel.funding_tx_signed
                            = tx.serializeFull.deserializeFull!Transaction;

                    channel.funding_externalized = true;
                    writefln("%s: Funding tx externalized(%s)",
                        this.kp.V.prettify, channel.conf.funding_tx_hash.prettify);
                    break;
                }
            }
        }

        foreach (id; pending_chans_to_remove)
            this.channels.remove(id);
    }

    /// Called by a channel funder
    public override string openChannel (in ChannelConfig chan_conf)
    {
        writefln("%s: openChannel()", this.kp.V.prettify);

        // todo: funding amount should be drived from the `funding_tx`
        // and not passed explicitly, else we would have to validate this.
        // add a sumOutputs thingy here.
        // todo: verify Outputs[] sum is equal to `funding_amoutn`
        // todo: verify `chan_conf.peer_pk` equals our own!

        // todo: need replay attack protection. adversary could feed us
        // a dupe temporary channel ID once it's removed from
        // `this.channels`
        if (chan_conf.chan_id in this.channels)
            return "There is already an open channel with this ID";

        auto peer = this.getFlashClient(chan_conf.funder_pk);

        const our_gen_hash = hashFull(GenesisBlock);
        if (chan_conf.gen_hash != our_gen_hash)
            return "Unrecognized blockchain genesis hash";

        const min_funding = Amount(1000);
        if (chan_conf.funding_amount < min_funding)
            return "Funding amount is too low";

        const min_settle_time = 5;
        const max_settle_time = 10;
        if (chan_conf.settle_time < min_settle_time ||
            chan_conf.settle_time > max_settle_time)
            return "Settle time is not within acceptable limits";

        this.channels[chan_conf.chan_id] = new Channel(chan_conf, this.kp,
            peer, this.taskman, &this.txPublisher);
        return null;
    }

    /// Flash API
    public override string requestSettlementSig (in Hash chan_id,
        in Transaction prev_tx, Output[] outputs, in uint seq_id,
        in Point peer_nonce_pk)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestSettlementSig(prev_tx, outputs, seq_id,
                peer_nonce_pk);

        return "Channel ID not found";
    }

    public override string receiveSettlementSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce_pk, in Signature peer_sig)
    {
        if (auto channel = chan_id in this.channels)
            return channel.receiveSettlementSig(seq_id, peer_nonce_pk, peer_sig);

        return "Channel ID not found";
    }

    public override string requestTriggerSig (in Hash chan_id,
        in Point peer_nonce_pk, Transaction trigger_tx)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestTriggerSig(peer_nonce_pk, trigger_tx);

        return "Channel ID not found";
    }

    public override string receiveTriggerSig (in Hash chan_id,
        in Point peer_nonce_pk, in Signature peer_sig)
    {
        if (auto channel = chan_id in this.channels)
            return channel.receiveTriggerSig(peer_nonce_pk, peer_sig);

        return "Channel ID not found";
    }

    public override string requestUpdateSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce_pk, Transaction update_tx)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestUpdateSig(seq_id, peer_nonce_pk, update_tx);

        return "Channel ID not found";
    }

    public override string receiveUpdateSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce_pk, in Signature peer_sig)
    {
        if (auto channel = chan_id in this.channels)
            return channel.receiveUpdateSig(seq_id, peer_nonce_pk, peer_sig);

        return "Channel ID not found";
    }

    private FlashAPI getFlashClient (in Point peer_pk)
    {
        auto tid = this.flash_registry.locate(peer_pk.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");
        Duration timeout;
        return new RemoteAPI!FlashAPI(tid, timeout);
    }
}

public class ControlFlashNode : FlashNode, ControlAPI
{
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        super(kp, agora_registry, agora_address, flash_registry);
    }

    /// Control API
    public override void prepare ()
    {
        this.taskman.setTimer(200.msecs, &this.listenFundingEvent, Periodic.Yes);
    }

    /// Control API
    public override string ctrlOpenChannel (in Hash funding_utxo,
        in Amount funding_amount, in uint settle_time, in Point peer_pk)
    {
        writefln("%s: ctrlOpenChannel(%s, %s, %s)", this.kp.V.prettify,
            funding_amount, settle_time, peer_pk.prettify);

        auto peer = this.getFlashClient(peer_pk);
        const pair_pk = this.kp.V + peer_pk;

        // create funding, don't sign it yet as we'll share it first
        auto funding_tx = createFundingTx(funding_utxo, funding_amount,
            pair_pk);

        const funding_tx_hash = hashFull(funding_tx);
        const Hash chan_id = funding_tx_hash;
        const num_peers = 2;

        const ChannelConfig chan_conf =
        {
            gen_hash        : hashFull(GenesisBlock),
            funder_pk       : this.kp.V,
            peer_pk         : peer_pk,
            pair_pk         : this.kp.V + peer_pk,
            num_peers       : num_peers,
            update_pair_pk  : getUpdatePk(pair_pk, funding_tx_hash, num_peers),
            funding_tx      : funding_tx,
            funding_tx_hash : funding_tx_hash,
            funding_amount  : funding_amount,
            settle_time     : settle_time,
        };

        if (auto error = peer.openChannel(chan_conf))
        {
            writefln("Peer rejected openChannel() request: %s", error);
            return error;
        }

        auto channel = new Channel(chan_conf, this.kp, peer, this.taskman,
            &this.txPublisher);
        this.channels[chan_id] = channel;
        channel.start();
        return null;
    }

    public void sendFlash (in Amount amount)
    {
        writefln("%s: sendFlash()", this.kp.V.prettify);

        //// todo: use actual channel IDs, or perhaps an invoice API
        //auto channel = this.open_channels[this.open_channels.byKey.front];

        //auto update_tx = this.createUpdateTx(channel.update_pair_pk,
        //    channel.trigger.tx,
        //    channel.funding_amount, channel.settle_time,
        //    channel.settle_origin_pair_pk);

        //this.peerrequestSettlementSig (in Hash chan_id,
        //    in Transaction prev_tx, Output[] outputs, in uint seq_id,
        //    in Point peer_nonce_pk)
    }

    /// convenience
    public override bool readyToExternalize ()
    {
        return this.ready_to_externalize;
    }

    /// ditto
    public override bool channelOpen ()
    {
        //return this.open_channels.length > 0;
        return false;
    }
}

/// Is in charge of spawning the flash nodes
public class FlashNodeFactory
{
    /// Registry of nodes
    private Registry* agora_registry;

    /// we keep a separate LocalRest registry of the flash "nodes"
    private Registry flash_registry;

    /// list of flash addresses
    private Point[] addresses;

    /// list of flash nodes
    private RemoteAPI!ControlAPI[] nodes;

    /// Ctor
    public this (Registry* agora_registry)
    {
        this.agora_registry = agora_registry;
        this.flash_registry.initialize();
    }

    /// Create a new flash node user
    public RemoteAPI!ControlAPI create (const Pair pair, string agora_address)
    {
        RemoteAPI!ControlAPI api = RemoteAPI!ControlAPI.spawn!ControlFlashNode(pair,
            this.agora_registry, agora_address, &this.flash_registry);
        api.prepare();

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
private Transaction createFundingTx (in Hash utxo, in Amount funding_amount,
    in Point pair_pk)
{
    Transaction funding_tx = {
        type: TxType.Payment,
        inputs: [Input(utxo)],
        outputs: [
            Output(funding_amount,
                Lock(LockType.Key, pair_pk[].dup))]
    };

    return funding_tx;
}

/// Also used for the first trigger tx (using next_seq_id of 0)
private Transaction createUpdateTx (in ChannelConfig chan_conf,
    in uint next_seq_id)
{
    const Lock = createLockEltoo(chan_conf.settle_time,
        chan_conf.funding_tx_hash, chan_conf.pair_pk, next_seq_id,
        chan_conf.num_peers);

    Transaction update_tx = {
        type: TxType.Payment,
        inputs: [Input(chan_conf.funding_tx, 0 /* index */, 0 /* unlock age */)],
        outputs: [
            Output(chan_conf.funding_amount, Lock)]
    };

    return update_tx;
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
    ulong next_seq_id, uint num_peers)
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

    const update_pair_pk = getUpdatePk(pair_pk, first_utxo, num_peers);
    const next_settle_pair_pk = getSettlePk(pair_pk, first_utxo,
        next_seq_id, num_peers);
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
public Point getUpdatePk (in Point origin, in Hash utxo, uint num_peers)
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);

    import std.stdio;
    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
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
    uint num_peers)
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;

    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

/// Simplified `schedule` routine
private class SchedulingTaskManager : LocalRestTaskManager
{
    /// Ditto
    public void schedule (void delegate() dg) nothrow
    {
        super.setTimer(0.seconds, dg);
    }
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

    auto factory = new FlashNodeFactory(network.getRegistry());
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

    //while (!alice.channelOpen())
    //{
    //    // there should be an infinite loop here which keeps creating txs
    //    Thread.sleep(100.msecs);
    //}

    //alice.sendFlash(Amount(10_000));

    Thread.sleep(1.seconds);
}
