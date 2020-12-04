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

import std.algorithm;
import std.bitmanip;
import std.container.dlist;
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

// todo: both parties could attempt to send each other invoices at the same
// time. how does C-LN handle this? Maybe the sequence ID should be part of
// the invoice, and only one can cooperatively be accepted.

// todo: make the channel ID a const struct?

// todo: create an example where we use a new update attaching to a settlement
// which immediately refunds everyone. This is a cooperative closing of a channel.
public struct OpenResult
{
    string error;  // in case rejected
    PublicNonce peer_nonce;
}

public struct SigResult
{
    string error;  // in case rejected
    Signature sig;
}

public struct Balance
{
    Output[] outputs;
}

public struct BalanceRequest
{
    Balance balance;
    PublicNonce peer_nonce;
}

public struct BalanceResult
{
    string error;  // in case rejected
    PublicNonce peer_nonce;
}

public struct ChannelStatus
{
    string error;
    Hash chan_id;
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

    public OpenResult openChannel (in ChannelConfig chan_conf,
        PublicNonce peer_nonce);

    /***************************************************************************

        Requests opening a channel with this node.

        Params:
            chan_conf = contains all the static configuration for this channel.

        Returns:
            null if agreed to open this channel, otherwise an error

    ***************************************************************************/

    public BalanceResult requestUpdateBalance (in Hash chan_id, in uint seq_id,
        in BalanceRequest balance_req);

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
            peer_nonce = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public SigResult requestSettleSig (in Hash chan_id, in uint seq_id);

    /***************************************************************************

        Request the peer to sign the trigger transaction, from which the
        settlement transaction spends.

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveUpdateSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveUpdateSig()`,
        making the symmetry complete.

        Params:
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the peer could not sign the trigger
            transaction for whatever reason

    ***************************************************************************/

    public SigResult requestUpdateSig (in Hash chan_id, in uint seq_id);
}

/// Channel configuration. These fields remain static throughout the
/// lifetime of the channel. All of these fields are public and known
/// by all participants in the channel.
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

/// Tracks the current state of the channel.
/// States can only move forwards, and never back.
public enum State
{
    /// Cooperating on the initial trigger and settlement txs.
    Setup,

    /// Waiting for the funding tx to appear in the blockchain.
    WaitingForFunding,

    /// The channel is open.
    Open,

    /// The channel is closed.
    Closed,
}

/// The update & settle pair for a given sequence ID
public struct UpdatePair
{
    /// The sequence ID of this slot
    public uint seq_id;

    /// Update tx which spends the trigger tx's outputs and can replace
    /// any previous update containing a lower sequence ID than this one's.
    private Transaction update_tx;

    /// Settle tx which spends from `update_tx` above
    private Transaction settle_tx;
}

///
public class SignTask
{
    /// Channel configuration
    private const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Task manager to spawn fibers with
    public SchedulingTaskManager taskman;

    /// Peer we're communicating with
    private FlashAPI peer;

    /// Sequence ID we're trying to sign for
    /// Todo: we should also have some kind of incremental ID to be able to
    /// re-try the same sequence IDs
    private uint seq_id;

    private static struct PendingSettle
    {
        private Transaction tx;
        private Signature our_sig;
        private Signature peer_sig;
        private bool validated;
    }

    private static struct PendingUpdate
    {
        private Transaction tx;
        private Signature our_sig;
        private Signature peer_sig;
        private bool validated;
    }

    private PendingSettle pending_settle;
    private PendingUpdate pending_update;

    /// Tasks for the various asynchronous API calls
    private ITimer request_task;
    /// Ditto
    private ITimer send_settle_task;
    /// Ditto
    private ITimer send_update_task;

    /// Ctor
    public this (in ChannelConfig conf,  in Pair kp,
        SchedulingTaskManager taskman, FlashAPI peer)
    {
        this.conf = conf;
        this.kp = kp;
        this.taskman = taskman;
        this.peer = peer;
    }

    // balance allready agreed upon!
    // todo: this can be a blocking call
    /// priv_nonce = The private nonce we'll use for this signing session
    /// peer_nonce = The nonce we expect the peer to use for this signing session
    public UpdatePair run (in uint seq_id, in Balance balance,
        PrivateNonce priv_nonce, PublicNonce peer_nonce)
    {
        this.clearState();
        this.seq_id = seq_id;

        this.pending_update = this.createPendingUpdate(priv_nonce, peer_nonce);
        this.pending_settle = this.createPendingSettle(this.pending_update.tx,
            balance, priv_nonce, peer_nonce);

        auto status = this.peer.requestSettleSig(this.conf.chan_id,
            seq_id);
        if (status.error !is null)
        {
            // todo: retry?
            writefln("Settlement signature request rejected: %s", status.error);
            assert(0);
        }

        if (auto error = this.isInvalidSettleMultiSig(this.pending_settle,
            status.sig, priv_nonce, peer_nonce))
        {
            // todo: inform? ban?
            writefln("Error during validation: %s For settle signature: %s",
                error, status.sig);
            assert(0);
        }
        this.pending_settle.peer_sig = status.sig;
        this.pending_settle.validated = true;

        // here it's a bit problematic because the counter-party will refuse
        // to reveal their update sig until they receive the settlement signature
        // todo: could we just share it in the single request API?
        status = this.peer.requestUpdateSig(this.conf.chan_id, seq_id);
        if (status.error !is null)
        {
            // todo: retry?
            writefln("Update signature request rejected: %s", status.error);
            assert(0);
        }

        // todo: retry? add a better status code like NotReady?
        if (status.sig == Signature.init)
            assert(0);

        if (auto error = this.isInvalidUpdateMultiSig(this.pending_update,
            status.sig, priv_nonce, peer_nonce))
        {
            // todo: inform? ban?
            writefln("Error during validation: %s For update signature: %s",
                error, status.sig);
            assert(0);
        }
        this.pending_update.peer_sig = status.sig;
        this.pending_update.validated = true;

        UpdatePair pair =
        {
            seq_id : this.seq_id,
            update_tx : this.pending_update.tx,
            settle_tx : this.pending_settle.tx,
        };

        return pair;
    }

    private Signature getUpdateSig (in Transaction update_tx,
        in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.update.V + peer_nonce.update;

        // if the current sequence is 0 then the update tx is a trigger tx that
        // only needs a multi-sig and does not require a sequence.
        // Note that we cannot use a funding tx hash derived update key because
        // the funding tx's key lock is part of the hash (cyclic dependency).
        // Therefore we instead treat the trigger tx as special and simply
        // use a multisig with the pair_pk.
        // Note that an update tx with seq 0 do not exist.
        if (this.seq_id == 0)
        {
            return sign(this.kp.v, this.conf.pair_pk, nonce_pair_pk,
                priv_nonce.update.v, update_tx);
        }
        else
        {
            const update_key = getUpdateScalar(this.kp.v,
                this.conf.funding_tx_hash);
            const challenge_update = getSequenceChallenge(update_tx,
                this.seq_id, 0);  // todo: should not be hardcoded
            return sign(update_key, this.conf.update_pair_pk, nonce_pair_pk,
                priv_nonce.update.v, challenge_update);
        }
    }

    private PendingUpdate createPendingUpdate (in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        auto update_tx = createUpdateTx(this.conf, seq_id);
        const sig = this.getUpdateSig(update_tx, priv_nonce, peer_nonce);

        PendingUpdate update =
        {
            tx        : update_tx,
            our_sig   : sig,
            validated : false,
        };

        return update;
    }

    private PendingSettle createPendingSettle (in Transaction update_tx,
        in Balance balance, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const settle_key = getSettleScalar(this.kp.v, this.conf.funding_tx_hash,
            this.seq_id);
        const settle_pair_pk = getSettlePk(this.conf.pair_pk,
            this.conf.funding_tx_hash, this.seq_id, this.conf.num_peers);
        const nonce_pair_pk = priv_nonce.settle.V + peer_nonce.settle;

        const uint input_idx = 0;  // this should ideally not be hardcoded
        auto settle_tx = createSettleTx(update_tx, this.conf.settle_time,
            balance.outputs);
        const challenge_settle = getSequenceChallenge(settle_tx, this.seq_id,
            input_idx);

        const sig = sign(settle_key, settle_pair_pk, nonce_pair_pk,
            priv_nonce.settle.v, challenge_settle);

        // settle.tx.inputs[0].unlock =
        PendingSettle settle =
        {
            tx        : settle_tx,
            our_sig   : sig,
            validated : false,
        };

        return settle;
    }

    private string isInvalidSettleMultiSig (ref PendingSettle settle,
        in Signature peer_sig, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.settle.V + peer_nonce.settle;
        const settle_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(settle.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        Transaction settle_tx
            = settle.tx.serializeFull().deserializeFull!Transaction;

        const Unlock settle_unlock = createUnlockSettle(settle_multi_sig,
            this.seq_id);
        settle_tx.inputs[0].unlock = settle_unlock;

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            this.pending_update.tx.outputs[0].lock, settle_tx.inputs[0].unlock,
            settle_tx, settle_tx.inputs[0]))
            return error;

        settle.tx = settle_tx;
        return null;
    }

    private string isInvalidUpdateMultiSig (ref PendingUpdate update,
        in Signature peer_sig, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.update.V + peer_nonce.update;
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(update.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        Transaction update_tx
            = update.tx.serializeFull().deserializeFull!Transaction;

        const Unlock update_unlock = this.getUpdateUnlock(update_multi_sig);
        update_tx.inputs[0].unlock = update_unlock;
        const lock = this.getUpdateLock();

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(lock, update_tx.inputs[0].unlock,
            update_tx, update_tx.inputs[0]))
            return error;

        update.tx = update_tx;
        return null;
    }

    private Unlock getUpdateUnlock (Signature update_multi_sig)
    {
        // if the current sequence is 0 then the update tx is a trigger tx that
        // only needs a multi-sig and does not require a sequence.
        // an update tx with seq 0 do not exist.
        if (this.seq_id == 0)
            return genKeyUnlock(update_multi_sig);
        else
            return createUnlockUpdate(update_multi_sig, this.seq_id);
    }

    private Lock getUpdateLock ()
    {
        // if the current sequence is 0 then the lock is the funding tx's lock,
        // otherwise it's the trigger tx's lock
        if (this.seq_id == 0)
        {
            return this.conf.funding_tx.outputs[0].lock;
        }
        else
        {
            const prev_seq = this.seq_id - 1;
            return createLockEltoo(this.conf.settle_time,
                this.conf.funding_tx_hash, this.conf.pair_pk, prev_seq,
                this.conf.num_peers);
        }
    }

    ///
    public SigResult requestSettleSig ()
    {
        // it's always safe to share our settlement signature because
        // it may only attach to the matching update tx which is signed later.
        return SigResult(null, this.pending_settle.our_sig);
    }

    ///
    public SigResult requestUpdateSig ()
    {
        // sharing the update signature prematurely can lead to funds being
        // permanently locked if the settlement signature is missing and the
        // update transaction is externalized.
        if (!this.pending_settle.validated)
            return SigResult("Cannot share update signature until "
                ~ "settlement signature is received");

        return SigResult(null, this.pending_update.our_sig);
    }

    /// Cancels any existing tasks and clears the state
    public void clearState ()
    {
        this.pending_settle = PendingSettle.init;
        this.pending_update = PendingUpdate.init;

        // cancel any pending tasks
        if (this.request_task !is null)
            this.request_task.stop();
        if (this.send_settle_task !is null)
            this.send_settle_task.stop();
        if (this.send_update_task !is null)
            this.send_update_task.stop();
    }
}

struct PrivateNonce
{
    Pair settle;
    Pair update;
}

struct PublicNonce
{
    Point settle;
    Point update;
}

/// Contains all the logic for maintaining a channel
public class Channel
{
    /// The static information about this channel
    public const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Whether we are the funder of this channel (`funder_pk == this.kp.V`)
    public const bool is_owner;

    /// Used to publish funding / trigger / update / settlement txs to blockchain
    public const void delegate (in Transaction) txPublisher;

    /// Task manager to spawn fibers with
    public SchedulingTaskManager taskman;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Current state of the channel
    private State state;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// The signer for an update / settle pair
    private SignTask sign_task;

    /// The list of any off-chain updates which happened on this channel
    private UpdatePair[] channel_updates;

    /// The current sequence ID
    private uint cur_seq_id;

    /// The current balance of the channel. Initially empty until the
    /// funding tx is externalized.
    private Balance cur_balance;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, FlashAPI peer,
        SchedulingTaskManager taskman,
        void delegate (in Transaction) txPublisher)
    {
        this.conf = conf;
        this.kp = kp;
        this.is_owner = conf.funder_pk == kp.V;
        this.peer = peer;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.sign_task = new SignTask(this.conf, this.kp, this.taskman,
            this.peer);
    }

    ///
    public bool isWaitingForFunding ()
    {
        return this.state == State.WaitingForFunding;
    }

    ///
    public bool isOpen ()
    {
        return this.state == State.Open;
    }

    /// Start routine for the channel
    public void start (in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        assert(this.state == State.Setup);
        assert(this.cur_seq_id == 0);

        // initial output allocates all the funds back to the channel creator
        const seq_id = 0;
        auto balance = Balance([Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))]);
        auto pair = this.sign_task.run(seq_id, balance, priv_nonce, peer_nonce);
        this.onSetupComplete(pair);
    }

    public void fundingExternalized (in Transaction tx)
    {
        this.funding_tx_signed = tx.serializeFull.deserializeFull!Transaction;
        if (this.state == State.WaitingForFunding)
            this.state = State.Open;

        // todo: assert that this is really the actual balance
        this.cur_balance = Balance([Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))]);
    }

    ///
    private void onSetupComplete (UpdatePair update_pair)
    {
        // this is not technically an error, but it would be very strange
        // that a funding tx was published before signing was complete,
        // as the funding party carries the risk of having their funds locked.
        // in this case we skip straight to the open state.
        if (this.funding_tx_signed != Transaction.init)
            this.state = State.Open;
        else
            this.state = State.WaitingForFunding;

        // if we're the funder then it's time to publish the funding tx
        if (this.is_owner)
        {
            this.funding_tx_signed = this.conf.funding_tx.clone();
            this.funding_tx_signed.inputs[0].unlock
                = genKeyUnlock(sign(this.kp, this.conf.funding_tx));

            this.txPublisher(this.funding_tx_signed);
        }

        this.sign_task.clearState();
        this.channel_updates ~= update_pair;
    }

    ///
    public SigResult requestSettleSig (in uint seq_id)
    {
        if (auto error = this.isInvalidSeq(seq_id))
            return SigResult(error);

        return this.sign_task.requestSettleSig();
    }

    ///
    public SigResult requestUpdateSig (in uint seq_id)
    {
        if (auto error = this.isInvalidSeq(seq_id))
            return SigResult(error);

        return this.sign_task.requestUpdateSig();
    }

    ///
    public void signUpdate (in uint seq_id, PrivateNonce priv_nonce,
        PublicNonce peer_nonce, in Balance new_balance)
    {
        writefln("%s: signUpdate(%s)", this.kp.V.prettify,
            seq_id);

        assert(this.state == State.Open);
        assert(seq_id == this.cur_seq_id + 1);

        this.cur_seq_id++;
        auto update_pair = this.sign_task.run(this.cur_seq_id, new_balance,
            priv_nonce, peer_nonce);

        writefln("%s: Got new update pair!", this.kp.V.prettify);
        this.sign_task.clearState();
        this.channel_updates ~= update_pair;
        this.cur_balance.outputs = new_balance.outputs.dup;
    }

    public UpdatePair close ()
    {
        assert(this.isOpen());
        this.state = State.Closed;

        // publish the trigger transaction
        return this.channel_updates[0];
    }

    ///
    private string isInvalidSeq (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return "Invalid sequence ID";

        return null;
    }
}

/// In addition to the Flash API, we provide controller methods to initiate
/// the channel creation procedures, and control each flash node's behavior.
public interface ControlAPI : FlashAPI
{
    /// Prepare timers
    public void prepare ();

    /// Open a channel with another flash node.
    public Hash ctrlOpenChannel (in Hash funding_hash, in Amount funding_amount,
        in uint settle_time, in Point peer_pk);

    public UpdatePair ctrlUpdateBalance (in Hash chan_id, in Amount funder,
        in Amount peer);

    public void ctrlCloseChannel (in Hash chan_id);

    // todo: add channel ID
    public bool readyToExternalize ();

    /// ditto
    public bool anyChannelOpen ();
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

    private bool ready_to_close;

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

    /// Called by a channel funder
    public override OpenResult openChannel (in ChannelConfig chan_conf,
        PublicNonce peer_nonce)
    {
        writefln("%s: openChannel()", this.kp.V.prettify);

        if (chan_conf.chan_id in this.channels)
            return OpenResult("There is already an open channel with this ID");

        auto peer = this.getFlashClient(chan_conf.funder_pk);

        const our_gen_hash = hashFull(GenesisBlock);
        if (chan_conf.gen_hash != our_gen_hash)
            return OpenResult("Unrecognized blockchain genesis hash");

        const min_funding = Amount(1000);
        if (chan_conf.funding_amount < min_funding)
            return OpenResult("Funding amount is too low");

        // todo: re-enable
        version (none)
        {
            const min_settle_time = 5;
            const max_settle_time = 10;
            if (chan_conf.settle_time < min_settle_time ||
                chan_conf.settle_time > max_settle_time)
                return OpenResult("Settle time is not within acceptable limits");
        }

        // todo: move this into start()
        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        auto channel = new Channel(chan_conf, this.kp, peer, this.taskman,
            &this.txPublisher);
        this.channels[chan_conf.chan_id] = channel;

        this.taskman.schedule(
        {
            channel.start(priv_nonce, peer_nonce);
        });

        return OpenResult(null, pub_nonce);
    }

    ///
    public override SigResult requestSettleSig (in Hash chan_id, in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestSettleSig(seq_id);

        return SigResult("Channel ID not found");
    }

    ///
    public override SigResult requestUpdateSig (in Hash chan_id, in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestUpdateSig(seq_id);

        return SigResult("Channel ID not found");
    }

    ///
    public override BalanceResult requestUpdateBalance (in Hash chan_id,
        in uint seq_id, in BalanceRequest balance_req)
    {
        writefln("%s: requestUpdateBalance(%s, %s)", this.kp.V.prettify,
            chan_id.prettify, seq_id);

        auto channel = chan_id in this.channels;
        if (channel is null)
            return BalanceResult("Channel ID not found");

        if (!channel.isOpen())
            return BalanceResult("This channel is not funded yet");

        // todo: need to add sequence ID verification here
        // todo: add logic if we agree with the new balance
        // todo: check sums for the balance so it doesn't exceed
        // the channel balance, and that it matches exactly.

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        this.taskman.schedule(
        {
            channel.signUpdate(seq_id, priv_nonce, balance_req.peer_nonce,
                balance_req.balance);
        });

        return BalanceResult(null, pub_nonce);
    }

    ///
    private FlashAPI getFlashClient (in Point peer_pk)
    {
        auto tid = this.flash_registry.locate(peer_pk.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");
        Duration timeout;
        return new RemoteAPI!FlashAPI(tid, timeout);
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
            if (!channel.isWaitingForFunding())
                continue;

            foreach (tx; last_block.txs)
            {
                if (tx.hashFull() == channel.conf.funding_tx_hash)
                {
                    channel.fundingExternalized(tx);
                    writefln("%s: Funding tx externalized(%s)",
                        this.kp.V.prettify, channel.conf.funding_tx_hash);
                    break;
                }
            }
        }

        foreach (id; pending_chans_to_remove)
            this.channels.remove(id);
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
    public override Hash ctrlOpenChannel (in Hash funding_utxo,
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

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        auto status = peer.openChannel(chan_conf, pub_nonce);
        assert(status.error is null, status.error);

        auto channel = new Channel(chan_conf, this.kp, peer, this.taskman,
            &this.txPublisher);
        this.channels[chan_id] = channel;
        channel.start(priv_nonce, status.peer_nonce);

        return chan_id;
    }

    /// Control API
    public override void ctrlCloseChannel (in Hash chan_id)
    {

    }

    /// Control API
    public override UpdatePair ctrlUpdateBalance (in Hash chan_id,
        in Amount funder_amount, in Amount peer_amount)
    {
        writefln("%s: ctrlUpdateBalance(%s, %s, %s)", this.kp.V.prettify,
            chan_id.prettify, funder_amount, peer_amount);

        auto channel = chan_id in this.channels;
        assert(channel !is null);

        // todo: we need to track this somewhere else
        static uint seq_id = 0;
        ++seq_id;

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        const Balance balance = Balance(
            [Output(funder_amount, PublicKey(channel.conf.funder_pk[])),
             Output(peer_amount, PublicKey(channel.conf.peer_pk[]))]);

        const BalanceRequest balance_req =
        {
            balance    : balance,
            peer_nonce : pub_nonce,
        };

        auto status = channel.peer.requestUpdateBalance(chan_id, seq_id,
            balance_req);
        assert(status.error is null, status.error);

        channel.signUpdate(seq_id, priv_nonce, status.peer_nonce, balance);
        return channel.close();
    }

    /// convenience
    public override bool readyToExternalize ()
    {
        return this.ready_to_externalize;
    }

    /// ditto
    public override bool anyChannelOpen ()
    {
        return this.channels.byValue.any!(chan => chan.isOpen());
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

///
private Transaction createUpdateTx (in ChannelConfig chan_conf,
    in uint seq_id)
{
    const Lock = createLockEltoo(chan_conf.settle_time,
        chan_conf.funding_tx_hash, chan_conf.pair_pk, seq_id,
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
        seq_id = the sequence ID to use for the settlement branch. For the
            update branch `seq_id + 1` will be used.

    Returns:
        a lock script which can be unlocked instantly with an update key-pair,
        or with a settlement key-pair if the age constraint of the input
        is satisfied.

*******************************************************************************/

public Lock createLockEltoo (uint age, Hash first_utxo, Point pair_pk,
    ulong seq_id, uint num_peers)
    //pure nothrow @safe
{
    /*
        Eltoo whitepaper Figure 4:

        Key pairs must be different for the if/else branch,
        otherwise an attacker could just steal the signature
        and use a different PUSH to evaluate the other branch.

        To force only a specific settlement tx to be valid we need to make
        the settle key derived for each sequence ID. That way an attacker
        cannot attach any arbitrary settlement to any other update.

        Differences to whitepaper:
        - we use naive schnorr multisig for simplicity
        - we use VERIFY_SIG rather than CHECK_SIG, it improves testing
          reliability by ensuring the right failure reason is emitted.
          We manually push OP.TRUE to the stack after the verify. (temporary)
        - VERIFY_SEQ_SIG expects a push of the sequence on the stack by
          the unlock script, and hashes the sequence to produce a signature.

        Explanation:
        [sig] - signature pushed by the unlock script.
        [spend_seq] - sequence ID pushed by the unlock script in the spending tx.
        <seq + 1> - minimum sequence ID as set by the lock script. It's +1
            to allow binding of the next update tx (or any future update tx).
        OP.VERIFY_SEQ_SIG - verifies that [spend_seq] >= <seq + 1>.
            Hashes the blanked Input together with the [spend_seq] that was
            pushed to the stack and then verifies the signature.

        OP.IF
            [sig] [spend_seq] <seq + 1> <update_pub_multi> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ELSE
            <age> OP.VERIFY_UNLOCK_AGE
            [sig] [spend_seq] <seq> <settle_pub_multi[spend_seq]> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ENDIF
    */

    const update_pair_pk = getUpdatePk(pair_pk, first_utxo, num_peers);
    const settle_pair_pk = getSettlePk(pair_pk, first_utxo, seq_id, num_peers);
    const age_bytes = nativeToLittleEndian(age);
    const ubyte[8] seq_id_bytes = nativeToLittleEndian(seq_id);
    const ubyte[8] next_seq_id_bytes = nativeToLittleEndian(seq_id + 1);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ [ubyte(32)] ~ update_pair_pk[] ~ toPushOpcode(next_seq_id_bytes)
            ~ [ubyte(OP.VERIFY_SEQ_SIG), ubyte(OP.TRUE),
         ubyte(OP.ELSE)]
             ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_UNLOCK_AGE)]
            ~ [ubyte(32)] ~ settle_pair_pk[] ~ toPushOpcode(seq_id_bytes)
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

public Unlock createUnlockUpdate (Signature sig, in ulong sequence)
    pure nothrow @safe
{
    // remember it's LIFO when popping, TRUE is pushed last
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

public Unlock createUnlockSettle (Signature sig, in ulong sequence)
    pure nothrow @safe
{
    // remember it's LIFO when popping, FALSE is pushed last
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
    public ITimer schedule (void delegate() dg) nothrow
    {
        return super.setTimer(0.seconds, dg);
    }
}

/// utility
private T clone (T)(in T input)
{
    return input.serializeFull.deserializeFull!T;
}

private PrivateNonce genPrivateNonce ()
{
    PrivateNonce priv_nonce =
    {
        settle : Pair.random(),
        update : Pair.random(),
    };

    return priv_nonce;
}

private PublicNonce getPublicNonce (in PrivateNonce priv_nonce)
{
    PublicNonce pub_nonce =
    {
        settle : priv_nonce.settle.V,
        update : priv_nonce.update.V,
    };

    return pub_nonce;
}

/// Ditto
unittest
{
    TestConf conf = TestConf.init;
    auto network = makeTestNetwork(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (exit) network.printLogs();
    scope (failure) network.printLogs();
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
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only really important for the funder)
    const utxo = UTXO.getHash(hashFull(txs[0]), 0);

    const chan_id = alice.ctrlOpenChannel(
        utxo, Amount(10_000), Settle_1_Blocks, bob_pair.V);

    while (!alice.readyToExternalize())
    {
        // there should be an infinite loop here which keeps creating txs
        Thread.sleep(100.msecs);
    }

    // one of these txs will be a double-spend but it's ok
    txs = txs.map!(tx => TxBuilder(tx, 0))
        .enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(2), network.blocks[0].header);

    // todo: should check both parties if they're ready
    while (!alice.anyChannelOpen())
    {
        // there should be an infinite loop here which keeps creating txs
        Thread.sleep(100.msecs);
    }

    Thread.sleep(1.seconds);

    // there seems to be a timing issue (channel not funded for counter-party yet)
    auto update_pair = alice.ctrlUpdateBalance(
        chan_id, Amount(10_000), Amount(5_000));

    // now we publish trigger tx
    const block_2 = node_1.getBlocksFrom(0, 1024)[$ - 1];

    foreach (idx, tx; block_2.txs)
    {
        //writefln("%s match: %s", idx, tx.outputs[0].lock.bytes);
    }

    const funding_tx_hash = Hash.fromString("0x54615ad5a07681a1a4e677ede7bd325c570d2d5003b0f86e6c03f3031a4d905514354cf72048f9c50c7ccdca251a01fa8971fe042f8e67e9b21652d54162241b");

    txs = filtSpendable!(tx => tx.hashFull() != funding_tx_hash)(block_2)
        .enumerate()
        .map!(en => en.value.refund(WK.Keys[3].address).sign())
        .take(7)
        .array();
    writefln("Posting update tx: %s", update_pair.update_tx.hashFull());
    txs ~= update_pair.update_tx;

    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(3), network.blocks[0].header);

    const block_3 = node_1.getBlocksFrom(0, 1024)[$ - 1];
    txs = filtSpendable!(tx => tx.hashFull() != update_pair.update_tx.hashFull())(block_3)
        .enumerate()
        .map!(en => en.value.refund(WK.Keys[3].address).sign())
        .take(7)
        .array();
    writefln("Posting settle tx: %s", update_pair.settle_tx.hashFull());
    txs ~= update_pair.settle_tx;

    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(4), network.blocks[0].header);

    Thread.sleep(1.seconds);
}

import agora.consensus.data.Block;
import std.range;
public auto filtSpendable (alias filt)(const ref Block block)
{
    return block.txs
        .filter!(tx => tx.type == TxType.Payment)
        .filter!(tx => filt(tx))
        .map!(tx => iota(tx.outputs.length).map!(idx => TxBuilder(tx, cast(uint)idx)))
        .joiner();
}
