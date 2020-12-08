/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Channel;

import agora.flash.API;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Scripts;
import agora.flash.Signer;
import agora.flash.Types;

import agora.common.crypto.Key;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.script.Lock;

// todo: remove
import std.stdio;

alias LockType = agora.script.Lock.LockType;

/// Tracks the current state of the channel.
/// States can only move forwards, and never back.
/// Once a channel is closed, it may never be re-opened again.
public enum ChannelState
{
    /// Cooperating on the initial trigger and settlement txs.
    Setup,

    /// Waiting for the funding tx to appear in the blockchain.
    WaitingForFunding,

    /// The channel is open and ready for new balance update requests.
    Open,

    /// A channel closure was requested. New balance update requests will
    /// be rejected. For safety reasons, the channel's metadata should be kept
    /// around until the channel's state becomes `Closed`.
    PendingClose,

    /// The funding transaction has been spent and externalized.
    /// This marks the channel as closed.
    /// New channels cannot use the same funding UTXO since it was spent,
    /// therefore it's safe to delete this channel's data when it reaches this
    /// closed state.
    Closed,
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
    public TaskManager taskman;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Current state of the channel
    private ChannelState state;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// The signer for an update / settle pair
    private Signer signer;

    /// The list of any off-chain updates which happened on this channel
    private UpdatePair[] channel_updates;

    /// The current sequence ID
    private uint cur_seq_id;

    /// The current balance of the channel. Initially empty until the
    /// funding tx is externalized.
    private Balance cur_balance;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, FlashAPI peer,
        TaskManager taskman, void delegate (in Transaction) txPublisher)
    {
        this.conf = conf;
        this.kp = kp;
        this.is_owner = conf.funder_pk == kp.V;
        this.peer = peer;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.signer = new Signer(this.conf, this.kp, this.peer, this.taskman);
    }

    ///
    public bool isWaitingForFunding ()
    {
        return this.state == ChannelState.WaitingForFunding;
    }

    ///
    public bool isOpen ()
    {
        return this.state == ChannelState.Open;
    }

    /// Start routine for the channel
    public void start (in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        assert(this.state == ChannelState.Setup);
        assert(this.cur_seq_id == 0);

        // initial output allocates all the funds back to the channel creator
        const seq_id = 0;
        auto balance = Balance([Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))]);

        auto pair = this.signer.collectSignatures(seq_id, balance, priv_nonce,
            peer_nonce);
        this.onSetupComplete(pair);
    }

    public void fundingExternalized (in Transaction tx)
    {
        this.funding_tx_signed = tx.clone();
        if (this.state == ChannelState.WaitingForFunding)
            this.state = ChannelState.Open;

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
            this.state = ChannelState.Open;
        else
            this.state = ChannelState.WaitingForFunding;

        // if we're the funder then it's time to publish the funding tx
        if (this.is_owner)
        {
            this.funding_tx_signed = this.conf.funding_tx.clone();
            this.funding_tx_signed.inputs[0].unlock
                = genKeyUnlock(sign(this.kp, this.conf.funding_tx));

            this.txPublisher(this.funding_tx_signed);
        }

        this.channel_updates ~= update_pair;
    }

    ///
    public Result!Signature requestSettleSig (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID);

        return this.signer.requestSettleSig();
    }

    ///
    public Result!Signature requestUpdateSig (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID);

        return this.signer.requestUpdateSig();
    }

    ///
    public void signUpdate (in uint seq_id, PrivateNonce priv_nonce,
        PublicNonce peer_nonce, in Balance new_balance)
    {
        writefln("%s: signUpdate(%s)", this.kp.V.prettify,
            seq_id);

        assert(this.state == ChannelState.Open);
        assert(seq_id == this.cur_seq_id + 1);

        this.cur_seq_id++;
        auto update_pair = this.signer.collectSignatures(this.cur_seq_id,
            new_balance, priv_nonce, peer_nonce);

        writefln("%s: Got new update pair!", this.kp.V.prettify);
        this.channel_updates ~= update_pair;
        this.cur_balance.outputs = new_balance.outputs.dup;
    }

    public UpdatePair close ()
    {
        assert(this.isOpen());
        this.state = ChannelState.PendingClose;

        // publish the trigger transaction
        return this.channel_updates[0];
    }
}

/// utility
private T clone (T)(in T input)
{
    import agora.common.Serializer;
    return input.serializeFull.deserializeFull!T;
}
