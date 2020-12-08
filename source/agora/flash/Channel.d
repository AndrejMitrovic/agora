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

// todo: limit accepting only one funding UTXO, should not accept the same one
// for multiple channels.
// todo: once we've signed the very first channel accept message for a UTXO,
// never accept it again for opening of a new channel.

// todo: create an example where we use a new update attaching to a settlement
// which immediately refunds everyone. This is a cooperative closing of a channel.

// todo: allocation of Outputs in subsequent updates must equal exactly the
// channel sum amount, otherwise we end up creating fees for no reason.

// todo: invoicing will be needed for the API to work. This is what we can present
// to the clients and libraries. They just need to interact with the Flash node.
// todo: must support QR codes. Such as in https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
// Amount can be optional in the invoice, in case of donations. But perhaps
// a minimum donation limit could be set.
// todo: add a SemVer version field, so compatibility can be easily derived between protocols.

// LN uses <type,length,bytes[length] value> tuplets for all field types, this way
// enabling skipping some fields for future/backwards compatibility.
// We should probably add the protocol descriptor (unique ID) in each message.

// todo: consider just having a single API end-point with the tuplet values.
// todo: should have an init() to initialize any *new* connection to a node.
// it's possible that a user updates its flash node and suddenly becomes incompatible,
// therefore renegotiating the setup is important.

/*
design decisions taken from LN (https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md):

> By default SHA2 and Bitcoin public keys are both encoded as big endian, thus it would be unusual to use a different endian for other fields.
=> We can just use LE

> Length is limited to 65535 bytes by the cryptographic wrapping, and messages in the protocol are never more than that length anyway.
=> This is a good hint. We should check if we can encrypt 64k via Schnorr or if we're reaching
some kind of limit here.
*/

// todo: channel ID should be derived from the UTXO, not from just the hash of the funding tx.
// so we should provide the funding tx and also the output index (?). Hence why we used the
// implicit index 0 in some places, we should explicitly specify it, because the funding tx
// may have more outputs than just 1.

// todo: nodes should signal each other when they have discovered the funding tx in the blockchain.

// todo: maybe the creation of the funding tx should be delayed until the counterparty
// accepts the proposal.

// todo: channel discovery in LN: Only the least-significant bit of channel_flags is currently defined: announce_channel. This indicates whether the initiator of the funding flow wishes to advertise this channel publicly to the network, as detailed within BOLT #7.

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
    private State state;

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

        auto pair = this.signer.run(seq_id, balance, priv_nonce, peer_nonce);
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

        this.signer.clearState();
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

        assert(this.state == State.Open);
        assert(seq_id == this.cur_seq_id + 1);

        this.cur_seq_id++;
        auto update_pair = this.signer.run(this.cur_seq_id, new_balance,
            priv_nonce, peer_nonce);

        writefln("%s: Got new update pair!", this.kp.V.prettify);
        this.signer.clearState();
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
}

/// utility
private T clone (T)(in T input)
{
    return input.serializeFull.deserializeFull!T;
}
