/*******************************************************************************

    Contains the Flash abstract node definition.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Node;

import agora.api.FullNode : FullNodeAPI = API;
import agora.common.Amount;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.flash.API;
import agora.flash.Channel;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.OnionPacket;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.script.Engine;

import vibe.web.rest;

import core.time;
import std.format;
import std.stdio;

/// Ditto
public abstract class FlashNode : FlashAPI
{
    /// Schnorr key-pair belonging to this node
    protected const Pair kp;

    /// Hash of the genesis block
    protected const Hash genesis_hash;

    /// random agora node
    protected FullNodeAPI agora_node;

    /// Execution engine
    protected Engine engine;

    /// for scheduling
    protected TaskManager taskman;

    /// Channels which are pending and not accepted yet.
    /// Once the channel handshake is complete and only after the funding
    /// transaction is externalized, the Channel channel gets promoted
    /// to a Channel with a unique ID derived from the hash of the funding tx.
    protected Channel[Hash] channels;
    protected Channel[][Hash] channels_by_key;

    /// The last read block height.
    protected ulong read_block_height;

    /***************************************************************************

        Get an instance of an Agora client.

        Params:
            address = The address (IPv4, IPv6, hostname) of the Agora node.
            genesis_hash = the hash of the genesis block to use
            taskman = the task manager ot use
            agora_address = IP address of an Agora node to monitor the
                blockchain and publish new on-chain transactions to it.

        Returns:
            the Agora FullNode client

    ***************************************************************************/

    public this (const Pair kp, Hash genesis_hash, TaskManager taskman,
        string agora_address)
    {
        this.genesis_hash = genesis_hash;
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        this.engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        this.kp = kp;
        this.taskman = taskman;
        Duration timeout;
        this.agora_node = this.getAgoraClient(agora_address, timeout);
    }

    /***************************************************************************

        Get an instance of an Agora client.

        Params:
            address = The address (IPv4, IPv6, hostname) of the Agora node.
            timeout = the timeout duration to use for requests.

        Returns:
            the Agora FullNode client

    ***************************************************************************/

    protected FullNodeAPI getAgoraClient (Address address, Duration timeout)
    {
        import vibe.http.client;

        auto settings = new RestInterfaceSettings;
        settings.baseURL = URL(address);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        return new RestInterfaceClient!FullNodeAPI(settings);
    }

    /***************************************************************************

        Get an instance of a Flash client.

        Params:
            address = The address (IPv4, IPv6, hostname) of the Flash node.
            timeout = the timeout duration to use for requests.

        Returns:
            the Flash client

    ***************************************************************************/

    protected FlashAPI getFlashClient (in Point peer_pk, Duration timeout)
    {
        import vibe.http.client;
        import std.conv : to;

        auto settings = new RestInterfaceSettings;
        // todo: this is obviously wrong, need proper connection handling later
        settings.baseURL = URL(peer_pk.to!string);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        return new RestInterfaceClient!FlashAPI(settings);
    }

    /***************************************************************************

        Start monitoring the blockchain for any new externalized blocks.

    ***************************************************************************/

    public void startMonitoring ()
    {
        // todo: 200 msecs is ok only in tests
        // todo: should additionally register as pushBlock() listener
        this.taskman.setTimer(200.msecs, &this.monitorBlockchain, Periodic.Yes);
    }

    /// See `FlashAPI.openChannel`
    public override Result!PublicNonce openChannel (in ChannelConfig chan_conf,
        in PublicNonce peer_nonce)
    {
        // todo: verify `chan_conf.funding_utxo`
        writefln("%s: openChannel()", this.kp.V.prettify);

        if (chan_conf.chan_id in this.channels)
            return Result!PublicNonce(ErrorCode.DuplicateChannelID,
                "There is already an open channel with this ID");

        // todo: move to initialization stage!
        auto peer = this.getFlashClient(chan_conf.funder_pk, Duration.init);

        if (chan_conf.gen_hash != this.genesis_hash)
            return Result!PublicNonce(ErrorCode.InvalidGenesisHash,
                "Unrecognized blockchain genesis hash");

        const min_funding = Amount(1000);
        if (chan_conf.capacity < min_funding)
            return Result!PublicNonce(ErrorCode.FundingTooLow,
                format("Funding amount is too low. Want at least %s", min_funding));

        // todo: re-enable
        version (none)
        {
            const min_settle_time = 5;
            const max_settle_time = 10;
            if (chan_conf.settle_time < min_settle_time ||
                chan_conf.settle_time > max_settle_time)
                return OpenResult("Settle time is not within acceptable limits");
        }

        PrivateNonce priv_nonce = genPrivateNonce();
        auto channel = new Channel(chan_conf, this.kp, priv_nonce, peer_nonce,
            peer, this.engine, this.taskman, &this.agora_node.putTransaction);

        this.channels[chan_conf.chan_id] = channel;

        // todo: simplify
        if (chan_conf.chan_id in this.channels_by_key)
            this.channels_by_key[chan_conf.chan_id] = [channel];
        else
            this.channels_by_key[chan_conf.chan_id] ~= channel;

        PublicNonce pub_nonce = priv_nonce.getPublicNonce();
        return Result!PublicNonce(pub_nonce);
    }

    /// See `FlashAPI.closeChannel`
    public override Result!Point closeChannel (in Hash chan_id,
        in uint seq_id, in Point peer_nonce, in Amount fee )
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestCloseChannel(seq_id, peer_nonce, fee);

        return Result!Point(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.requestCloseSig`
    public override Result!Signature requestCloseSig (in Hash chan_id,
        in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestCloseSig(seq_id);

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.getChannelState`
    public override Result!ChannelState getChannelState (in Hash chan_id)
    {
        if (auto channel = chan_id in this.channels)
            return Result!ChannelState(channel.getState());

        return Result!ChannelState(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.requestSettleSig`
    public override Result!Signature requestSettleSig (in Hash chan_id,
        in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.onRequestSettleSig(seq_id);

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    /// See `FlashAPI.requestUpdateSig`
    public override Result!Signature requestUpdateSig (in Hash chan_id,
        in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.onRequestUpdateSig(seq_id);

        return Result!Signature(ErrorCode.InvalidChannelID,
            "Channel ID not found");
    }

    // incoming API
    public override Result!PublicNonce proposePayment (in Hash chan_id,
        in uint seq_id, in Amount amount, in Hash payment_hash,
        in Height lock_height, in OnionPacket packet, in PublicNonce peer_nonce)
    {
        auto channel = chan_id in this.channels;
        if (channel is null)
            return Result!PublicNonce(ErrorCode.InvalidChannelID,
                "Channel ID not found");

        if (!channel.isOpen())
            return Result!PublicNonce(ErrorCode.ChannelNotOpen,
                "This channel is not funded yet");

        if (channel.isCollectingSignatures())
            return Result!PublicNonce(ErrorCode.SigningInProcess,
                "This channel is still collecting signatures for a "
                ~ "previous sequence ID");

        Payload payload;
        if (!decryptPayload(packet.encrypted_payload, this.kp.v,
            packet.ephemeral_pk, payload,))
        {
            writefln("--- ERROR: CANNOT DECRYPT PAYLOAD");
            return Result!PublicNonce(ErrorCode.CantDecrypt);
        }

        writefln("+++ PAYLOAD IS: %s", payload);

        // Forwarding HTLC. Check balance first.
        // todo: check the owner balance first
        // todo: need to find the next channel ID (if forwarding packet),
        // and check our balance.
        const cur_amount = channel.getOwnerBalance();
        if (cur_amount < amount)
            return Result!PublicNonce(ErrorCode.ExceedsMaximumPayment,
                format("Insufficient funds to route this payment. "
                    ~ "Amount requested: %s. Available: %s. Balance: %s",
                    amount, cur_amount, channel.cur_balance));

        // todo
        version (none)
        if (amount > channel.conf.max_payment_amount)
            return Result!PublicNonce(ErrorCode.ExceedsMaximumPayment,
                "Exceeds maximum payment the node is comfortable routing");

        // TODO: Forward the HTLC to the next channel
        // todo: add some kind of acceptHTLC in the channel here, or
        // begin signing process for that HTLC
        return channel.acceptProposedPayment(seq_id, payment_hash, amount,
            lock_height, payload, peer_nonce, &this.paymentRouter);
    }

    // todo: the node should internally call proposeUpdate() when a new block
    // height is received
    public override Result!PublicNonce proposeUpdate (in Hash chan_id,
        in uint seq_id, in Hash[] secrets, in PublicNonce peer_nonce)
    {
        return Result!PublicNonce.init;
    }

    public void paymentRouter (in Hash chan_id, in Hash payment_hash,
        in Amount amount, in Height lock_height, in OnionPacket packet)
    {
        auto channel = chan_id in this.channels;
        if (channel is null)
        {
            // todo: what to do in this case?
            writefln("Could not find this channel ID: %s", chan_id);
            return;
        }

        channel.routeNewPayment(payment_hash, amount, lock_height,
            packet);
    }

    /***************************************************************************

        Monitors the blockchain for any new externalized blocks.

        If a funding / closing / trigger / update / settlement transaction
        belong to a channel is detected, it will trigger that channel's
        handler for this event.

        This enables changing the channel's state from open to closed.

    ***************************************************************************/

    private void monitorBlockchain ()
    {
        while (1)
        {
            auto latest_height = this.agora_node.getBlockHeight();
            if (this.read_block_height < latest_height)
            {
                auto next_block = this.agora_node.getBlocksFrom(
                    this.read_block_height + 1, 1)[0];

                foreach (channel; this.channels)
                    channel.onBlockExternalized(next_block);

                this.read_block_height++;
            }

            this.taskman.wait(0.msecs);  // yield
        }
    }
}
