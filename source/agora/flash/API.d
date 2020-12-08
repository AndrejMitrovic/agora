/*******************************************************************************

    Contains the Flash API.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.API;

import agora.common.Types;
import agora.flash.Config;
import agora.flash.Types;

/// This is the API that each flash node must implement.
public interface FlashAPI
{
    /***************************************************************************

        Requests opening a channel with this Flash node.

        Params:
            chan_conf = contains all the static configuration for this channel.
            peer_nonce = the nonce pair that will be used for signing the
                initial settlement & trigger transactions

        Returns:
            null if agreed to open this channel, otherwise an error

    ***************************************************************************/

    public Result!PublicNonce openChannel (in ChannelConfig chan_conf,
        PublicNonce peer_nonce);

    /***************************************************************************

        Requests opening a channel with this node.

        Params:
            chan_conf = contains all the static configuration for this channel.

        Returns:
            null if agreed to open this channel, otherwise an error

    ***************************************************************************/

    public Result!PublicNonce requestBalanceUpdate (in Hash chan_id,
        in uint seq_id, in BalanceRequest balance_req);

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

    public Result!Signature requestSettleSig (in Hash chan_id, in uint seq_id);

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

    public Result!Signature requestUpdateSig (in Hash chan_id, in uint seq_id);
}
