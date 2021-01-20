/*******************************************************************************

    Contains the user-facing API used to control the flash node,
    for example creating invoices and paying invoices.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.ControlAPI;

import agora.common.Amount;
import agora.common.crypto.ECC;
import agora.common.Types;
import agora.flash.API;
import agora.flash.Types;

/// Ditto
public interface ControlFlashAPI : FlashAPI
{
    /***************************************************************************

        Start the Flash node. This starts timers which monitor the blockchain
        for any setup / trigger / close transactions which will update the
        internal state machine.

    ***************************************************************************/

    public void start();

    /***************************************************************************

        Begin a collaborative closure of a channel with the counter-party
        for the given channel ID.

        Params:
            chan_id = the ID of the channel to close

    ***************************************************************************/

    public void beginCollaborativeClose (in Hash chan_id);

    /***************************************************************************

        Open a new channel with another flash node.

        Params:
            funding_utxo = the UTXO that will be used to fund the setup tx
            funding_amount = the amount that will be used to fund the setup tx
            settle_time = closing settle time in number of blocks since last
                setup / update tx was published on the blockchain
            peer_pk = the public key of the counter-party flash node

    ***************************************************************************/

    public Hash openNewChannel (in Hash funding_utxo, in Amount funding_amount,
        in uint settle_time, in Point peer_pk);

    /***************************************************************************

        Block the calling fiber until the channel with the given ID becomes
        open. If the channel is already open then it returns immediately.
        The channel is considered open once the setup tx has been
        externalized in the blockchain.

        TODO: does not handle

        Params:
            chan_id = the ID of the channel to wait until it's open

    ***************************************************************************/

    public void waitChannelOpen (in Hash chan_id);

    /***************************************************************************

        Create an invoice that can be paid by another party. A preimage is
        shared through a secure channel to the party which will pay the invoice.
        The hash of the preimage is used in the contract, which is then shared
        across zero or more channel hops. The invoice payer must reveal their
        preimage to proove

        Params:
            chan_id = TODO: this should be the public key of the payer, not
                the channel ID itself (?)
            funder_amount = TODO: replace with just amount
            peer_amount = TODO: remove

    ***************************************************************************/

    public void createInvoice (in Hash chan_id, in Amount funder_amount,
        in Amount peer_amount);
}
