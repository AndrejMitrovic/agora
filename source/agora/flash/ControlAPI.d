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

    ///
    public void createInvoice (in Hash chan_id, in Amount funder,
        in Amount peer);
}
