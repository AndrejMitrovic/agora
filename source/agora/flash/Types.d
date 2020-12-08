/*******************************************************************************

    Contains the common types used by the Flash node and the API,
    as well as some helper types.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Types;

import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.flash.ErrorCode;

import std.conv;
import std.format;

/*******************************************************************************

    Embeds a return value for an API as well as any error code and
    an optional message.

    Params:
        T = the type stored as the `value` field

*******************************************************************************/

public struct Result (T)
{
    /// The error code, if any
    public const ErrorCode error;

    /// The error message, if any
    public const string message;

    /// The result, only valid if `error != ErrorCode.None`
    public T value;

    /***************************************************************************

        Ctor when there was no error

        Params:
            value = value to store

    ***************************************************************************/

    public this (T value)
    {
        this.value = value;
    }

    /***************************************************************************

        Ctor when there was an error, with an optional message.

        Params:
            error = the error code. Must not be `ErrorCode.None`
            message = optional message.

    ***************************************************************************/

    public this (ErrorCode error, string message = null)
    {
        assert(error != ErrorCode.None);
        this.error = error;
        this.message = message;
    }

    // For the deserializer, should not be used by any other code
    public this (typeof(this.tupleof) fields, string mod = __MODULE__)
    {
        // precaution
        assert(mod == "agora.common.Serializer", mod);
        this.tupleof[] = fields[];
    }

    /// Convenience
    public string toString ()
    {
        if (this.error == ErrorCode.None)
            return format("%s", this.value);
        else
            return format("(Code: %s) %s", this.error, this.message);
    }
}

/// The settle & update pair for a given sequence ID
public struct UpdatePair
{
    /// The sequence ID of this slot
    public uint seq_id;

    /// Settle tx which spends from `update_tx` below
    public Transaction settle_tx;

    /// Update tx which spends the trigger tx's outputs and can replace
    /// any previous update containing a lower sequence ID than this one's.
    public Transaction update_tx;
}

/// A pair of settlement and update public nonces used for signing
public struct PublicNonce
{
    ///
    public Point settle;

    ///
    public Point update;
}

/// A pair of settlement and update private nonces used for signing.
/// This must be kept secret.
public struct PrivateNonce
{
    ///
    public Pair settle;

    ///
    public Pair update;
}

/// Contains the balance towards each channel participant
public struct Balance
{
    ///
    public Output[] outputs;
}

/// A request for a new balance which also contains the senders's public
/// nonce pair which they promise to use for signing the settle & update txs.
public struct BalanceRequest
{
    ///
    public Balance balance;

    ///
    public PublicNonce peer_nonce;
}

/// Helper routine
public string prettify (T)(T input)
{
    return input.to!string[0 .. 6];
}
