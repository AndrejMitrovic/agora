/*******************************************************************************

    Contains the flash Channel definition

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

/// All Flash API return types use `Result` to encode any error code & message
public struct Result (T)
{
    /// The error code, if any
    public const ErrorCode error;

    /// The error message, if any
    public const string message;

    /// The result, only valid if `error != ErrorCode.None`
    public T value;

    /// Ctor when there was no error
    public this (T value)
    {
        this.value = value;
    }

    /// Ctor when there was an error, with optional message
    public this (ErrorCode error, string message = null)
    {
        assert(error != ErrorCode.None);
        this.error = error;
        this.message = message;
    }

    /// For the deserializer, should not be used by any other code
    public this (typeof(this.tupleof) fields, string mod = __MODULE__)
    {
        // precaution
        assert(mod == "agora.common.Serializer", mod);
        this.tupleof[] = fields[];
    }

    public string toString ()
    {
        if (this.error == ErrorCode.None)
            return format("%s", this.value);
        else
            return format("(Code: %s) %s", this.error, this.message);
    }
}

/// The update & settle pair for a given sequence ID
public struct UpdatePair
{
    /// The sequence ID of this slot
    public uint seq_id;

    /// Update tx which spends the trigger tx's outputs and can replace
    /// any previous update containing a lower sequence ID than this one's.
    public Transaction update_tx;

    /// Settle tx which spends from `update_tx` above
    public Transaction settle_tx;
}

///
public struct PublicNonce
{
    public Point settle;
    public Point update;
}

///
public struct PrivateNonce
{
    public Pair settle;
    public Pair update;
}

///
public struct Balance
{
    public Output[] outputs;
}

///
public struct BalanceRequest
{
    ///
    public Balance balance;

    ///
    public PublicNonce peer_nonce;
}

///
public string prettify (T)(T input)
{
    return input.to!string[0 .. 6];
}
