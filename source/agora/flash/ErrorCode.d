/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.ErrorCode;

/// All possible error codes for the return value
public enum ErrorCode : ushort
{
    None = 0,

    SettleNotReceived,

    InvalidSequenceID,

    InvalidSignature,

    WrongChannelID,

    DuplicateChannelID,

    InvalidGenesisHash,

    FundingTooLow,

    ChannelNotFunded,
}
