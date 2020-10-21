/*******************************************************************************

    Contains the supported opcodes for the basic execution engine (non-webASM)

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Codes;

import std.traits;

/// The supported opcodes
/// Opcodes named `CHECK_*` push their result to the stack,
/// whereas `VERIFY_*` opcodes invalidate the transaction if the result is false.
/// Can encode up to 255 opcodes (one of which is INVALID).
enum OP : ubyte
{
    /// Using this is an error and will invalidate the transaction
    INVALID,

    /// Hash the value
    HASH,

    /// Duplicate the item on the stack
    //DUP,

    /// Checks the stack item is equal to the input value
    //CHECK_EQUAL,

    /// Verifies the stack item is equal to the input value
    VERIFY_EQUAL,

    /// Checks the signature with the given public key,
    /// pushes the result to the stack
    CHECK_SIG,

    /// The next 1 byte contains the number of bytes to push onto the stack
    PUSH_DATA_1,

    /// The next 2 bytes contains the number of bytes to push onto the stack
    PUSH_DATA_2,
}

/*******************************************************************************

    Converts the byte to an opcode, or OP.INVALID if it's an unrecognized opcode.

    Returns:
        The opcode, or OP.INVALID if the value was an unrecognized opcode.

*******************************************************************************/

public OP toOPCode (ubyte value) pure nothrow @safe @nogc
{
    switch (value)
    {
        foreach (member; EnumMembers!OP)
        {
            case member:
                return member;
        }

        default:
            return OP.INVALID;
    }
}

///
unittest
{
    assert(0.toOPCode() == OP.INVALID);
    assert(1.toOPCode() == OP.HASH);
    assert(255.toOPCode() == OP.INVALID);
}
