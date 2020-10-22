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
/// Note that the range between `PUSH_BYTES_1` and `PUSH_BYTES_64` is
/// purposefully reserved to encode a push to the stack between 1 .. 64 bytes,
/// without having to encode it in a separate length byte. 64 was chosen as
/// the upper bound because our signatures are 64 bytes.
/// For pushes of data longer than 64 bytes use the `PUSH_DATA_*` opcodes.
enum OP : ubyte
{
    /// Using this is an error and will invalidate the transaction
    /// Purposefully located first to default OPs to errors.
    INVALID = 0x44,

    /// Pushes False onto the stack
    FALSE = 0x00,

    /// Pushes True onto the stack
    TRUE = 0x45,  // 69

    /// Used to encode small length of data to push to the stack (up to 64 bytes),
    /// may be used with `case PUSH_BYTES_1: .. case PUSH_BYTES_64:` syntax.
    PUSH_BYTES_1 = 0x01,
    PUSH_BYTES_64 = 0x40, // 64 decimal

    /// The next 1 byte contains the number of bytes to push onto the stack
    PUSH_DATA_1 = 0x41,

    /// The next 2 bytes (ushort in LE format) contains the number of bytes to
    /// push onto the stack
    PUSH_DATA_2 = 0x42,

    /// The next 4 bytes (ushort in LE format) contains the number of bytes to
    /// push onto the stack
    RESERVED_PUSH_DATA_3 = 0x43,

    IF = 0x46,
    NOT_IF = 0x47,
    VERIFY_IF = 0x48,
    VERIFY_NOT_IF = 0x49,
    ELSE = 0x50,
    END_IF = 0x51,

    /// Hash the value
    HASH = 0x52,

    /// Duplicate the item on the stack
    DUP,

    /// Checks the stack item is equal to the input value
    //CHECK_EQUAL,

    /// Verifies the stack item is equal to the input value
    VERIFY_EQUAL,

    /// Checks the signature with the given public key,
    /// pushes the result to the stack
    CHECK_SIG,

    /// Encodes a set of web assembly instructions
    WEB_ASM,
}

/*******************************************************************************

    Converts the byte to an opcode,
    or returns false if it's an unrecognized opcode.

    Params:
        opcode = will contain the opcode if it was recognized

    Returns:
        true if the value is a recognized opcode

*******************************************************************************/

public bool toOPCode (ubyte value, out OP opcode) pure nothrow @safe @nogc
{
    switch (value)
    {
        foreach (member; EnumMembers!OP)
        {
            case member:
            {
                opcode = member;
                return true;
            }
        }

        default:
            break;
    }

    if (value >= 1 && value <= 64)  // PUSH_BYTES_1 .. PUSH_BYTES_64
    {
        opcode = cast(OP)value;
        return true;
    }

    return false;
}

///
unittest
{
    OP op;
    assert(0x00.toOPCode(op) && op == OP.FALSE);
    assert(0x52.toOPCode(op) && op == OP.HASH);
    assert(!255.toOPCode(op));
    assert(1.toOPCode(op) && op == OP.PUSH_BYTES_1);
    assert(32.toOPCode(op) && op == cast(OP)32);
    assert(64.toOPCode(op) && op == OP.PUSH_BYTES_64);
}
