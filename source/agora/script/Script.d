/*******************************************************************************

    Contains the script execution engine (non-webASM)

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Script;

import agora.script.Codes;
import agora.script.Stack;

import std.bitmanip;
import std.conv;
import std.range;
import std.traits;

/// Script
public struct Script
{
    /// opcodes + any associated data for each push opcode
    private ubyte[] data;

    /***************************************************************************

        Validates the script syntactically, but not semantically.
        Each opcode is checked for validity, and any push opcodes have their
        length & payload checked for size constraints.

        The semantics of the script are not checked here. They may only be
        checked by the script execution engine.

    ***************************************************************************/

    public bool isValidSyntax () const nothrow pure @safe @nogc
    {
        return this.isInvalidSyntaxReason() is null;
    }

    /***************************************************************************

        Ditto, but returns the string reason when the script is
        considered syntactically invalid.

    ***************************************************************************/

    public string isInvalidSyntaxReason () const nothrow pure @safe @nogc
    {
        const(ubyte)[] bytes = this.data[];
        if (bytes.empty)
            return "Script is empty";

        string isInvalidPushReason (OP op)()
        {
            alias T = Select!(op == OP.PUSH_DATA_1, ubyte, ushort);

            if (bytes.length < T.sizeof)
                return op.stringof ~ " requires "
                    ~ T.sizeof.stringof ~ " bytes for the size";

            const T size = littleEndianToNative!T(bytes[0 .. T.sizeof]);
            if (size == 0 || size > MAX_STACK_ITEM_SIZE)
                return op.stringof ~ " requires size value between 1 and " ~
                    MAX_STACK_ITEM_SIZE.stringof;

            bytes.popFrontN(T.sizeof);
            if (bytes.length < size)
                return op.stringof ~ " size value exceeds script size";

            bytes.popFrontN(size);
            return null;
        }

        while (!bytes.empty())
        {
            const OP opcode = bytes.front.toOPCode();
            if (opcode == OP.INVALID)
                return "Script contains an invalid opcode";

            bytes.popFront();
            switch (opcode)
            {
                case OP.PUSH_DATA_1:
                    if (auto reason = isInvalidPushReason!(OP.PUSH_DATA_1))
                        return reason;
                    else break;

                case OP.PUSH_DATA_2:
                    if (auto reason = isInvalidPushReason!(OP.PUSH_DATA_2))
                        return reason;
                    else break;

                default:
                    break;
            }
        }

        return null;
    }
}

///
unittest
{
    assert(!Script.init.isValidSyntax());
    assert(!Script([255]).isValidSyntax());
    assert(!Script([OP.INVALID]).isValidSyntax());
    assert(!Script([OP.PUSH_DATA_1]).isValidSyntax());
    assert(!Script([OP.PUSH_DATA_1, 0]).isValidSyntax());
    assert(!Script([OP.PUSH_DATA_1, 1]).isValidSyntax());
    assert(Script([OP.PUSH_DATA_1, 1, 1]).isValidSyntax());
}
