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

import ocean.core.Test;

import std.bitmanip;
import std.conv;
import std.range;
import std.traits;

/// Script
public struct Script
{
    /// opcodes + any associated data for each push opcode
    private const(ubyte)[] data;

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
            static assert(op == OP.PUSH_DATA_1 || op == OP.PUSH_DATA_2);
            alias T = Select!(op == OP.PUSH_DATA_1, ubyte, ushort);
            if (bytes.length < T.sizeof)
            {
                static immutable err1 = op.to!string ~ " opcode requires "
                    ~ T.sizeof.to!string ~ " byte(s) for the payload size";
                return err1;
            }

            const T size = littleEndianToNative!T(bytes[0 .. T.sizeof]);
            if (size == 0 || size > MAX_STACK_ITEM_SIZE)
            {
                static immutable err2 = op.to!string
                    ~ " opcode requires payload size value to be between 1 and "
                    ~ MAX_STACK_ITEM_SIZE.to!string;
                return err2;
            }

            bytes.popFrontN(T.sizeof);
            if (bytes.length < size)
            {
                static immutable err3 = op.to!string
                    ~ " opcode payload size exceeds total script size";
                return err3;
            }

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
    test!"=="(Script.init.isInvalidSyntaxReason(), "Script is empty");
    test!"=="(Script([255]).isInvalidSyntaxReason(), "Script contains an invalid opcode");
    test!"=="(Script([OP.INVALID]).isInvalidSyntaxReason(), "Script contains an invalid opcode");
    test!"=="(Script([OP.PUSH_DATA_1]).isInvalidSyntaxReason(), "PUSH_DATA_1 opcode requires 1 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_1, 0]).isInvalidSyntaxReason(), "PUSH_DATA_1 opcode requires payload size value to be between 1 and 512");
    test!"=="(Script([OP.PUSH_DATA_1, 1]).isInvalidSyntaxReason(), "PUSH_DATA_1 opcode payload size exceeds total script size");
    test!"=="(Script([OP.PUSH_DATA_1, 1, 1]).isInvalidSyntaxReason(), null);
    test!"=="(Script([OP.PUSH_DATA_2]).isInvalidSyntaxReason(), "PUSH_DATA_2 opcode requires 2 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_2, 0]).isInvalidSyntaxReason(), "PUSH_DATA_2 opcode requires 2 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_2, 0, 0]).isInvalidSyntaxReason(), "PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");

    const ubyte[2] size_1 = nativeToLittleEndian(ushort(1));
    test!"=="(Script([OP.PUSH_DATA_2, size_1[0], size_1[1]]).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode payload size exceeds total script size");
    test!"=="(Script([OP.PUSH_DATA_2, size_1[0], size_1[1], 1]).isInvalidSyntaxReason(), null);

    const ubyte[2] size_max = nativeToLittleEndian(ushort(MAX_STACK_ITEM_SIZE));
    const ubyte[MAX_STACK_ITEM_SIZE] payload;
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2, size_max[0], size_max[1]] ~ payload).isInvalidSyntaxReason(), null);

    const ubyte[2] size_overflow = nativeToLittleEndian(ushort(MAX_STACK_ITEM_SIZE + 1));
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2, size_overflow[0], size_overflow[1]] ~ payload).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");
}