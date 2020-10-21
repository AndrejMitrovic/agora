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

import std.conv;
import std.range;

//
public struct Script
{
    private ubyte[] data;

    // todo: need to iterate over all opcodes
    // when we have a push opcode we need to read the size,
    // and then the data after it, and then we can iterate over it.
    // todo: perhaps use a range for this

    /***************************************************************************

        Validates the script syntactically, but not semantically.
        Each opcode is checked for validity, and any push opcodes have their
        length & payload checked for size constraints.

        The semantics of the script are not checked here. They may only be
        checked by the script execution engine.

    ***************************************************************************/

    public bool isValidSyntax () const nothrow
    {
        if (this.data.length == 0)
            return false;

        auto bytes = this.data;
        while (!bytes.empty())
        {
            //const OP opcode = bytes.front.toOPCode();
            //if (opcode == OP.INVALID)
            //    return false;

            //bytes.popFront();
            //switch (opcode)
            //{
            //    case OP.PUSH_DATA_1:
            //    {
            //        if (bytes.empty)
            //            return false;

            //        const ubyte size = bytes.front;
            //        bytes.popFront();
            //    }

            //    case OP.PUSH_DATA_2:
            //    case OP.PUSH_DATA_4:
            //}
        }

        return true;
    }
}
