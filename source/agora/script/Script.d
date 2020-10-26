/*******************************************************************************

    Contains the script definition and syntactical opcode validation.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Script;

import agora.common.crypto.ECC;
import agora.script.Codes;
import agora.script.Stack;

import ocean.core.Test;

import std.bitmanip;
import std.conv;
import std.range;
import std.traits;

version (unittest)
{
    import agora.common.Hash;
}

/// Ditto
public struct Script
{
    /// opcodes + any associated data for each push opcode
    private const(ubyte)[] data;

    /***************************************************************************

        Returns:
            the byte array of the script

    ***************************************************************************/

    public const(ubyte)[] opSlice () const pure nothrow @safe @nogc
    {
        return this.data[];
    }

    /***************************************************************************

        Validates the script syntactically, but not semantically.
        Each opcode is checked for validity, and any push opcodes have their
        length & payload checked for size constraints.

        The semantics of the script are not checked here. They may only be
        checked by the script execution engine.

        Returns:
            true if the script is syntactically valid

    ***************************************************************************/

    public bool isValidSyntax () const pure nothrow @safe @nogc
    {
        return this.isInvalidSyntaxReason() is null;
    }

    /***************************************************************************

        Ditto, but returns the string reason when the script is
        considered syntactically invalid.

        Returns:
            null if the script is syntactically valid,
            otherwise the string explaining the reason why it's invalid

    ***************************************************************************/

    public string isInvalidSyntaxReason () const pure nothrow @safe @nogc
    {
        const(ubyte)[] bytes = this.data[];
        if (bytes.empty)
            return null;  // empty scripts are syntactically valid

        // todo: add script size checks (based on consensus params)

        while (!bytes.empty())
        {
            OP opcode;
            if (!bytes.front.toOPCode(opcode))
                return "Script contains an unrecognized opcode";

            bytes.popFront();
            switch (opcode)
            {
                case OP.PUSH_DATA_1:
                    if (auto reason = isInvalidPushReason!(OP.PUSH_DATA_1)(bytes))
                        return reason;
                    else break;

                case OP.PUSH_DATA_2:
                    if (auto reason = isInvalidPushReason!(OP.PUSH_DATA_2)(bytes))
                        return reason;
                    else break;

                case OP.PUSH_BYTES_1: .. case OP.PUSH_BYTES_64:
                    const payload_size = opcode;  // encoded in the opcode
                    if (bytes.length < payload_size)
                        return "PUSH_BYTES_* opcode exceeds total script size";

                    bytes.popFrontN(payload_size);
                    break;

                default:
                    break;
            }
        }

        return null;
    }

    /***************************************************************************

        Checks the validity of a `PUSH_DATA_*` opcode and advances
        the `bytes` array if the payload does not exceed the array.

        Params:
            OP = the associated `PUSH_DATA_*` opcode
            bytes = the opcode byte array

        Returns:
            null if the opcode is syntactically valid,
            otherwise the string explaining the reason why it's invalid

    ***************************************************************************/

    private static string isInvalidPushReason (OP op)(ref const(ubyte)[] bytes)
        pure nothrow @safe @nogc
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
}

///
unittest
{
    test!"=="(Script.init.isInvalidSyntaxReason(), null);
    test!"=="(Script([255]).isInvalidSyntaxReason(), "Script contains an unrecognized opcode");
    test!"=="(Script([OP.INVALID]).isInvalidSyntaxReason(), null);  // OP.INVALID is only semantically invalid

    // PUSH_BYTES_*
    test!"=="(Script([1]).isInvalidSyntaxReason(),
        "PUSH_BYTES_* opcode exceeds total script size");
    test!"=="(Script([1, 255]).isInvalidSyntaxReason(), null);  // 1-byte data payload
    test!"=="(Script([2]).isInvalidSyntaxReason(),
        "PUSH_BYTES_* opcode exceeds total script size");
    test!"=="(Script([2, 255]).isInvalidSyntaxReason(),
        "PUSH_BYTES_* opcode exceeds total script size");
    test!"=="(Script([2, 255, 255]).isInvalidSyntaxReason(), null);  // 2-byte data payload
    ubyte[64] payload_64;
    test!"=="(Script([ubyte(64)] ~ payload_64[0 .. 63]).isInvalidSyntaxReason(),
        "PUSH_BYTES_* opcode exceeds total script size");
    test!"=="(Script([ubyte(64)] ~ payload_64).isInvalidSyntaxReason(), null);  // 64-byte data payload

    // PUSH_DATA_*
    const ubyte[2] size_1 = nativeToLittleEndian(ushort(1));
    const ubyte[2] size_max = nativeToLittleEndian(ushort(MAX_STACK_ITEM_SIZE));
    const ubyte[MAX_STACK_ITEM_SIZE] max_payload;
    const ubyte[2] size_overflow = nativeToLittleEndian(
        ushort(MAX_STACK_ITEM_SIZE + 1));

    test!"=="(Script([OP.PUSH_DATA_1]).isInvalidSyntaxReason(),
        "PUSH_DATA_1 opcode requires 1 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_1, 0]).isInvalidSyntaxReason(),
        "PUSH_DATA_1 opcode requires payload size value to be between 1 and 512");
    test!"=="(Script([OP.PUSH_DATA_1, 1]).isInvalidSyntaxReason(),
        "PUSH_DATA_1 opcode payload size exceeds total script size");
    test!"=="(Script([OP.PUSH_DATA_1, 1, 1]).isInvalidSyntaxReason(), null);
    test!"=="(Script([OP.PUSH_DATA_2]).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode requires 2 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_2, 0]).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode requires 2 byte(s) for the payload size");
    test!"=="(Script([OP.PUSH_DATA_2, 0, 0]).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_1).isInvalidSyntaxReason(),
        "PUSH_DATA_2 opcode payload size exceeds total script size");
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_1 ~ [ubyte(1)])
        .isInvalidSyntaxReason(), null);
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_max ~ max_payload)
        .isInvalidSyntaxReason(), null);
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_overflow ~ max_payload)
        .isInvalidSyntaxReason(), "PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_max ~ max_payload ~ OP.HASH)
        .isInvalidSyntaxReason(), null);
    test!"=="(Script(cast(ubyte[])[OP.PUSH_DATA_2] ~ size_max ~ max_payload ~ ubyte(255))
        .isInvalidSyntaxReason(), "Script contains an unrecognized opcode");
}

/*******************************************************************************

    Params:
        key_hash = the key hash to encode in the P2PKH lock script

    Returns:
        a P2PKH lock script which can be unlocked with the matching
        public key & signature

*******************************************************************************/

public Script createLockP2PKH (Hash key_hash) pure nothrow @safe
{
    Script script = { cast(ubyte[])[OP.DUP, OP.HASH]
        ~ [ubyte(64)] ~ key_hash[]
        ~ cast(ubyte[])[OP.VERIFY_EQUAL, OP.CHECK_SIG] };
    return script;
}

/*******************************************************************************

    Params:
        sig = the signature
        pub_key = the public key

    Returns:
        a P2PKH unlock script which can be used with the associated lock script

*******************************************************************************/

public Script createUnlockP2PKH (Signature sig, Point pub_key)
    pure nothrow @safe
{
    Script script = { [ubyte(64)] ~ sig[] ~ [ubyte(32)] ~ pub_key[] };
    return script;
}

///
unittest
{
    import agora.common.crypto.Schnorr;
    import agora.utils.Test;

    Pair kp = Pair.random();
    auto sig = sign(kp, "Hello world");

    const key_hash = hashFull(kp.V);
    Script lock_script = createLockP2PKH(key_hash);
    assert(lock_script.isValidSyntax());

    Script unlock_script = createUnlockP2PKH(sig, kp.V);
    assert(unlock_script.isValidSyntax());
}

/*******************************************************************************

    Creates a locking P2SH script.

    Params:
        redeem_hash = the hash of the redeem script

    Returns:
        a P2SH lock script which can be unlocked with a
        P2SH unlock script with a matching redeem script

*******************************************************************************/

public Script createLockP2SH (Hash redeem_hash) pure nothrow @safe
{
    Script script = { cast(ubyte[])[OP.HASH]
        ~ [ubyte(64)] ~ redeem_hash[]
        ~ cast(ubyte[])[OP.CHECK_EQUAL] };
    return script;
}

/*******************************************************************************

    Params:
        sig = the signature
        redeem = the redeem script

    Returns:
        a P2SH unlock script which can be used with the associated lock script

*******************************************************************************/

public Script createUnlockP2SH (Signature sig, Script redeem) pure nothrow @safe
{
    const bytes = redeem[];
    assert(bytes.length <= MAX_STACK_ITEM_SIZE);
    Script script = { [ubyte(64)] ~ sig[] ~ toPushData(bytes) };
    return script;
}

///
unittest
{
    import agora.common.crypto.Schnorr;
    import agora.utils.Test;

    Pair kp = Pair.random();
    auto sig = sign(kp, "Hello world");

    Script redeem = Script([ubyte(32)] ~ kp.V[] ~ cast(ubyte[])[OP.CHECK_SIG]);
    const redeem_hash = hashFull(redeem);

    Script lock_script = createLockP2SH(redeem_hash);
    assert(lock_script.isValidSyntax());

    Script unlock_script = createUnlockP2SH(sig, redeem);
    assert(unlock_script.isValidSyntax());
}

/*******************************************************************************

    Creates `PUSH_DATA_*` opcodes based on the length of the data.

    Params:
        data = the data to push

    Returns:
        a byte array embeddable in a script

*******************************************************************************/

public ubyte[] toPushData (in ubyte[] data) pure nothrow @safe
{
    assert(data.length <= MAX_STACK_ITEM_SIZE);
    if (data.length > ubyte.max)
    {
        return cast(ubyte[])[OP.PUSH_DATA_2]
            ~ nativeToLittleEndian(cast(ushort)data.length) ~ data;
    }
    else
    {
        return cast(ubyte[])[OP.PUSH_DATA_1, cast(ubyte)data.length] ~ data;
    }
}

///
/*pure @safe nothrow*/ // test!() woes
unittest
{
    import std.array;
    import std.range;
    test!("==")([42].toPushData(), [65, 1, 42]);
    test!("==")(ubyte(42).repeat(255).array.toPushData(),
        [65, 255] ~ 42.repeat(255).array);
    test!("==")(ubyte(42).repeat(500).array.toPushData(),
        [66, 244, 1] ~ 42.repeat(500).array);  // little-endian form
}
