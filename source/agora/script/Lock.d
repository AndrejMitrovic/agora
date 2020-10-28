/*******************************************************************************

    Contains the Lock / Unlock definitions

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Lock;

/// Contains the Lock, which is a tag and either a Hash or set of opcodes
public struct Lock
{
    /// Specifies the type of lock script
    public LockType type;

    /// May either be a Hash, or a sequence of opcodes
    public const(ubyte)[] bytes;
}

/// Contains the Unlock, which can be a data tuple or a set of push opcodes
public struct Unlock
{
    /// May be: <signature>, <signature, key>, <push opcodes>
    public const(ubyte)[] bytes;
}

/// The output lock types. If the lock is a 64-byte array it's derived
/// to be a hash of a public key. Otherwise the first byte is the lock type.
public enum LockType : ubyte
{
    /// lock is a 64-byte public key, unlock is the signature
    Key = 0x0,

    /// lock is a 64-byte public key hash, unlock is a (sig, key) pair
    KeyHash = 0x01,

    /// lock is a script, unlock may be anything required by the lock script
    Script = 0x2,

    /// lock is a 64-byte hash of a script, unlock is the stack containing
    /// the pushes and the script itself
    ScriptHash = 0x3,
}

/*******************************************************************************

    Converts the byte to an opcode,
    or returns false if it's an unrecognized opcode.

    Params:
        value = the byte containing the opcode
        opcode = will contain the opcode if it was recognized

    Returns:
        true if the value is a recognized opcode

*******************************************************************************/

public bool toLockType (ubyte value, out LockType opcode)
    pure nothrow @safe @nogc
{
    switch (value)
    {
        foreach (member; EnumMembers!LockType)
        {
            case member:
            {
                opcode = member;
                return true;
            }
        }

        default:
            return false;
    }
}

/// Ditto, but assumes the opcode is valid (safe to use after validation)
public LockType toLockType (ubyte value) pure nothrow @safe @nogc
{
    LockType opcode;
    if (!toLockType(value, opcode))
        assert(0);
    return opcode;
}

///
pure nothrow @safe @nogc unittest
{
    LockType lt;
    assert(0x00.toLockType(lt) && lt == LockType.Key);
    assert(0x01.toLockType(lt) && lt == LockType.KeyHash);
    assert(!255.toLockType(lt));
}
