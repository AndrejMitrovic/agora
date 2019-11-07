/*******************************************************************************

    Contains a BitField implementation based on Ocean's BitArray struct.
    The choice of Ocean's over Phobos' implementation of BitArray is
    because the Phobos implementation requires the backing store length to be
    a multiple of size_t, which makes it platform-specific and hard to code for.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.BitField;

import agora.common.Deserializer;
import agora.common.Serializer;

import ocean.core.BitArray;

import std.algorithm;
import std.math;

/// Ditto
struct BitField
{
    /// Bitfield implementation
    public BitArray bit_array;

    /// Expose the bitfield API
    public alias bit_array this;

    /// Backing store (BitArray requires integer arrays)
    private uint[] storage;


    /***************************************************************************

        Constructor

        Params:
            num_bits = the number of bits to be used.

    ***************************************************************************/

    public this ( size_t num_bits ) @trusted
    {
        // BitArray uses ints as storage, we have to use multiples of 32
        this.storage.length = (num_bits + 31) / 32;
        this.bit_array.init(this.storage,
            this.storage.length * uint.sizeof * 8);
    }

    /***************************************************************************

        Serialization. The data is packed tightly by
        removing unused bytes from the uint[] storage,
        and the length of bits is encoded instead of
        the length of bytes.

        Params:
            dg = serialize function accumulator

    ***************************************************************************/

    public void serialize (scope SerializeDg dg) const @trusted
    {
        // cast: BitArray does not support const yet
        const uint bit_length = cast(uint)(cast()this.bit_array).length();
        serializePart(bit_length, dg);

        const byte_length = bit_length / 8;
        foreach (data; (cast(ubyte[])this.storage)[0 .. byte_length])
            serializePart(data, dg);
    }

    /***************************************************************************

        Deserialization.

        Params:
            dg = deserialize function accumulator

    ***************************************************************************/

    public void deserialize (scope DeserializeDg dg) @safe
    {
        uint num_bits;
        deserializePart(num_bits, dg);

        const num_bytes = num_bits / 8;
        ubyte[] bytes;
        bytes.length = num_bytes;

        foreach (ref data; bytes)
            deserializePart(data, dg);

        // the length of the uint[] storage to fit all the bits
        immutable storage_len = (num_bits + 31) / 32;

        // must potentially increase length before casting,
        // to fit ubyte[] => uint[] layout
        bytes.length = storage_len * 4;

        this.storage = cast(uint[])bytes;
        () @trusted { this.bit_array.init(this.storage, num_bits); }();
    }

    /// Custom equality support
    public int opEquals ( in BitField rhs_ ) const nothrow @trusted
    {
        scope (failure) assert(0);  // BitArray lacks nothrow support

        // cast: BitArray does not support const yet
        auto lhs = cast()this.bit_array;
        auto rhs = cast()rhs_.bit_array;
        return lhs.opEquals(rhs);
    }
}

/// opEquals tests
unittest
{
    auto bf1 = BitField(6);
    bf1[0] = true;
    bf1[2] = true;
    bf1[4] = true;

    auto bf2 = bf1;
    assert(bf1 == bf2);

    bf2 = BitField(8);
    assert(bf2 != bf1);

    bf2[0] = true;
    bf2[2] = true;
    bf2[4] = true;
    assert(bf2 == bf1);

    bf2[5] = true;
    assert(bf2 != bf1);
}

/// Serialization tests
unittest
{
    // less than 1 byte
    {
        auto bf = BitField(6);
        bf[0] = bf[5] = true;
        auto bytes = bf.serializeFull();
        assert(bytes.deserializeFull!BitField == bf);
    }

    // exactly 1 byte
    {
        auto bf = BitField(8);
        assert(bf.storage.length == 1);
        bf[0] = bf[7] = true;
        auto bytes = bf.serializeFull();
        assert(bytes.deserializeFull!BitField == bf);
    }

    // more than 1 byte
    {
        auto bf = BitField(12);
        bf[0] = bf[1] = true;
        auto bytes = bf.serializeFull();
        assert(bytes.deserializeFull!BitField == bf);
    }

    // 3 bytes
    {
        auto bf = BitField(28);
        bf[0] = bf[27] = true;
        auto bytes = bf.serializeFull();
        assert(bytes.deserializeFull!BitField == bf);
    }

    // more than 4 bytes (backing store is uint)
    {
        auto bf = BitField(40);
        bf[0] = bf[39] = true;
        auto bytes = bf.serializeFull();
        assert(bytes.deserializeFull!BitField == bf);
    }
}
