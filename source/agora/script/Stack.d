/*******************************************************************************

    Contains a stack implementation for use with the script execution engine.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Stack;

import agora.common.Serializer;

import std.range;

/// Maximum stack size
public enum MAX_STACK_SIZE = 16_384;

/// Maximum size of an item on the stack
public enum MAX_STACK_ITEM_SIZE = 512;

/// Supports pushing and popping arbitrary items from the stack,
/// using the default serializer to store to the internal byte array.
struct Stack
{
    /// The actual stack
    private ubyte[] stack;

    /***************************************************************************

        Pushes the value to the stack

    ***************************************************************************/

    public void push (T)(auto const ref T value) @safe
    {
        assert(T.sizeof <= MAX_STACK_ITEM_SIZE);
        assert(this.stack.length + T.sizeof <= MAX_STACK_SIZE);
        this.stack ~= value.serializeFull;
    }

    /***************************************************************************

        Returns:
            the popped item from the stack

    ***************************************************************************/

    public T pop (T)() @safe
    {
        assert(this.stack.length >= T.sizeof);

        auto data = this.stack[$ - T.sizeof .. $];
        auto value = data.deserializeFull!T;
        this.stack.popBackN(T.sizeof);
        () @trusted { this.stack.assumeSafeAppend(); }();
        return value;
    }

    /***************************************************************************

        Returns:
            true if the stack is empty

    ***************************************************************************/

    public bool empty () @safe @nogc pure const
    {
        return this.stack.length == 0;
    }
}

///
unittest
{
    Stack stack;
    assert(stack.empty());
    stack.push!int(42);
    assert(!stack.empty());
    assert(stack.pop!int() == 42);
    assert(stack.empty());
}
