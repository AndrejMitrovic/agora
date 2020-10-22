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

/// Maximum total stack size
public enum MAX_STACK_TOTAL_SIZE = 16_384;

/// Maximum size of an item on the stack
public enum MAX_STACK_ITEM_SIZE = 512;

/// Supports pushing and popping arbitrary items from the stack,
/// using the default serializer to store to the internal byte array.
struct Stack
{
    /// The actual stack
    private ubyte[][] stack;

    /// Used stack size
    private size_t used_size;

    /***************************************************************************

        Pushes the value to the stack

    ***************************************************************************/

    public void push (ubyte[] data) @safe nothrow
    {
        assert(data.sizeof <= MAX_STACK_ITEM_SIZE);
        assert(this.used_size + data.length <= MAX_STACK_TOTAL_SIZE);
        this.stack ~= data;
    }

    /***************************************************************************

        Returns:
            the popped value from the stack

    ***************************************************************************/

    public ubyte[] pop () @safe nothrow
    {
        assert(this.stack.length > 0);
        auto value = this.stack.back();
        this.stack.popBackN(T.sizeof);
        () @trusted { this.stack.assumeSafeAppend(); }();
        return value;
    }

    /***************************************************************************

        Returns:
            true if the stack is empty

    ***************************************************************************/

    public bool empty () const pure nothrow @safe @nogc
    {
        return this.stack.length == 0;
    }
}

///
unittest
{
    Stack stack;
    assert(stack.empty());
    stack.push([123]);
    assert(!stack.empty());
    assert(stack.pop() == [123]);
    assert(stack.empty());
}
