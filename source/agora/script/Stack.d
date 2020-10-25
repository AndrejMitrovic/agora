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

import std.container : DList;
import std.range;

/// Maximum total stack size
public enum MAX_STACK_TOTAL_SIZE = 16_384;

/// Maximum size of an item on the stack
public enum MAX_STACK_ITEM_SIZE = 512;

/*******************************************************************************

    Uses a linked-list rather than a vector to avoid unnecessary copying
    due to stomping prevention as the same item may be popped and later pushed
    to the stack.

*******************************************************************************/

public struct Stack
{
    /// The actual stack
    private DList!(const(ubyte)[]) stack;

    /// Used stack size
    private size_t used_size;

    /***************************************************************************

        Pushes the value to the stack

    ***************************************************************************/

    public void push (const(ubyte)[] data) @safe nothrow
    {
        assert(data.sizeof <= MAX_STACK_ITEM_SIZE);
        assert(this.used_size + data.length <= MAX_STACK_TOTAL_SIZE);
        this.stack.insertBack(data);
    }

    /***************************************************************************

        Returns:
            the popped value from the stack

    ***************************************************************************/

    public const(ubyte)[] pop () @safe nothrow
    {
        assert(!this.stack.empty());
        auto value = this.stack.back();
        this.stack.removeBack();
        return value;
    }

    /***************************************************************************

        Returns:
            true if the stack is empty

    ***************************************************************************/

    public bool empty () const pure nothrow @safe @nogc
    {
        return this.stack.empty();
    }
}

///
@safe nothrow unittest
{
    Stack stack;
    assert(stack.empty());
    stack.push([123]);
    stack.push([255]);
    assert(!stack.empty());
    assert(stack.pop() == [255]);
    assert(!stack.empty());
    assert(stack.pop() == [123]);
    assert(stack.empty());
}
