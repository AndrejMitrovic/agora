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

import std.container : SList;
import std.range;

version (unittest)
{
    import std.stdio;
}

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
    private SList!(const(ubyte)[]) stack;

    /// The number of items on the stack
    private ulong num_items;

    /// Total used bytes for this stack
    private size_t used_bytes;

    /***************************************************************************

        Pushes the value to the stack

    ***************************************************************************/

    public void push (const(ubyte)[] data) @safe nothrow
    {
        assert(data.sizeof <= MAX_STACK_ITEM_SIZE);
        assert(this.used_bytes + data.length <= MAX_STACK_TOTAL_SIZE);
        this.stack.insertFront(data);
        this.num_items++;
    }

    /***************************************************************************

        Returns:
            the top item on the stack, without popping it

    ***************************************************************************/

    public const(ubyte)[] peek () @safe nothrow
    {
        assert(!this.stack.empty());
        return this.stack.front();
    }

    /***************************************************************************

        Returns:
            the popped value from the stack

    ***************************************************************************/

    public const(ubyte)[] pop () @safe nothrow
    {
        assert(!this.stack.empty());
        assert(this.num_items > 0);
        auto value = this.stack.front();
        this.stack.removeFront();
        this.num_items--;
        return value;
    }

    /***************************************************************************

        Get the number of items on the stack. Explicitly typed as ulong to
        avoid introducing platform-dependent behavior.

        Returns:
            the number of items on the stack

    ***************************************************************************/

    public ulong count () const pure nothrow @safe @nogc
    {
        return this.num_items;
    }

    /***************************************************************************

        Returns:
            true if the stack is empty

    ***************************************************************************/

    public bool empty () const pure nothrow @safe @nogc
    {
        return this.stack.empty();
    }

    /***************************************************************************

        Returns:
            a range over the stack items, from top to bottom

    ***************************************************************************/

    public auto opSlice () /*const @nogc*/ pure nothrow @safe
    {
        return this.stack[];
    }
}

///
//@safe nothrow
unittest
{
    import std.array;
    Stack stack;
    assert(stack.empty());
    assert(stack.count() == 0);
    stack.push([123]);
    assert(stack.count() == 1);
    stack.push([255]);
    assert(stack.count() == 2);
    assert(stack.peek() == [255]);
    assert(stack.count() == 2);     // did not consume
    assert(stack.peek() == [255]);  // ditto
    assert(stack[].array == [[255], [123]]);
    assert(!stack.empty());
    assert(stack.pop() == [255]);
    assert(stack.count() == 1);
    assert(!stack.empty());
    assert(stack.pop() == [123]);
    assert(stack.count() == 0);
    assert(stack.empty());
}
