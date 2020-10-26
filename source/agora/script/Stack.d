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
    import ocean.core.Test;
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
    In addition, it makes it very cheap to copy the stack as all internal
    items are immutable anyway.

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
        this.used_bytes += data.length;
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
        this.used_bytes -= value.length;
        this.num_items--;
        return value;
    }

    /***************************************************************************

        Returns:
            the number of bytes used by this stack

    ***************************************************************************/

    public ulong usedBytes () const pure nothrow @safe @nogc
    {
        return this.used_bytes;
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

    /// SList uses reference semantics by default. For the user to either use
    /// `ref` or to explicitly copy the stack via `copy()`.
    public @disable this(this);

    /***************************************************************************

        Returns:
            a copy of the stack. The two stacks may then be modified
            independently of each other. Items may not be modified as
            they're immutable, making the stack safe.

    ***************************************************************************/

    public Stack copy () /*const @nogc*/ pure nothrow @safe
    {
        auto dup = Stack(this.tupleof);
        dup.stack = dup.stack.dup();  // must dup to avoid ref semantics
        return dup;
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
    assert(stack.usedBytes() == 0);
    stack.push([1, 2, 3]);
    assert(stack.count() == 1);
    test!"=="(stack.usedBytes(), 3);
    stack.push([255]);
    assert(stack.count() == 2);
    test!"=="(stack.usedBytes(), 4);
    assert(stack.peek() == [255]);
    assert(stack.count() == 2);     // did not consume
    assert(stack.peek() == [255]);  // ditto
    assert(stack[].array == [[255], [1, 2, 3]]);
    assert(!stack.empty());
    // copies disabled: either use 'ref' or explicitly do a 'copy()'
    static assert(!is(typeof( { Stack nogo = stack; } )));
    Stack copy = stack.copy();
    assert(stack.pop() == [255]);
    assert(stack.count() == 1);
    test!"=="(stack.usedBytes(), 3);
    assert(!stack.empty());
    assert(stack.pop() == [1, 2, 3]);
    assert(stack.count() == 0);
    test!"=="(stack.usedBytes(), 0);
    assert(stack.empty());
    assert(copy.count() == 2);     // did not consume copy
    assert(copy.usedBytes() == 4); // ditto
    assert(!copy.empty());         // ditto
}
