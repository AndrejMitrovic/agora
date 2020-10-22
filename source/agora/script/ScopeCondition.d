/*******************************************************************************

    Keeps track of scopes and their conditions (TRUE or FALSE).
    This struct can be used to implement conditional (IF/ELSE/ENDIF) logic.

    It does this pushing a new scope for each visited `IF` opcode,
    popping a scope for every visited `ENDIF` opcode, and toggling the scope's
    condition for every visited `ELSE` opcode.

    Unlike C-like programming languages, we do not support GOTO and therefore
    may only increment the program counter one instruction at a time.

    This implementation is largely based on Bitcoin's `ConditionStack`,
    as it's the most optimal O(1) solution we can think of.

    Copyright:
        Copyright (c) 2009-2010 Satoshi Nakamoto
        Copyright (c) 2009-2020 The Bitcoin Core developers
        Copyright (c) 2020 BOS Platform Foundation Korea

    License:
        Distributed under the MIT software license, see the accompanying
        file LICENSE or http://www.opensource.org/licenses/mit-license.php.

*******************************************************************************/

module agora.script.ScopeCondition;

/// Ditto
public struct ScopeCondition
{
    /// Current number of scopes
    private uint scope_count;

    /// The scope index at which the earliest FALSE is found, or -1 of none
    private int false_idx = -1;

    /***************************************************************************

        Returns:
            true if there are any scopes left

    ***************************************************************************/

    public bool empty () const pure nothrow @safe @nogc
    {
        return this.scope_count == 0;
    }

    /***************************************************************************

        Returns:
            true if the current scope is in a TRUE condition,
            and there are no earlier FALSE condition scopes.

    ***************************************************************************/

    public bool isTrue () const pure nothrow @safe @nogc
    {
        return !this.empty() && this.false_idx == -1;
    }

    /***************************************************************************

        Push a new scope with the given condition.
        If this is the first scope with a FALSE condition,
        it sets the earliest FALSE scope index to the current scope.

        Params:
            cond = the evaluated condition of a visited IF opcode

    ***************************************************************************/

    public void push (bool cond) nothrow @safe @nogc
    {
        if (!cond && this.false_idx == -1)  // first false condition
            this.false_idx = this.scope_count;

        this.scope_count++;
    }

    /***************************************************************************

        Pops the current scope, and potentially toggles the condition to TRUE
        if the outer scope we entered was the earliest FALSE scope.

        Call this after an `ENDIF` opcode, but check `empty()` first.

    ***************************************************************************/

    public void pop () nothrow @safe @nogc
    {
        assert(this.scope_count > 0);

        if (this.false_idx == this.scope_count - 1)
            this.false_idx = -1;  // earliest false, toggle to true
        this.scope_count--;
    }

    /***************************************************************************

        Toggles the current scope's condition.

        If the current scope's condition is TRUE, set it to FALSE.
        If the current scope's condition is FALSE, it's toggled to TRUE
        only if the earliest FALSE condition is the current scope.

        Call this after an `ELSE` opcode, but check `empty()` first.
        Note that `ScopeCondition` does not handle any dangling / duplicate
        `ELSE` opcodes, this is the client code's responsibility.

    ***************************************************************************/

    public void toggle () nothrow @safe @nogc
    {
        assert(this.scope_count > 0);

        if (this.false_idx == -1)  // all scopes are true, mark earliest false
            this.false_idx = this.scope_count - 1;
        else if (this.false_idx == this.scope_count - 1)
            this.false_idx = -1;  // we're at earliest false scope, toggle to true
    }
}

///
nothrow @safe @nogc unittest
{
    import ocean.core.Test;

    ScopeCondition sc;
    assert(sc.empty());
    assert(!sc.isTrue());

    // IF
    //     DO <- pc
    sc.push(true);
    assert(!sc.empty());
    assert(sc.isTrue());

    // IF
    //     DO
    // ELSE
    //     DO <- pc
    sc.toggle();
    assert(!sc.empty());
    assert(!sc.isTrue());

    // IF
    //     IF
    //         DO <- pc
    //     ENDIF
    //     DO
    // ENDIF
    sc = ScopeCondition.init;
    sc.push(true);
    sc.push(true);
    assert(!sc.empty());
    assert(sc.isTrue());

    // IF
    //     IF
    //         DO
    //     ENDIF
    //     DO  <- pc
    // ENDIF
    sc.pop();
    assert(!sc.empty());
    assert(sc.isTrue());

    // IF
    //     IF
    //         DO
    //     ENDIF
    //     DO
    // ENDIF  <- pc
    sc.pop();
    assert(sc.empty());
    assert(!sc.isTrue());

    // OP_TRUE
    // IF -> true
    //     DO -> executed
    //     OP_0
    //     IF
    //         DO -> skipped
    //         OP_TRUE <- false as previous scope was false
    //         IF
    //             DO -> skipped
    //             OP_TRUE <- false, ditto
    //             IF
    //                 DO -> skipped
    //                 OP_TRUE <- false, ditto
    //                 IF
    //                      DO -> skipped
    //                 ENDIF
    //                 DO -> skipped
    //             ENDIF
    //             DO -> skipped
    //         ENDIF
    //         DO -> skipped
    //     ENDIF
    //     DO -> executed (no false scopes left)
    // ENDIF
    sc = ScopeCondition.init;
    sc.push(true);
    sc.push(false);
    sc.push(true);
    sc.push(true);
    sc.push(false);
    assert(!sc.empty());
    assert(!sc.isTrue());
    sc.pop();
    assert(!sc.empty());
    assert(!sc.isTrue());
    sc.pop();
    assert(!sc.empty());
    assert(!sc.isTrue());
    sc.pop();
    assert(!sc.empty());
    assert(!sc.isTrue());
    sc.pop();
    assert(sc.isTrue());
    sc.pop();
    assert(sc.empty());
    assert(!sc.isTrue());
}
