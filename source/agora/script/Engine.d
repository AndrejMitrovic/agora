/*******************************************************************************

    Contains the script execution engine (non-webASM)

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Engine;

import agora.script.Codes;
import agora.script.Script;
import agora.script.Stack;

import ocean.core.Test;

import std.range;

/// The engine executes scripts, and returns a value or throws
public class Engine
{
    public string execute (in Script lock, in Script unlock)
    {
        if (auto error = lock.isInvalidSyntaxReason())
            return "Lock script error: " ~ error;

        if (auto error = unlock.isInvalidSyntaxReason())
            return "Unlock script error: " ~ error;

        // todo: check script weight:
        // - max opcode length
        // - num of opcodes
        // - weight of each opcode (e.g. sig checks more expensive than ADD)
        // might want to calculate the weight in an out parameter in
        // isInvalidSyntaxReason()

        // todo: check *executed* instructions and that they don't
        // go over the configured (consensus) limit

        // non-standard scripts (meaning non-recognized ones with unexpected opcodes)
        // are not relayed to the network, even though they are technically valid.
        // see: https://bitcoin.stackexchange.com/questions/73728/why-can-non-standard-transactions-be-mined-but-not-relayed/
        // however this only makes sense in the scope of PoW. If a miner did spend
        // the time to mine a block, then the time they spent on running the contract
        // can be verified not to DDoS the system.

        // for the locking script the rule is:
        // valid only if there is one element on the stack: 1
        // invalid if: stack is empty, top element is not 1,
        // there is more than 1 element on the stack,
        // the script exits prematurely
        // for the unlocking script we have different validation rules.

        // the unlock script must be ran separately from the lock script
        // to avoid a form of vulnerability:
        // https://bitcoin.stackexchange.com/q/80258/93682

        Stack stack;
        if (auto error = this.executeUnlockScript(unlock, stack))
            return error;

        return null;
    }

    public string executeUnlockScript (in Script unlock, out Stack stack)
    {
        const(ubyte)[] opcodes = unlock[];

        // for a description on how code flow control works,
        // see: https://building-on-bitcoin.com/docs/slides/Thomas_Kerin_BoB_2018.pdf

        // if *any* items are false, then the current execution
        // state is false, and we continue executing next
        // instructions. however the fExec level is set to false,
        // until an ELSE or ENDIF sets it to true (I think),
        // and then we can execute code again.

        // essentially:
        // pc -> IF
        // pc ->    DO  // exec if fExec is 1
        // pc ->    DO  // exec if fExec is 1
        // pc -> ELSE   // toggles fExec
        // pc ->    DO  // exec if fExec is 1
        // pc ->    DO  // exec if fExec is 1
        // pc -> ENDIF
        //
        // unlike in C-like programming languages, there are no goto's and
        // we may only increment the program counter by 1

        // todo: verify stack data pushes via CheckMinimalPush(),
        // it seems it's related to BIP62 where pushes can be
        // encoded in different ways. Note: BIP141 (segwit)
        // largely replaces BIP62, so we may not require
        // the validation in CheckMinimalPush(). It is likely
        // still there for compatibility reasons.

        // todo: check max stack size
        // todo: do not implement alt stack, it's unnecessary

        // todo: do not add any more support other than the bare
        // minimum for script validation. e.g. don't add OP_ADD support
        // because this requires emulating a specific virtual machine
        // platform which handles integer arithmetic the same on all platforms.

        //while (!opcodes.empty())
        //{

        //}

        return null;
    }
}

///
unittest
{
    import agora.common.crypto.ECC;
    import agora.common.crypto.Schnorr;
    import agora.common.Hash;
    import agora.utils.Test;

    Pair kp = Pair.random();
    auto sig = sign(kp, "Hello world");

    const key_hash = hashFull(kp.V);
    Script lock_script = createLockP2PKH(key_hash);
    assert(lock_script.isValidSyntax());

    Script unlock_script = createUnlockP2PKH(sig, kp.V);
    assert(unlock_script.isValidSyntax());

    const invalid_script = Script([255]);
    scope engine = new Engine();
    test!("==")(engine.execute(invalid_script, unlock_script),
        "Lock script error: Script contains an unrecognized opcode");
    test!("==")(engine.execute(lock_script, invalid_script),
        "Unlock script error: Script contains an unrecognized opcode");
    //test!("==")(engine.execute(lock_script, unlock_script), null);
}

/*******************************************************************************

    Keeps track of scopes and their conditions (TRUE or FALSE).

    Unlike C-like programming languages, we do not support GOTO and therefore
    may only increment the program counter 1 instruction at a time.
    This struct can be used to implement conditional (IF/ELSE/ENDIF) logic.

    It does this pushing a new scope for each visited `IF` opcode,
    popping a scope for every visited `ENDIF` opcode, and toggling the scope's
    condition for every visited `ELSE` opcode.

    This implementation is largely based on Bitcoin's `ConditionStack`,
    as it's the most optimal O(1) solution we can think of.

    Copyright:
        Copyright (c) 2009-2010 Satoshi Nakamoto
        Copyright (c) 2009-2020 The Bitcoin Core developers

    License:
        Distributed under the MIT software license, see the accompanying
        file COPYING or http://www.opensource.org/licenses/mit-license.php.

*******************************************************************************/

struct ConditionScope
{
    /// Current number of scopes
    private uint scope_count;

    /// The scope index at which the earliest FALSE is found, or -1 of none
    private int false_idx = -1;

    /***************************************************************************

        Returns:
            true if there are any scopes left

    ***************************************************************************/

    public bool empty ()
    {
        return this.scope_count == 0;
    }

    /***************************************************************************

        Returns:
            true if the current scope is in an executable state
            (condition is TRUE and there are no earlier FALSE conditions)

    ***************************************************************************/

    public bool mayExecute ()
    {
        return this.false_idx == -1;
    }

    /***************************************************************************

        Push a new scope with the given condition
        If this is the first scope with a FALSE condition,
        it sets the earliest FALSE scope index to the current scope.

        Params:
            cond = the evaluated condition of a visited IF opcode

    ***************************************************************************/

    public void push (bool cond)
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

    public void pop ()
    {
        assert(this.scope_count > 0);

        if (this.false_idx == this.scope_count - 1)  // earliest false, toggle to true
            this.false_idx = -1;
        this.scope_count--;
    }

    /***************************************************************************

        Toggles the current scope's condition.

        If the current scope's condition is TRUE, set it to FALSE.
        If the current scope's condition is FALSE, it's toggled to TRUE
        only if the earliest FALSE condition is the current scope.

        Call this after an `ELSE` opcode, but check `empty()` first.

    ***************************************************************************/

    public void toggle ()
    {
        assert(this.scope_count > 0);

        if (this.false_idx == -1)  // all scopes are true, mark earliest false
            this.false_idx = this.scope_count - 1;
        else if (this.false_idx == this.scope_count - 1)
            this.false_idx = -1;  // we're at earliest false scope, toggle to true
    }
}
