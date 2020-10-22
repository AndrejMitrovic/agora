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
import agora.script.ScopeCondition;
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

        ScopeCondition sc;
        const(ubyte)[] bytes = unlock[];
        while (!bytes.empty())
        {
            const OP opcode = bytes.front.toOPCode();
            bytes.popFront();

            switch (opcode)
            {
                case OP.PUSH_DATA_1:
                    if (auto reason = pushToStack!(OP.PUSH_DATA_1)(bytes))
                        return reason;
                    else break;

                case OP.PUSH_DATA_2:
                    if (auto reason = pushToStack!(OP.PUSH_DATA_2)(bytes))
                        return reason;
                    else break;

                case OP.PUSH_BYTES_1: .. case OP.PUSH_BYTES_64:
                    const payload_size = opcode;  // encoded in the opcode
                    if (bytes.length < payload_size)
                        assert(0);  // should have been validated

                    stack.push(bytes[0 .. payload_size]);
                    bytes.popFrontN(payload_size);
                    break;

                default:
                    break;
            }
        }

        return null;
    }

    /***************************************************************************

        Reads the length and payload of the associated `PUSH_DATA_*` opcode,
        pushes the payload onto the stack, and advances the `bytes` array
        to the next opcode.

        Params:
            stack = the stack to push the payload to
            bytes = the opcode / data byte array

    ***************************************************************************/

    private static void pushToStack (OP op)(ref Stack stack,
        ref const(ubyte)[] bytes) nothrow @safe /*@nogc*/
    {
        static assert(op == OP.PUSH_DATA_1 || op == OP.PUSH_DATA_2);
        alias T = Select!(op == OP.PUSH_DATA_1, ubyte, ushort);
        if (bytes.length < T.sizeof)
            assert(0);  // script should have been validated

        const T size = littleEndianToNative!T(bytes[0 .. T.sizeof]);
        if (size == 0 || size > MAX_STACK_ITEM_SIZE)
            assert(0);  // ditto

        bytes.popFrontN(T.sizeof);
        if (bytes.length < size)
            assert(0);  // ditto

        stack.push(bytes[0 .. size]);  // push to stack
        bytes.popFrontN(size);  // advance to next opcode
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
