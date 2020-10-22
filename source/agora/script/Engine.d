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
