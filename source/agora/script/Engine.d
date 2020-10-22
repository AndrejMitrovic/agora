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

import ocean.core.Test;

/// The engine executes scripts, and returns a value or throws
public class Engine
{
    public string execute (Script lock, Script unlock)
    {
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

        // The unlock script must be ran separately from the lock script

        //Stack stack;
        //if (auto error = this.executeUnlockScript(lock, stack))
        //    return error;

        return null;
    }

    //public string executeUnlockScript
}

///
unittest
{
    //import agora.common.crypto.ECC;
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

    scope engine = new Engine();
    test!("==")(engine.execute(lock_script, unlock_script), null);
}
