/*******************************************************************************

    Contains lock + unlock script generators for the Eltoo protocol.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.LockScripts;

import agora.consensus.data.Transaction;
import agora.script.Engine;
import agora.script.Lock;
import agora.script.Opcodes;
import agora.script.Script;

import std.bitmanip;

version (unittest)
{
    import agora.common.crypto.ECC;
    import agora.common.crypto.Schnorr;
    import agora.common.Hash;
    import agora.utils.Test;
    import ocean.core.Test;
    import std.stdio : writefln, writeln;  // avoid importing LockType
}

version (unittest)
{
    private const TestStackMaxTotalSize = 16_384;
    private const TestStackMaxItemSize = 512;
}

/*******************************************************************************

    Create an Eltoo lock script based on Figure 2 from the whitepaper.

    Params:
        age = the age constraint for using the settlement keypair
        settle_X = the Schnorr sum of the multi-party public keys for the
                   age-constrained settlement branch
        update_X = the Schnorr sum of the multi-party public keys for the
                   non-constrained update branch

    Returns:
        a lock script which can be unlocked instantly with an update key-pair,
        or with a settlement key-pair if the age constraint of the input
        is satisfied.

*******************************************************************************/

public Lock createLockEltoo (uint age, Point settle_X, Point update_X)
    pure nothrow @safe
{
    /*
        Eltoo whitepaper Figure 2:

        Key pairs must be different for the if/else branch,
        otherwise an attacker could just steal the signature
        and use a different PUSH to evaluate the other branch.

        OP_IF
            <age> OP_CSV
            <pubkey> OP_CHECKSIG
        OP_ELSE
            2 Au Bu 2 OP_CHECKSIG
        OP_ENDIF
    */
    const age_bytes = nativeToLittleEndian(age);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_INPUT_LOCK),
            ubyte(32)] ~ settle_X[] ~ [ubyte(OP.CHECK_SIG),
         ubyte(OP.ELSE),
            ubyte(32)] ~ update_X[] ~ [ubyte(OP.CHECK_SIG),
         ubyte(OP.END_IF)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 2.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockSettleEltoo (Signature sig) pure nothrow @safe
{
    // remember it's LIFO when popping, TRUE goes last
    return Unlock([ubyte(64)] ~ sig[] ~ [ubyte(OP.TRUE)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 2.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockUpdateEltoo (Signature sig) pure nothrow @safe
{
    // remember it's LIFO when popping, FALSE goes last
    return Unlock([ubyte(64)] ~ sig[] ~ [ubyte(OP.FALSE)]);
}

///
unittest
{
    scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
    const Transaction tx;

    const Input input_9 = Input(Hash.init, 0, 9 /* unlock_age */);
    const Input input_10 = Input(Hash.init, 0, 10 /* unlock_age */);

    const Pair kim_settle_kp = Pair.random();
    const Pair kim_update_kp = Pair.random();
    Pair kim_nonce = Pair.random();  // updating w/ each new sig

    const Pair bob_settle_kp = Pair.random();
    const Pair bob_update_kp = Pair.random();
    Pair bob_nonce = Pair.random();  // updating w/ each new sig

    const SX = kim_settle_kp.V + bob_settle_kp.V;
    auto SRX = kim_nonce.V + bob_nonce.V;  // updating w/ each new sig

    // settle sigs (individual & multisig)
    const kim_settle_sig = sign(kim_settle_kp.v, SX, SRX, kim_nonce.v, tx);
    const bob_settle_sig = sign(bob_settle_kp.v, SX, SRX, bob_nonce.v, tx);
    const settle_multi_sig = Sig(SRX,
          Sig.fromBlob(kim_settle_sig).s
        + Sig.fromBlob(bob_settle_sig).s).toBlob();
    assert(verify(SX, settle_multi_sig, tx));

    const UX = kim_update_kp.V + bob_update_kp.V;
    auto URX = kim_nonce.V + bob_nonce.V;  // updating w/ each new sig

    // update sigs (individual & multisig)
    const kim_update_sig = sign(kim_update_kp.v, UX, URX, kim_nonce.v, tx);
    const bob_update_sig = sign(bob_update_kp.v, UX, URX, bob_nonce.v, tx);
    const update_multi_sig = Sig(URX,
          Sig.fromBlob(kim_update_sig).s
        + Sig.fromBlob(bob_update_sig).s).toBlob();
    assert(verify(UX, update_multi_sig, tx));

    // note: technically input 9 and input 10 would be part of separate tx'es
    // and would each require their own signatures. For simplification we
    // base the signature on a static tx
    const age_9 = nativeToLittleEndian(ubyte(9));
    const age_10 = nativeToLittleEndian(ubyte(10));

    Lock lock_9 = createLockEltoo(9, SX, UX);
    Lock lock_10 = createLockEltoo(10, SX, UX);

    // only valid signatures
    Unlock unlock_settle_kp_settle = createUnlockSettleEltoo(settle_multi_sig);
    Unlock unlock_update_kp_update = createUnlockUpdateEltoo(update_multi_sig);

    // invalid: settle kp w/ update branch, and vice-veras
    Unlock unlock_settle_kp_update = createUnlockSettleEltoo(update_multi_sig);
    Unlock unlock_update_kp_settle = createUnlockUpdateEltoo(settle_multi_sig);

    // invalid: partial signatures
    Unlock unlock_update_kp_kim_update = createUnlockUpdateEltoo(kim_update_sig);
    Unlock unlock_update_kp_bob_update = createUnlockUpdateEltoo(bob_update_sig);
    Unlock unlock_settle_kp_kim_settle = createUnlockSettleEltoo(kim_settle_sig);
    Unlock unlock_settle_kp_bob_settle = createUnlockSettleEltoo(bob_settle_sig);

    // update kp may be used for update branch (any age)
    test!("==")(engine.execute(lock_9, unlock_update_kp_update, tx, input_9),
        null);
    test!("==")(engine.execute(lock_9, unlock_update_kp_update, tx, input_10),
        null);
    test!("==")(engine.execute(lock_10, unlock_update_kp_update, tx, input_9),
        null);
    test!("==")(engine.execute(lock_10, unlock_update_kp_update, tx, input_10),
        null);

    // partial sigs disallowed
    test!("==")(engine.execute(lock_9, unlock_update_kp_kim_update, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_9, unlock_update_kp_bob_update, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_kim_settle, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_bob_settle, tx, input_9),
        "Script failed");

    // update kp can't be used for settlement branch
    test!("==")(engine.execute(lock_9, unlock_settle_kp_update, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_update, tx, input_10),
        "Script failed");
    test!("==")(engine.execute(lock_10, unlock_settle_kp_update, tx, input_9),
        "VERIFY_INPUT_LOCK unlock age of input is too low");  // age too low
    test!("==")(engine.execute(lock_10, unlock_settle_kp_update, tx, input_10),
        "Script failed");  // age ok, sig failed

    // settle kp only usable for settle branch (with age check)
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle, tx, input_9),
        null);             // matching age
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle, tx, input_10),
        null);             // 10 > 9, ok
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle, tx, input_9),
        "VERIFY_INPUT_LOCK unlock age of input is too low");  // age too low
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle, tx, input_10),
        null);             // matching age

    // settle kp can't be used for update branch
    test!("==")(engine.execute(lock_9, unlock_update_kp_settle, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_9, unlock_update_kp_settle, tx, input_10),
        "Script failed");
    test!("==")(engine.execute(lock_10, unlock_update_kp_settle, tx, input_9),
        "Script failed");
    test!("==")(engine.execute(lock_10, unlock_update_kp_settle, tx, input_10),
        "Script failed");
}
