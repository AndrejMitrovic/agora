/*******************************************************************************

    Contains lock + unlock script generators for the Eltoo protocol.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.OnChainScripts;

import agora.consensus.data.Transaction;
import agora.script.Engine;
import agora.script.Lock;
import agora.script.Opcodes;
import agora.script.Signature;
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
    // reasonable defaults
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

        Differences to whitepaper:
        - we use naive schnorr multisig for simplicity
        - we use VERIFY_SIG rather than CHECK_SIG, it improves testing
          reliability by ensuring the right failure reason is emitted.
          We manually push OP.TRUE to the stack after the verify.

        OP.IF
            <age> OP.VERIFY_INPUT_LOCK
            <settle_pub_multi> OP.VERIFY_SIG OP.TRUE
        OP.ELSE
            <update_pub_multi> OP.VERIFY_SIG OP.TRUE
        OP.END_IF
    */
    const age_bytes = nativeToLittleEndian(age);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_INPUT_LOCK),
            ubyte(32)] ~ settle_X[] ~ [ubyte(OP.VERIFY_SIG), ubyte(OP.TRUE),
         ubyte(OP.ELSE),
            ubyte(32)] ~ update_X[] ~ [ubyte(OP.VERIFY_SIG), ubyte(OP.TRUE),
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
    return Unlock([ubyte(65)] ~ sig[] ~ [ubyte(SigHash.All)]
        ~ [ubyte(OP.TRUE)]);
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
    return Unlock([ubyte(65)] ~ sig[] ~ [ubyte(SigHash.All)]
        ~ [ubyte(OP.FALSE)]);
}

///
unittest
{
    scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);

    const Input input_9 = Input(Hash.init, 0, 9 /* unlock_age */);
    const Transaction tx_9 = { inputs : [input_9] };
    const challenge_9 = getChallenge(tx_9, SigHash.All, 0);

    const Input input_10 = Input(Hash.init, 0, 10 /* unlock_age */);
    const Transaction tx_10 = { inputs : [input_10] };
    const challenge_10 = getChallenge(tx_10, SigHash.All, 0);

    const Pair kim_settle_kp = Pair.random();
    const Pair kim_update_kp = Pair.random();
    Pair kim_nonce = Pair.random();

    const Pair bob_settle_kp = Pair.random();
    const Pair bob_update_kp = Pair.random();
    Pair bob_nonce = Pair.random();

    // settle sigs for lock 9 (individual & multisig)
    const SX = kim_settle_kp.V + bob_settle_kp.V;
    auto SRX = kim_nonce.V + bob_nonce.V;
    const kim_settle_sig_9 = sign(kim_settle_kp.v, SX, SRX, kim_nonce.v,
        challenge_9);
    const bob_settle_sig_9 = sign(bob_settle_kp.v, SX, SRX, bob_nonce.v,
        challenge_9);
    const settle_multi_sig_9 = Sig(SRX,
          Sig.fromBlob(kim_settle_sig_9).s
        + Sig.fromBlob(bob_settle_sig_9).s).toBlob();
    assert(verify(SX, settle_multi_sig_9, challenge_9));

    // settle sigs for lock 10 (individual & multisig)
    const kim_settle_sig_10 = sign(kim_settle_kp.v, SX, SRX, kim_nonce.v,
        challenge_10);
    const bob_settle_sig_10 = sign(bob_settle_kp.v, SX, SRX, bob_nonce.v,
        challenge_10);
    const settle_multi_sig_10 = Sig(SRX,
          Sig.fromBlob(kim_settle_sig_10).s
        + Sig.fromBlob(bob_settle_sig_10).s).toBlob();
    assert(verify(SX, settle_multi_sig_10, challenge_10));

    // update sigs for lock 9 (individual & multisig)
    const UX = kim_update_kp.V + bob_update_kp.V;
    auto URX = kim_nonce.V + bob_nonce.V;
    const kim_update_sig_9 = sign(kim_update_kp.v, UX, URX, kim_nonce.v,
        challenge_9);
    const bob_update_sig_9 = sign(bob_update_kp.v, UX, URX, bob_nonce.v,
        challenge_9);
    const update_multi_sig_9 = Sig(URX,
          Sig.fromBlob(kim_update_sig_9).s
        + Sig.fromBlob(bob_update_sig_9).s).toBlob();
    assert(verify(UX, update_multi_sig_9, challenge_9));

    // update sigs for lock 10 (individual & multisig)
    const kim_update_sig_10 = sign(kim_update_kp.v, UX, URX, kim_nonce.v,
        challenge_10);
    const bob_update_sig_10 = sign(bob_update_kp.v, UX, URX, bob_nonce.v,
        challenge_10);
    const update_multi_sig_10 = Sig(URX,
          Sig.fromBlob(kim_update_sig_10).s
        + Sig.fromBlob(bob_update_sig_10).s).toBlob();
    assert(verify(UX, update_multi_sig_10, challenge_10));

    Lock lock_9 = createLockEltoo(9, SX, UX);
    Lock lock_10 = createLockEltoo(10, SX, UX);

    // only valid signatures, for lock 9
    Unlock unlock_settle_kp_settle_9 = createUnlockSettleEltoo(settle_multi_sig_9);
    Unlock unlock_update_kp_update_9 = createUnlockUpdateEltoo(update_multi_sig_9);

    // only valid signatures, for lock 10
    Unlock unlock_settle_kp_settle_10 = createUnlockSettleEltoo(settle_multi_sig_10);
    Unlock unlock_update_kp_update_10 = createUnlockUpdateEltoo(update_multi_sig_10);

    // invalid: settle kp w/ update branch, and vice-veras
    Unlock unlock_settle_kp_update_9 = createUnlockSettleEltoo(update_multi_sig_9);
    Unlock unlock_update_kp_settle_9 = createUnlockUpdateEltoo(settle_multi_sig_9);
    Unlock unlock_settle_kp_update_10 = createUnlockSettleEltoo(update_multi_sig_10);
    Unlock unlock_update_kp_settle_10 = createUnlockUpdateEltoo(settle_multi_sig_10);

    // invalid: partial signatures
    Unlock unlock_update_kp_kim_update_9 = createUnlockUpdateEltoo(kim_update_sig_9);
    Unlock unlock_update_kp_bob_update_9 = createUnlockUpdateEltoo(bob_update_sig_9);
    Unlock unlock_settle_kp_kim_settle_9 = createUnlockSettleEltoo(kim_settle_sig_9);
    Unlock unlock_settle_kp_bob_settle_9 = createUnlockSettleEltoo(bob_settle_sig_9);
    Unlock unlock_update_kp_kim_update_10 = createUnlockUpdateEltoo(kim_update_sig_10);
    Unlock unlock_update_kp_bob_update_10 = createUnlockUpdateEltoo(bob_update_sig_10);
    Unlock unlock_settle_kp_kim_settle_10 = createUnlockSettleEltoo(kim_settle_sig_10);
    Unlock unlock_settle_kp_bob_settle_10 = createUnlockSettleEltoo(bob_settle_sig_10);

    // update kp may be used for update branch (any age)
    test!("==")(engine.execute(lock_9, unlock_update_kp_update_9, tx_9, input_9),
        null);
    test!("==")(engine.execute(lock_9, unlock_update_kp_update_10, tx_10, input_10),
        null);
    test!("==")(engine.execute(lock_10, unlock_update_kp_update_9, tx_9, input_9),
        null);
    test!("==")(engine.execute(lock_10, unlock_update_kp_update_10, tx_10, input_10),
        null);

    // ditto but wrong signature used
    test!("==")(engine.execute(lock_9, unlock_update_kp_update_10, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_update_kp_update_9, tx_10, input_10),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_update_kp_update_10, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_update_kp_update_9, tx_10, input_10),
        "VERIFY_SIG signature failed validation");

    // partial sigs disallowed
    test!("==")(engine.execute(lock_9, unlock_update_kp_kim_update_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_update_kp_bob_update_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_kim_settle_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_bob_settle_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");

    // update kp can't be used for settlement branch
    test!("==")(engine.execute(lock_9, unlock_settle_kp_update_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_update_10, tx_10, input_10),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_settle_kp_update_9, tx_9, input_9),
        "VERIFY_INPUT_LOCK unlock age of input is too low");  // age too low
    test!("==")(engine.execute(lock_10, unlock_settle_kp_update_10, tx_10, input_10),
        "VERIFY_SIG signature failed validation");  // age ok, sig failed

    // settle kp only usable for settle branch (with age check)
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle_9, tx_9, input_9),
        null);  // matching age
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle_10, tx_10, input_10),
        null);  // 10 > 9, ok
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle_9, tx_9, input_9),
        "VERIFY_INPUT_LOCK unlock age of input is too low");  // age too low
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle_10, tx_10, input_10),
        null);  // matching age

    // ditto but wrong signatures used
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle_10, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_settle_kp_settle_9, tx_10, input_10),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle_10, tx_9, input_9),
        "VERIFY_INPUT_LOCK unlock age of input is too low");
    test!("==")(engine.execute(lock_10, unlock_settle_kp_settle_9, tx_10, input_10),
        "VERIFY_SIG signature failed validation");

    // settle kp can't be used for update branch
    test!("==")(engine.execute(lock_9, unlock_update_kp_settle_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_9, unlock_update_kp_settle_10, tx_10, input_10),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_update_kp_settle_9, tx_9, input_9),
        "VERIFY_SIG signature failed validation");
    test!("==")(engine.execute(lock_10, unlock_update_kp_settle_10, tx_10, input_10),
        "VERIFY_SIG signature failed validation");
}
