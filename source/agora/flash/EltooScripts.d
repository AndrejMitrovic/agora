/*******************************************************************************

    Contains lock + unlock script generators for the Eltoo protocol.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.EltooScripts;

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
    private const TestStackMaxTotalSize = 16_384;
    private const TestStackMaxItemSize = 512;
}

/*******************************************************************************

    Create an Eltoo lock script based on Figure 4 from the whitepaper.

    Params:
        age = the age constraint for using the settlement keypair
        settle_X = the Schnorr sum of the multi-party public keys for the
                   age-constrained settlement branch
        update_X = the Schnorr sum of the multi-party public keys for the
                   sequence-constrained update branch

    Returns:
        a lock script which can be unlocked instantly with an update key-pair,
        or with a settlement key-pair if the age constraint of the input
        is satisfied.

*******************************************************************************/

public Lock createLockEltoo (uint age, Point settle_X, Point update_X,
    uint seq_id) pure nothrow @safe
{
    /*
        Eltoo whitepaper Figure 4:

        Key pairs must be different for the if/else branch,
        otherwise an attacker could just steal the signature
        and use a different PUSH to evaluate the other branch.

        To force only a specific settlement tx to be valid, we need to make
        the settle key derived for each sequence ID. That way an attacker
        cannot attach any arbitrary settlement to any other update.

        Differences to whitepaper:
        - we use naive schnorr multisig for simplicity
        - we use VERIFY_SIG rather than CHECK_SIG, it improves testing
          reliability by ensuring the right failure reason is emitted.
          We manually push OP.TRUE to the stack after the verify.

        OP.IF
            <age> OP.VERIFY_INPUT_LOCK
            <settle_pub_multi[seq]> OP.VERIFY_SIG OP.TRUE
        OP_ELSE
            <seq + 1> OP.VERIFY_TX_SEQ
            <update_pub_multi> OP.VERIFY_SIG OP.TRUE
        OP_ENDIF
    */
    const age_bytes = nativeToLittleEndian(age);
    const ubyte[4] seq_id_bytes = nativeToLittleEndian(seq_id);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_INPUT_LOCK),
            ubyte(32)] ~ settle_X[] ~ [ubyte(OP.VERIFY_SIG), ubyte(OP.TRUE),
         ubyte(OP.ELSE)]
            ~ toPushOpcode(seq_id_bytes) ~ [ubyte(OP.VERIFY_TX_SEQ)]
            ~ [ubyte(32)] ~ update_X[] ~ [ubyte(OP.VERIFY_SIG), ubyte(OP.TRUE),
         ubyte(OP.END_IF)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockSettleEltoo (Signature sig)
    pure nothrow @safe
{
    // remember it's LIFO when popping, TRUE goes last
    return Unlock([ubyte(65)] ~ sig[] ~ [ubyte(SigHash.NoInput)]
        ~ [ubyte(OP.TRUE)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockUpdateEltoo (Signature sig) pure nothrow @safe
{
    // remember it's LIFO when popping, FALSE goes last
    return Unlock([ubyte(65)] ~ sig[] ~ [ubyte(SigHash.NoInput)]
        ~ [ubyte(OP.FALSE)]);
}
