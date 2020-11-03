/*******************************************************************************

    Contains lock + unlock script generators for the Eltoo protocol.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Eltoo;

import agora.common.crypto.Key;
import agora.consensus.data.Transaction;
import agora.flash.LockScripts;
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

// Example of the Eltoo whitepaper on-chain protocol from Figure 2
unittest
{
    import agora.common.Amount;
    import agora.consensus.data.UTXO;

    // used for the initial funding tx input spend
    const Pair kim_funding_kp = Pair.random();

    const Pair kim_settle_kp = Pair.random();
    const Pair kim_update_kp = Pair.random();
    Pair kim_nonce = Pair.random();

    const Pair bob_settle_kp = Pair.random();
    const Pair bob_update_kp = Pair.random();
    Pair bob_nonce = Pair.random();

    const Transaction genesis = {
        type: TxType.Payment,
        outputs: [Output(Amount(61_000_000L * 10_000_000uL), PublicKey(kim_funding_kp.V[]))]
    };
    scope utxo_set = new TestUTXOSet();
    utxo_set.put(genesis, 1 /* height */);

    const SX = kim_settle_kp.V + bob_settle_kp.V;
    const UX = kim_update_kp.V + bob_update_kp.V;

    //auto SRX = kim_nonce.V + bob_nonce.V;
    //auto URX = kim_nonce.V + bob_nonce.V;

    const FundingAmount = Amount(10L * 10_000_000uL);  // 10 BOA
    const SettlementMinAge = 10;
    const FundingLock = createLockEltoo(SettlementMinAge, SX, UX);

    // step 1: one party creates the funding tx,
    // and *does not* sign yet
    Transaction funding = {
        type: TxType.Payment,
        inputs: [Input(genesis, 0 /* index */, 0 /* unlock age */)],
        outputs: [Output(FundingAmount,
                    // this is ignored! it's here for backwards compatibility (hashing)
                    PublicKey(kim_funding_kp.V[]),
                    FundingLock)]
    };

    UTXO _utxo;  // verify we can accept funding tx
    assert(utxo_set.peekUTXO(funding.inputs[0].utxo, _utxo));

    // step 2: before Kim signs the funding tx, he needs Bob to sign a new
    // settlement tx. This is because if Kim prematurely published the
    // funding tx, the funds could be forever locked as they require multisig
    // for both the update and settle branches.
    // Kim sends the unsigned funding tx to Bob so he can create & sign
    // a settlement tx.

    // spends `funding`
    Unlock unlock = createUnlockSettleEltoo(bob_settle_kp);
    Transaction settle_0 = {
        type: TxType.Payment,
        inputs: [Input(funding, 0 /* index */, 0 /* unlock age */)],
        outputs: [Output(FundingAmount,
                    // this is ignored! it's here for backwards compatibility (hashing)
                    PublicKey(SX.V[]),
                    FundingLock)]
    };

    const bob_settle_sig = sign(bob_settle_kp.v, SX, SRX, bob_nonce.v, tx);
}
