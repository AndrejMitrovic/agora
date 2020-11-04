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
// note: throughout this code the R is never incremented, which makes
// the signature scheme itself insecure but helps simplify the tests.
// note: we will need to change our transaction filter in the consensus rules
// to always prefer tx's with outputs with a lower lock age. Otherwise a
// Settlement tx could override an Update tx during network outages.
unittest
{
    import agora.common.Amount;
    import agora.consensus.data.UTXO;

    // used for the initial funding tx input spend
    const Pair kim_funding_kp = Pair.random();

    const Pair kim_settle_kp = Pair.random();
    const Pair kim_update_kp = Pair.random();
    Pair kim_nonce = Pair.random();

    const Pair bob_payment_kp = Pair.random();  // the channel's destination
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

    //auto URX = kim_nonce.V + bob_nonce.V;

    // step 0: setlement age and funding need to be collaboratively agreed upon
    // in this example there is only a single founder, but this is very easy
    // to extend to multi-party funding transactions.
    const FundingAmount = Amount(10L * 10_000_000uL);  // 10 BOA
    const SettleAge = 10;
    const FundingLock = createLockEltoo(SettleAge, SX, UX);

    // step 1: Kim creates the funding tx and *does not* sign it yet
    Transaction funding_tx = {
        type: TxType.Payment,
        inputs: [Input(genesis, 0 /* index */, 0 /* unlock age */)],
        outputs: [
            Output(FundingAmount,
                PublicKey.init,  // ignored, backwards compatibility (hashing)
                FundingLock)]
    };

    UTXO _utxo;  // verify we can accept funding tx
    assert(utxo_set.peekUTXO(funding_tx.inputs[0].utxo, _utxo));

    // step 2: before Kim signs the funding tx he needs Bob to sign a new
    // settlement tx. This is because if Kim prematurely published the
    // funding tx then the funds could be forever locked - as they require
    // multisig for both the update and settle branches.
    // Kim sends the unsigned funding tx to Bob so he can create & sign
    // a settlement tx which spends from the funding tx.

    // step 2.5: for Schnorr to work we need to agree on a sum R value,
    // so Kim will have to collaborate on this with Bob.
    // alternative: implement `OP.CHECK_MULTI_SIG`, or alternatively a
    // different N-of-M scheme that doesn't require so much interaction.
    // for simplifying the tests we re-use R for all signatures
    auto RX = kim_nonce.V + bob_nonce.V;

    // step 3: Bob creates a settlement spending the funding tx,
    // and partially signs it with only its own signature.
    // The input lock remains empty.
    // Bob sends this <settle_0, signature> tuple back to Kim.
    Transaction settle_0 = {
        type: TxType.Payment,
        inputs: [Input(funding_tx, 0 /* index */, SettleAge)],
        outputs: [
            Output(FundingAmount,
                PublicKey.init,  // ignored, backwards compatibility (hashing)
                Lock(LockType.Key, kim_funding_kp.V[]))]
    };
    const bob_settle_0_sig = sign(bob_settle_kp.v, SX, RX, bob_nonce.v,
        settle_0);
    assert(!verify(SX, bob_settle_0_sig, settle_0));  // not valid yet

    // step 4: Kim received the <settlement, signature> tuple.
    // he signs it, and finishes the multisig.
    const kim_settle_0_sig = sign(kim_settle_kp.v, SX, RX, kim_nonce.v,
        settle_0);
    const settle_0_multi_sig = Sig(RX,
          Sig.fromBlob(kim_settle_0_sig).s
        + Sig.fromBlob(bob_settle_0_sig).s).toBlob();

    // step 5: the unlock settlement script is created
    const Unlock settle_0_unlock = createUnlockSettleEltoo(settle_0_multi_sig);
    settle_0.inputs[0].unlock = settle_0_unlock;

    // step 6: the settlement is checked for validity with the engine.
    // If the settlement tx is valid, it is now safe to publish the Funding
    // transaction to the blockchain. If validation has failed it means
    // the collaboration has failed, and Kim can proceed to try again or to
    // pick another partner to create a channel with.
    scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
    test!("==")(engine.execute(
        funding_tx.outputs[0].lock, settle_0_unlock, settle_0,
            settle_0.inputs[0]),
        null);

    // step 7: Funding tx was externalized, this signals the payment channel
    // has been created.
    assert(utxo_set.peekUTXO(funding_tx.inputs[0].utxo, _utxo));  // sanity check
    utxo_set.clear();  // think of it as spend with below put() call
    utxo_set.put(funding_tx, 1 /* unlock_height */);

    // The UTXO spent by the funding tx is now gone
    assert(!utxo_set.peekUTXO(funding_tx.inputs[0].utxo, _utxo));
    // settlement can refer to the new funding UTXO, however we will not add it
    // yet (it's encumbered by a time-lock anyway)
    assert(utxo_set.peekUTXO(settle_0.inputs[0].utxo, _utxo));

    // step 8: Kim shares his part of the signature to Bob, or alternatively
    // sends the entire settlement tx struct. This is not strictly necessary,
    // because Bob doesn't care about this first settlement transaction,
    // as it refunds everything back to Kim. Furthermore Bob doesn't need this
    // settlement for any future constructions. But for symmetry reasons we
    // might send it anyway.
    version (none) sendToKim(settle_0);

    // step 9: Kim wants to send 1 BOA to Bob. He needs to create an update tx,
    // however before signing it he should also create a new settlement which
    // will be able to attach to the update tx.
    // note: there is no `update_0`, and `update_1` will double-spend `settle_0`
    // this upate double-spends the settlement `settle_0`
    Transaction update_1 = {
        type: TxType.Payment,
        inputs: [Input(funding_tx, 0 /* index */, 0 /* no unlock age */)],
        outputs: [
            Output(FundingAmount,
                PublicKey.init,  // ignored, backwards compatibility (hashing)
                FundingLock)]
    };
    // the input unlock will be signed later, after the settlement is created

    // step 10: Kim creates the settlement that spends `update_1` output
    // Kim wants to send 1 BOA to Bob. So the new settlement has two outputs
    // this time.
    Amount KimAmount = Amount(9L * 10_000_000uL);  // 9 BOA
    Amount BobAmount = Amount(1L * 10_000_000uL);  // 1 BOA
    Transaction settle_1 = {
        type: TxType.Payment,
        inputs: [Input(update_1, 0 /* index */, SettleAge)],
        outputs: [
            Output(KimAmount,
                PublicKey.init,  // ignored, backwards compatibility (hashing)
                Lock(LockType.Key, kim_funding_kp.V[])),
            Output(BobAmount,
                PublicKey.init,  // ignored, backwards compatibility (hashing)
                Lock(LockType.Key, bob_payment_kp.V[])),
            ]
    };

    const bob_settle_1_sig = sign(bob_settle_kp.v, SX, RX, bob_nonce.v,
        settle_1);
    assert(!verify(SX, bob_settle_1_sig, settle_1));  // not valid yet

    // step 11 (4): Kim received the <settlement, signature> tuple.
    // he signs it, and finishes the multisig.
    const kim_settle_1_sig = sign(kim_settle_kp.v, SX, RX, kim_nonce.v,
        settle_1);
    const settle_1_multi_sig = Sig(RX,
          Sig.fromBlob(kim_settle_1_sig).s
        + Sig.fromBlob(bob_settle_1_sig).s).toBlob();

    // step 12 (5): the unlock settlement script is created
    // this step should be optimized because both Kim and Bob
    // need to verify the settlement signature
    const Unlock settle_1_unlock = createUnlockSettleEltoo(settle_1_multi_sig);
    settle_1.inputs[0].unlock = settle_1_unlock;

    // step 13 (6): the settlement is checked for validity with the engine,
    // both at Kim's and at Bob's side. If the settlement tx is valid,
    // it is now safe to sign the update transaction
    test!("==")(engine.execute(
        update_1.outputs[0].lock, settle_1_unlock, settle_1,
            settle_1.inputs[0]),
        null);

    // step 14: Kim & Bob sign the update tx
    const bob_update_1_sig = sign(bob_update_kp.v, UX, RX, bob_nonce.v,
        update_1);
    assert(!verify(UX, bob_update_1_sig, update_1));  // not valid yet

    // step 11 (4): Kim received the <settlement, signature> tuple.
    // he signs it, and finishes the multisig.
    const kim_update_1_sig = sign(kim_update_kp.v, UX, RX, kim_nonce.v,
        update_1);
    const update_1_multi_sig = Sig(RX,
          Sig.fromBlob(kim_update_1_sig).s
        + Sig.fromBlob(bob_update_1_sig).s).toBlob();

    const Unlock update_1_unlock = createUnlockUpdateEltoo(update_1_multi_sig);
    update_1.inputs[0].unlock = update_1_unlock;

    // validate that `update_1` can attach to funding tx
    test!("==")(engine.execute(
        funding_tx.outputs[0].lock, update_1_unlock, update_1,
            update_1.inputs[0]),
        null);

    // step 12: publish `update_1` to the blockchain, which enables
    // settlement 1 to attach to it. This is the on-chain protocol
    // as defined in Figure 2 in the Eltoo whitepaper.
}
