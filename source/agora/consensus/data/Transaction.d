/*******************************************************************************

    Defines the data structure of a transaction

    The current design is heavily influenced by Bitcoin: as we have a UTXO,
    starting with a simple input/output approach seems to make the most sense.
    Script is not implemented: instead, we currently only have a simple signature
    verification step.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.Transaction;

import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.Types;
import agora.common.Hash;
import agora.common.Serializer;
import agora.script.Lock;

import std.algorithm;

/// Type of the transaction: defines the content that follows and the semantic of it
public enum TxType : ubyte
{
    Payment,
    Freeze,
}

/*******************************************************************************

    Represents a transaction (shortened as 'tx')

    Agora uses a UTXO model for transactions, so the transaction format is
    originally derived from that of Bitcoin.

*******************************************************************************/

public struct Transaction
{
    /// Transaction type
    public TxType type;

    /// The list of unspent `outputs` from previous transaction(s) that will be spent
    public Input[] inputs;

    /// The list of newly created outputs to put in the UTXO
    public Output[] outputs;

    /// This transaction may only be included in a block with height >= this
    /// Note that another tx with a lower lock time could double-spend this tx.
    public uint unlock_height = 0;

    /***************************************************************************

        Implements hashing support
        Temporarily skips hashing `unlock_height` to avoid breaking tests.

        todo: remove

        Params:
            dg = hashing function

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const nothrow @safe @nogc
    {
        // skip `unlock_height` for now..
        hashPart(this.type, dg);
        hashPart(this.inputs, dg);
        hashPart(this.outputs, dg);
    }

    /***************************************************************************

        Transactions Serialization

        Params:
            dg = Serialize function

    ***************************************************************************/

    public void serialize (scope SerializeDg dg) const @safe
    {
        serializePart(this.type, dg);

        serializePart(this.inputs.length, dg);
        foreach (const ref input; this.inputs)
            serializePart(input, dg);

        serializePart(this.outputs.length, dg);
        foreach (const ref output; this.outputs)
            serializePart(output, dg);

        serializePart(this.unlock_height, dg);
    }

    /// Support for sorting transactions
    public int opCmp (ref const(Transaction) other) const nothrow @safe @nogc
    {
        return hashFull(this).opCmp(hashFull(other));
    }

    /// Ditto
    public int opCmp (const(Transaction) other) const nothrow @safe @nogc
    {
        return this.opCmp(other);
    }
}

///
nothrow @safe @nogc unittest
{
    Transaction tx;
    auto hash = hashFull(tx);
    auto exp_hash = Hash("0x4b6e507a0519827d48792e6f27f3a0f5b4bc284c69c83a2a" ~
        "ebe35f11443e96364c90f780d4448320440efe68808fe4b6c7c4745d2e7c7e16956" ~
        "987df86f6a32f");
    assert(hash == exp_hash);
}

unittest
{
    import std.algorithm.sorting : isStrictlyMonotonic;
    static Transaction identity (ref Transaction tx) { return tx; }
    Transaction[] txs = [ Transaction.init, Transaction.init ];
    assert(!txs.isStrictlyMonotonic!((a, b) => identity(a) < identity(b)));
}

/*******************************************************************************

    Represents an entry in the UTXO

    This is created by a valid `Transaction` and is added to the UTXO after
    a transaction is confirmed.

*******************************************************************************/

public struct Output
{
    /// The monetary value of this output, in 1/10^7
    public Amount value;

    /// The public key that can redeem this output (A = pubkey)
    /// Note that in Bitcoin, this is an address (the double hash of a pubkey)
    public PublicKey address;

    /// The lock condition for this Output (will replace `address` above later)
    public Lock lock;

    /***************************************************************************

        Implements hashing support

        Params:
            dg = hashing function

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const nothrow @safe @nogc
    {
        hashPart(this.value, dg);
        hashPart(this.address, dg);

        // todo: hash `lock`
    }
}

/// The input of the transaction, which spends a previously received `Output`
public struct Input
{
    /// The hash of the UTXO to be spent
    public Hash utxo;

    /// A signature that should be verified using the `previous[index].address` public key
    public Signature signature;

    /// Used to implement relative time locks.
    /// This Input is only accepted if the current block height is
    /// >= `prev_utxo.unlock_height + unlock_age`
    public uint unlock_age = 0;

    /// Simple ctor
    public this (in Hash utxo_, in Signature sig = Signature.init, uint unlock_age = 0)
        inout pure nothrow @nogc @safe
    {
        this.utxo = utxo_;
        this.signature = sig;
        this.unlock_age = unlock_age;
    }

    /// Ctor which does hashing based on index
    public this (Hash txhash, ulong index, uint unlock_age = 0) nothrow @safe
    {
        this.utxo = hashMulti(txhash, index);
        this.unlock_age = unlock_age;
    }

    /// Ctor which does hashing based on the `Transaction` and index
    public this (in Transaction tx, ulong index, uint unlock_age = 0) nothrow @safe
    {
        this.utxo = hashMulti(tx.hashFull(), index);
        this.unlock_age = unlock_age;
    }

    /***************************************************************************

        Implements hashing support

        Params:
            dg = hashing function

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const nothrow @safe @nogc
    {
        dg(this.utxo[]);

        // todo: hash `unlock_age`
    }
}

/// Transaction type serialize & deserialize for unittest
unittest
{
    testSymmetry!Transaction();

    Transaction payment_tx = Transaction(
        TxType.Payment,
        [Input(Hash.init, 0)],
        [Output.init]
    );
    testSymmetry(payment_tx);

    Transaction freeze_tx = Transaction(
        TxType.Freeze,
        [Input(Hash.init, 0)],
        [Output.init]
    );
    testSymmetry(freeze_tx);
}

unittest
{
    import agora.common.Set;
    auto tx_set = Set!Transaction.from([Transaction.init]);
    testSymmetry(tx_set);
}

/// Transaction type hashing for unittest
unittest
{
    Transaction payment_tx = Transaction(
        TxType.Payment,
        [Input(Hash.init, 0)],
        [Output.init]
    );

    const tx_payment_hash = Hash(
        `0x35927f79ab7f2c8273f5dc24bb1efa5ebe3ac050fd4fd84d014b51124d0322ed` ~
        `709225b92ba28b3ee6b70144d4acafb9a5289fc48ecb4a4f273b537837c78cb0`);
    const expected1 = payment_tx.hashFull();
    assert(expected1 == tx_payment_hash, expected1.toString());

    Transaction freeze_tx = Transaction(
        TxType.Freeze,
        [Input(Hash.init, 0)],
        [Output.init]
    );

    const tx_freeze_hash = Hash(
        `0x0277044f0628605485a8f8a999f9a2519231e8c59c1568ef2dac2f241ce569d8` ~
        `54e15f950e0fd3d88460309d3e0ef3fbd57b8f5af998f8bacbe391ddb9aea328`);
    const expected2 = freeze_tx.hashFull();
    assert(expected2 == tx_freeze_hash, expected2.toString());
}

/*******************************************************************************

    Get sum of `Output`

    Params:
        tx = `Transaction`
        acc = Accumulator value. Pass a default-initialized value to get this
              transaction's sum of output.

    Return:
        `true` if the sum returned is correct. `false` if there was an overflow.

*******************************************************************************/

public bool getSumOutput (const Transaction tx, ref Amount acc)
    nothrow pure @safe @nogc
{
    foreach (ref o; tx.outputs)
        if (!acc.add(o.value))
            return false;
    return true;
}
