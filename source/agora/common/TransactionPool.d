/*******************************************************************************

    Contains a transaction pool that is serializable to disk,
    using SQLite as a backing store.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.TransactionPool;

import agora.common.Data;
import agora.common.Deserializer;
import agora.common.Hash;
import agora.common.Serializer;
import agora.common.Set;
import agora.consensus.data.Transaction;
import agora.utils.Log;

import d2sqlite3.database;
import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

import std.algorithm;
import std.conv : to;
import std.exception : collectException, enforce;
import std.file : exists;
import std.range;

mixin AddLogger!();

/// Ditto
public class TransactionPool
{
    /// Keeps track of outputs referenced by transactions in the Pool,
    /// allowing double-spend txs to be filtered before they enter the Pool.
    /// When Transactions are moved from the Pool to an externalized Block,
    /// their referenced UTXOs are removed from 'pool_utxos'
    private Set!Hash pool_utxos;

    /***************************************************************************

        Initialization function. Must be called once per-process
        (not per-thread!) before the class can be used.

    ***************************************************************************/

    public static void initialize ()
    {
        .shutdown();
        .config(SQLITE_CONFIG_MULTITHREAD);
        version (unittest) {} else
            .config(SQLITE_CONFIG_LOG, &loggerCallback, null);
        .initialize();
    }

    /// SQLite db instance
    private Database db;


    /***************************************************************************

        Params:
            db_path = path to the database file, or in-memory storage if
                      :memory: was passed

    ***************************************************************************/

    public this (in string db_path)
    {
        const db_exists = db_path.exists;
        if (db_exists)
            log.info("Loading database from: {}", db_path);

        // note: can fail. we may want to just recover txes from the network instead.
        this.db = Database(db_path);

        if (db_exists)
            log.info("Loaded database from: {}", db_path);

        // create the table if it doesn't exist yet
        this.db.execute("CREATE TABLE IF NOT EXISTS tx_pool " ~
            "(key BLOB PRIMARY KEY, val BLOB NOT NULL)");
    }

    /***************************************************************************

        Callback used

        Params:
            arg = unused (null)
            code = the error code
            msg = the error message

    ***************************************************************************/

    private static extern(C) void loggerCallback (void *arg, int code,
        const(char)* msg) nothrow
    {
        try
        {
            log.error("SQLite error: ({}) {}", code, msg.to!string);
        }
        catch (Exception ex)
        {
            // should not propagate exceptions to C code
        }
    }

    /***************************************************************************

        Shut down the database

        Note: this method must be called explicitly, and not inside of
        a destructor.

    ***************************************************************************/

    public void shutdown ()
    {
        this.db.close();
    }

    /***************************************************************************

        Add a transaction to the pool

        Params:
            tx = the transaction to add

        Returns:
            false if the tx is a double-spend and was therefore rejected

    ***************************************************************************/

    public bool add (Transaction tx) @safe
    {
        scope (failure) assert(0);

        // track tx's own inputs for double-spend
        Set!Hash temp_utxos;

        foreach (const ref input; tx.inputs)
        {
            auto utxo_hash = getHash(input.previous, input.index);
            if (utxo_hash in this.pool_utxos ||
                utxo_hash in temp_utxos)
                return false;

            temp_utxos.put(utxo_hash);
        }

        foreach (utxo_hash; temp_utxos)
            this.pool_utxos.put(utxo_hash);

        static ubyte[] buffer;
        buffer.length = 0;
        () @trusted { assumeSafeAppend(buffer); }();

        scope SerializeDg dg = (scope const(ubyte[]) data) nothrow @safe
        {
            buffer ~= data;
        };

        serializePart(tx, dg);

        () @trusted {
            db.execute("INSERT INTO tx_pool (key, val) VALUES (?, ?)",
                hashFull(tx)[], buffer);
        }();

        return true;
    }

    /***************************************************************************

        Returns:
            the number of transactions in the pool

    ***************************************************************************/

    public size_t length () @safe
    {
        // todo: optimize / cache this
        return () @trusted {
            return db.execute("SELECT count(*) FROM tx_pool").oneValue!size_t;
        }();
    }

    /***************************************************************************

        Walk over the transactions in the pool and call the provided delegate
        with each hash and transaction

        Params:
            dg = the delegate to call

        Returns:
            the status code of the delegate, or zero

    ***************************************************************************/

    public int opApply (scope int delegate(Hash hash, Transaction tx) dg) @trusted
    {
        auto results = this.db.execute("SELECT key, val FROM tx_pool");

        foreach (row; results)
        {
            auto hash = *cast(Hash*)row.peek!(ubyte[])(0).ptr;
            auto tx = deserializeFull!Transaction(row.peek!(ubyte[])(1));

            // break
            if (auto ret = dg(hash, tx))
                return ret;
        }

        return 0;
    }

    /***************************************************************************

        Remove the transaction with the given key from the pool

        Params:
            tx = the transaction to remove
            hash = the hash of the transaction

    ***************************************************************************/

    public void remove (const Transaction tx, Hash hash) @trusted
    {
        foreach (const ref input; tx.inputs)
        {
            auto utxo_hash = getHash(input.previous, input.index);
            this.pool_utxos.remove(utxo_hash);
        }

        this.db.execute("DELETE FROM tx_pool WHERE key = ?", hash[]);
    }

    /***************************************************************************

        Take the specified number of transactions and remove them from the pool.

        Params:
            count = how many transactions to take from the pool

        Returns:
            an array of 'count' transactions

    ***************************************************************************/

    version (unittest) public Transaction[] take (size_t count) @safe
    {
        const len_prev = this.length();
        assert(len_prev >= count);
        Hash[] hashes;
        Transaction[] txs;

        foreach (hash, tx; this)
        {
            hashes ~= hash;
            txs ~= tx;
            if (txs.length == count)
                break;
        }

        foreach (tx, hash; zip(txs, hashes))
            this.remove(tx, hash);

        assert(this.length() == len_prev - count);
        return txs;
    }

    /***************************************************************************

        Get the combined hash of the previous hash and index.
        This makes sure the index is always of the same type,
        as mixing different-sized uint/ulong would create different hashes.

        Returns:
            the combined hash of a previous hash and index

    ***************************************************************************/

    private static Hash getHash (Hash hash, ulong index) @safe nothrow
    {
        return hashMulti(hash, index);
    }
}

/// add & opApply / remove tests (through take())
unittest
{
    import agora.consensus.Genesis;
    import std.exception;

    auto pool = new TransactionPool(":memory:");
    scope(exit) pool.shutdown();  // note: must call outside destructor

    auto gen_key = getGenesisKeyPair();
    auto txs = makeChainedTransactions(gen_key, null, 1);

    txs.each!(tx => assert(pool.add(tx)));
    assert(pool.length == txs.length);

    auto pool_txs = pool.take(txs.length);
    assert(pool.length == 0);
    assert(txs == pool_txs);

    txs.each!(tx => assert(pool.add(tx)));
    assert(pool.length == txs.length);

    auto half_txs = pool.take(txs.length / 2);
    assert(half_txs.length == txs.length / 2);
    assert(pool.length == txs.length / 2);

    // adding duplicate tx hash => return false
    assert(pool.add(txs[0]));
    assert(!pool.add(txs[0]));
}

/// memory reclamation tests
unittest
{
    import agora.common.Deserializer;
    import agora.common.Serializer;
    import agora.consensus.data.Block;
    import agora.consensus.Genesis;
    import std.exception;
    import core.memory;

    auto pool = new TransactionPool(":memory:");
    scope(exit) pool.shutdown();

    auto gen_key = getGenesisKeyPair();
    auto txs = makeChainedTransactions(gen_key, null, 1);

    txs.each!(tx => assert(pool.add(tx)));
    assert(pool.length == txs.length);

    // store the txes in serialized form
    ubyte[][] txs_bytes;
    txs.each!(tx => txs_bytes ~= serializeFull(tx));

    txs = null;

    // deserialize the transactions
    txs_bytes.each!((data)
        {
            Transaction tx;
            scope DeserializeDg dg = (size) nothrow @safe
            {
                ubyte[] res = data[0 .. size];
                data = data[size .. $];
                return res;
            };

            tx.deserialize(dg);
            txs ~= tx;
        });

    auto pool_txs = pool.take(txs.length);
    assert(pool.length == 0);
    assert(txs == pool_txs);
}
