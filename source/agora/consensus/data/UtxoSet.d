/*******************************************************************************

    Contains the unspent transaction output set implementation

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.UtxoSet;

import agora.common.Deserializer;
import agora.common.Hash;
import agora.common.Serializer;
import agora.common.Set;
import agora.consensus.data.Transaction;
import agora.consensus.Validation;

import d2sqlite3.database;
import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

import std.algorithm;
import std.conv;
import std.exception;
import std.file;
import std.range;
import std.path;

/*******************************************************************************

    Database of UTXOs backed by SQLite

*******************************************************************************/

public class UtxoDb
{
    /// SQLite db instance
    private Database db;


    /***************************************************************************

        Constructor

    ***************************************************************************/

    public this (string utxo_db_path)
    {
        const db_path = ":memory:";  // todo: replace

        const db_exists = utxo_db_path.exists;
        if (db_exists)
            logInfo("Loading UTXO database from: %s", utxo_db_path);

        // todo: can fail. we would have to recover by either:
        // A) reconstructing it from our blockchain storage
        // B) requesting the UTXO set from our peers
        this.db = Database(utxo_db_path);

        if (db_exists)
            logInfo("Loaded database from: %s", utxo_db_path);

        // create the table if it doesn't exist yet
        this.db.execute("CREATE TABLE IF NOT EXISTS utxo_map " ~
            "(key BLOB PRIMARY KEY, val BLOB NOT NULL)");
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

        Look up the output in the map, and store it to 'output' if found

        Returns:
            true if the output was found

    ***************************************************************************/

    public bool find (Hash key, out Output output) nothrow @trusted
    {
        try
        {
            auto results = db.execute("SELECT val FROM utxo_map WHERE key = ?",
                key[]);

            foreach (row; results)
            {
                output = deserialize!Output(row.peek!(ubyte[])(1));
                return true;
            }
        }
        catch (Exception)
        {
            assert(0);
        }

        return false;
    }

    /***************************************************************************

        Add an Output to the map

    ***************************************************************************/

    public void opIndexAssign (const ref Output output, Hash key) nothrow @safe
    {
        static ubyte[] buffer;
        buffer.length = 0;
        () @trusted { assumeSafeAppend(buffer); }();

        scope SerializeDg dg = (scope const(ubyte[]) data) nothrow @safe
        {
            buffer ~= data;
        };

        serializePart(output, dg);

        () @trusted {
            try
            {
                db.execute("INSERT INTO utxo_map (key, val) VALUES (?, ?)",
                    key[], buffer);
            }
            catch (Exception ex)
            {
                assert(0);
            }
        }();
    }

    /***************************************************************************

        Remove an Output from the map

    ***************************************************************************/

    public void remove (Hash key) nothrow @safe
    {
        try
        {
            () @trusted { db.execute("DELETE FROM utxo_map WHERE key = ?", key[]); }();
        }
        catch (Exception ex)
        {
            assert(0);
        }
    }
}

///
public class UtxoStore
{
    ///
    private struct UtxoPair
    {
        /// Key of the UTXO
        private Hash key;

        /// The Output
        private Output value;
    }

    /// Change later
    private const MaxRecentUtxos = 1024;

    /// Most recent unspent outputs
    private Output[Hash] hot_cache;

    /// Unspent outputs in the database
    private UtxoDb cold_store;

    /// used to track which Outputs should be moved from hot_cache => cold_store
    private UtxoPair[] most_recent_utxos;


    public this (string utxo_db_path)
    {
        this.cold_store = new UtxoDb(utxo_db_path);
    }

    /***************************************************************************

        When shutting down, we must push all items from
        the hot cache to the cold store.

    ***************************************************************************/

    public void shutdown ()
    {
        foreach (key, output; this.hot_cache)
            this.cold_store[key] = output;

        this.cold_store.shutdown();
    }

    /***************************************************************************

        Find a UTXO with the given key

        Params:
            key = the key to look up
            output = will contain the output if it's found

        Returns:
            true if the Output with the given key was found

    ***************************************************************************/

    public bool find (Hash key, out Output output) nothrow @safe
    {
        // in the hot cache
        if (auto out_ptr = key in this.hot_cache)
        {
            output = *out_ptr;
            return true;
        }

        // in the cold cache
        if (this.cold_store.find(key, output))
            return true;

        return false;
    }

    /***************************************************************************

        Remove a spent UTXO from the store

        Params:
            key = the key to remove

    ***************************************************************************/

    public void remove (Hash key) nothrow @safe
    {
        // in the hot cache
        if (auto out_ptr = key in this.hot_cache)
            this.hot_cache.remove(key);
        else
            this.cold_store.remove(key);  // it must be in the cold store
    }

    /***************************************************************************

        Add an Output to the map

        Params:
            output = the output to add
            key = the key to add

    ***************************************************************************/

    public void opIndexAssign (const ref Output output, Hash key) nothrow @safe
    {
        // just added => move to hot cache
        this.hot_cache[key] = output;

        // hot cache is full, move coldest item to the cold store
        if (this.most_recent_utxos.length + 1 >= MaxRecentUtxos)
        {
            auto least_used = most_recent_utxos[0];

            () @trusted {
                this.most_recent_utxos.dropIndex(0);
                assumeSafeAppend(this.most_recent_utxos);
            }();

            // move the utxo to the cold storage
            this.cold_store[least_used.key] = least_used.value;
        }

        // add it
        this.most_recent_utxos ~= UtxoPair(key, output);
    }
}

/// ditto
public class UtxoSet
{
    private UtxoStore utxo_store;

    /// Unspent outputs
    //private Output[Hash] utxo_store;

    /// Set of consumed outputs during validation
    private Set!Hash used_utxos;


    /***************************************************************************

        Constructor

        Params:
            utxo_db_path = path to the utxo database

    ***************************************************************************/

    public this (in string utxo_db_path)
    {
        this.utxo_store = new UtxoStore(utxo_db_path);
    }

    /***************************************************************************

        Add all of a transaction's outputs to the Utxo set,
        and remove the spent outputs in the transaction from the set.

        Params:
            tx = the transaction

    ***************************************************************************/

    public void updateUtxoSet (const ref Transaction tx) nothrow @safe
    {
        foreach (input; tx.inputs)
        {
            auto utxo_hash = hashMulti(input.previous, cast(size_t)input.index);
            this.utxo_store.remove(utxo_hash);
        }

        Hash tx_hash = tx.hashFull();
        foreach (idx, output; tx.outputs)
        {
            auto utxo_hash = hashMulti(tx_hash, cast(size_t)idx);
            this.utxo_store[utxo_hash] = output;
        }
    }

    /***************************************************************************

        Prepare tracking double-spend and return the UtxoFinder delegate

        Returns:
            the UtxoFinder delegate

    ***************************************************************************/

    public UtxoFinder getUtxoFinder () nothrow @safe
    {
        // clear used UTXOs
        this.used_utxos.clear();
        return &this.findOutput;
    }

    /***************************************************************************

        Find an unspent Output in the UTXO set.

        Params:
            tx_hash = the hash of transation
            index = the index of the output
            output = will contain the UTXO if found

        Return:
            Return true if the UTXO was found

    ***************************************************************************/

    public bool findOutput (Hash hash, size_t index, out Output output)
        nothrow @safe
    {
        auto utxo_hash = hashMulti(hash, cast(size_t)index);

        if (utxo_hash in this.used_utxos)
            return false;  // double-spend

        if (this.utxo_store.find(utxo_hash, output))
        {
            this.used_utxos.put(utxo_hash);
            return true;
        }

        return false;
    }
}
