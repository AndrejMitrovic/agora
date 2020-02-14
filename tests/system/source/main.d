/*******************************************************************************

    Stand alone client to test basic functionalities of the node

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module main;

import agora.api.FullNode;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXOSet;
import agora.consensus.Genesis;
import agora.common.Amount;
import agora.common.crypto.ECC;
import agora.common.crypto.Key;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Set;
import agora.utils.PrettyPrinter;

import vibe.web.rest;

import std.algorithm;
import std.stdio;
import core.thread;
import core.time;

/// Helper struct
private struct Address
{
    ///
    string host;
    ///
    ushort port;

    /// Helper function to call make the address vibe.inet.URL friendly
    public string withSchema () const @safe
    {
        import std.format;
        return format("http://%s:%d", this.host, this.port);
    }
}

/// Node addresses
private immutable Address[] Addrs = [
    { host: "127.0.0.1", port: 4000, },
    { host: "127.0.0.1", port: 4001, },
    { host: "127.0.0.1", port: 4002, },
];

/// Test node count
private immutable uint NodeCnt = 3;

/// Node config helper struct
private struct NodeConfig
{
    string seed;
}

/// Node seeds
private immutable NodeConfig[] configs = [
    { seed: `SCFPAX2KQEMBHCG6SJ77YTHVOYKUVHEFDROVFCKTZUG7Z6Q5IKSNG6NQ`},
    { seed: `SCTTRCMT7DVZHQS375GWIKYQYHKA3X4IC4EOBNPRGV7DFR3X6OM5VIWL`},
    { seed: `SAI4SRN2U6UQ32FXNYZSXA5OIO6BYTJMBFHJKX774IGS2RHQ7DOEW5SJ`},
];

void main ()
{
    auto kp = getGenesisKeyPair();

    KeyPair[] keypairs;
    foreach (config; configs)
        keypairs ~= KeyPair.fromSeed(Seed.fromString(config.seed));

    Transaction[] freeze_txs;
    Transaction payment;
    Enrollment[] enrolleds;

    {
        API[NodeCnt] clients;
        foreach (idx, const ref addr; Addrs)
            clients[idx] = new RestInterfaceClient!API(addr.withSchema());

        foreach (idx, ref client; clients)
        {
            writefln("[%s] getNetworkInfo: %s", idx, client.getNetworkInfo());
            const height = client.getBlockHeight();
            writefln("[%s] getBlockHeight: %s", idx, height);
            writeln("----------------------------------------");
            assert(height == 0);
        }

        foreach (idx; 0 .. Block.TxsInBlock)
        {
            Transaction tx = {
                type: TxType.Payment,
                inputs: [Input(GenesisBlock.header.merkle_root, idx)],
                outputs: [Output(GenesisTransaction.outputs[idx].value, kp.address)]
            };

            auto signature = kp.secret.sign(hashFull(tx)[]);
            tx.inputs[0].signature = signature;
            clients[0].putTransaction(tx);
        }

        checkBlockHeight(1);
    }

    /// Make Transactions for block height 2,
    /// which will contain N freeze tx's, and
    /// the rest of txs will have 8 outputs to the
    /// same address
    {
        API[NodeCnt] clients;
        foreach (idx, const ref addr; Addrs)
            clients[idx] = new RestInterfaceClient!API(addr.withSchema());

        // clients[0] Create frozen transactions and enrolment
        const Block[] blocks_1 = clients[0].getBlocksFrom(1,1);
        assert(blocks_1[0].header.height == 1);

        foreach (idx; 0 .. Block.TxsInBlock)
        {
            Transaction tx;

            if (idx < keypairs.length)
            {
                Transaction freeze_tx = {
                    type: TxType.Freeze,
                    inputs: [Input(hashFull(blocks_1[0].txs[idx]), 0)],
                    outputs: [Output(Amount.MinFreezeAmount,
                        keypairs[idx].address)]
                };
                freeze_tx.inputs[0].signature = kp.secret.sign(hashFull(freeze_tx)[]);
                clients[0].putTransaction(freeze_tx);
                freeze_txs ~= freeze_tx;
            }
            else
            {
                Transaction payment_tx = {TxType.Payment, [], []};
                payment_tx.inputs ~= Input(hashFull(blocks_1[0].txs[idx]), 0);
                // create tx's to be spent by all tx's in block 3
                foreach (idx2; 0 .. Block.TxsInBlock)
                    payment_tx.outputs ~= Output(Amount.MinFreezeAmount, kp.address);

                payment_tx.inputs[0].signature = kp.secret.sign(hashFull(payment_tx)[]);
                clients[0].putTransaction(payment_tx);
                if (payment == Transaction.init)
                    payment = payment_tx;
            }
        }

        checkBlockHeight(2);
    }

    /// Make Transactions for block height 3
    {
        API[NodeCnt] clients;
        foreach (idx, const ref addr; Addrs)
            clients[idx] = new RestInterfaceClient!API(addr.withSchema());

        const Block[] blocks_2 = clients[0].getBlocksFrom(0,3);
        assert(blocks_2[2].header.height == 2);

        foreach (idx; 0 .. Block.TxsInBlock)
        {
            Transaction tx = {
                type: TxType.Payment,
                inputs: [Input(hashFull(payment), idx)],
                outputs: [Output(Amount.MinFreezeAmount, kp.address)]
            };

            auto signature = kp.secret.sign(hashFull(tx)[]);
            tx.inputs[0].signature = signature;
            clients[2].putTransaction(tx);
        }

        checkBlockHeight(3);
    }

    /// Create enrollments
    {
        API[NodeCnt] clients;
        foreach (idx, const ref addr; Addrs)
            clients[idx] = new RestInterfaceClient!API(addr.withSchema());

        Hash[] utxo_hashs;
        foreach (idx; 0 .. NodeCnt)
        {
            Pair signature_noise;
            utxo_hashs ~= UTXOSet.getHash(hashFull(freeze_txs[idx]),0);
            signature_noise = Pair.random;

            Pair node_key_pair;
            node_key_pair.v = secretKeyToCurveScalar(keypairs[idx].secret);
            node_key_pair.V = node_key_pair.v.toPoint();

            Enrollment enroll;
            enroll.utxo_key = utxo_hashs[idx];
            enroll.random_seed = hashFull(Scalar.random());
            enroll.cycle_length = 1008;
            enroll.enroll_sig = sign(node_key_pair.v, node_key_pair.V,
                signature_noise.V, signature_noise.v, enroll);
            enrolleds ~= enroll;

            clients[0].enrollValidator(enrolleds[idx]);
        }

        Thread.sleep(500.msecs);

        // Checking Enrolled
        foreach (idx, ref client; clients)
        {
            foreach (utxo_hash; utxo_hashs)
            {
                assert(client.hasEnrollment(utxo_hash));
                writefln("[%s] hasEnrollment: %s", idx, utxo_hash);
            }
        }
    }

    /// Make Transactions for block height 4
    {
        API[NodeCnt] clients;
        foreach (idx, const ref addr; Addrs)
            clients[idx] = new RestInterfaceClient!API(addr.withSchema());

        const Block[] blocks_3 = clients[0].getBlocksFrom(0,5);
        assert(blocks_3[3].header.height == 3);

        foreach (idx; 0 .. Block.TxsInBlock)
        {
            Transaction tx = {
                type: TxType.Payment,
                inputs: [Input(hashFull(blocks_3[3].txs[idx]), 0)],
                outputs: [Output(Amount.MinFreezeAmount, kp.address)]
            };

            auto signature = kp.secret.sign(hashFull(tx)[]);
            tx.inputs[0].signature = signature;
            clients[1].putTransaction(tx);
        }

        checkBlockHeight(4);

        const Block[] blocks_4 = clients[0].getBlocksFrom(0,5);
        assert(blocks_4[4].header.height == 4);
        // Check that the enrollments are stored in the block
        assert(enrolleds == blocks_4[4].header.enrollments);
    }
}

/// Check block generation
private void checkBlockHeight (ulong height)
{
    // TODO: This is a hack because of issue #312
    // https://github.com/bpfkorea/agora/issues/312
    API[NodeCnt] clients;
    foreach (idx, const ref addr; Addrs)
        clients[idx] = new RestInterfaceClient!API(addr.withSchema());

    Hash blockHash;
    size_t times; // Number of times we slept for 50 msecs
    foreach (idx, ref client; clients)
    {
        ulong getHeight;
        do
        {
            Thread.sleep(50.msecs);
            getHeight = client.getBlockHeight();
        }
        while (getHeight < height && times++ < 100); // Retry if we're too early
        const blocks = client.getBlocksFrom(0, 42);
        writefln("[%s] getBlockHeight: %s", idx, getHeight);
        writefln("[%s] getBlocksFrom: %s", idx, blocks.map!prettify);
        writeln("----------------------------------------");
        assert(getHeight == height);
        assert(blocks.length == height+1);
        if (idx != 0)
            assert(blockHash == hashFull(blocks[height].header));
        else
            blockHash = hashFull(blocks[height].header);
        times = 0;
    }
}

/// Copied from Agora
public KeyPair getGenesisKeyPair ()
{
    return KeyPair.fromSeed(
        Seed.fromString(
            "SCT4KKJNYLTQO4TVDPVJQZEONTVVW66YLRWAINWI3FZDY7U4JS4JJEI4"));
}
