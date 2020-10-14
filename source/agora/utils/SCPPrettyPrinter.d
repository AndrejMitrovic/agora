/*******************************************************************************

    Contains pretty-printing routines specialized for SCP types.

    As the integration test-suite imports into PrettyPrinter,
    we want to avoid adding a dependency to SCP.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.utils.SCPPrettyPrinter;

version (none):

import agora.common.Types;
import agora.common.Amount;
import agora.common.Config;
import agora.common.Serializer;
import agora.common.Types;
import agora.common.crypto.Key;
import agora.consensus.data.Block;
import agora.consensus.data.ConsensusData;
import agora.consensus.data.Enrollment;
import agora.consensus.data.SCPTypes;
import agora.consensus.data.Transaction;
import agora.utils.PrettyPrinter;

import dscp.Types;

import std.algorithm;
import std.format;
import std.range;

/*******************************************************************************

    Returns a formatting prettifier for Envelope.

    Params:
        env = a pointer to Envelope
        get_qset = getter for quorum sets. If null it won't be used.

*******************************************************************************/

public SCPEnvelopeFmt scpPrettify (in Envelope* env,
    in GetQSetDg get_qset = null) nothrow @trusted @nogc
{
    return SCPEnvelopeFmt(env, get_qset);
}

/// Formatting struct for `Ballot`, deserializes Value types as ConsensusData
public struct SCPBallotFmt
{
    private const(Ballot) ballot;

    public void toString (scope void delegate (in char[]) @safe sink) @trusted nothrow
    {
        try
        {
            formattedWrite(sink,
                "{ counter: %s, ",
                this.ballot.counter);

            try
            {
                formattedWrite(sink,
                    "value: %s }",
                    prettify(  // cast: deserializer should take const(ubyte)[]
                    (cast(ubyte[])this.ballot.value[]).deserializeFull!ConsensusData));
            }
            catch (Exception ex)
            {
                formattedWrite(sink, "value: <un-deserializable> }");
            }
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// SCP Quorum set getter delegate
private alias GetQSetDg = QuorumSet* delegate (
    ref const(Hash) qSetHash);

/// Formatting struct for a quorum Hash => QuorumConfig through the use
/// of a quorum getter delegate
private struct QuorumFmt
{
    private const(Hash) hash;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink)
        @trusted nothrow
    {
        try
        {
            QuorumSet* qset;
            if (this.getQSet !is null)
                qset = this.getQSet(this.hash);

            if (qset.ptr !is null)
            {
                auto qconf = toQuorumConfig(*qset.ptr);
                formattedWrite(sink, "{ hash: %s, quorum: %s }",
                    prettify(this.hash), prettify(qconf));
            }
            else
            {
                formattedWrite(sink, "{ hash: %s, quorum: <unknown> }",
                    prettify(this.hash));
            }
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Prepare`
private struct PrepareFmt
{
    private const(Statement.Pledges.Prepare) prepare;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink,
                "Prepare { qset: %s, ballot: %s, ",
                QuorumFmt(this.prepare.quorum_hash, this.getQSet),
                SCPBallotFmt(this.prepare.ballot));

            if (this.prepare.prepared !is null)
                formattedWrite(sink, "prep: %s, ",
                    SCPBallotFmt(*this.prepare.prepared));
            else
                formattedWrite(sink, "prep: <null>, ");

            if (this.prepare.prepared_prime !is null)
                formattedWrite(sink, "prepPrime: %s, ",
                    SCPBallotFmt(*this.prepare.prepared_prime));
            else
                formattedWrite(sink, "prepPrime: <null>, ");

            formattedWrite(sink, "nc: %s, nH: %s }",
                this.prepare.nC,
                this.prepare.nH);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Confirm`
private struct ConfirmFmt
{
    private const(Statement.Pledges.Confirm) confirm;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink,
                "Confirm { qset: %s, ballot: %s, nPrep: %s, nComm: %s, nH: %s }",
                QuorumFmt(this.confirm.quorum_hash, this.getQSet),
                SCPBallotFmt(this.confirm.ballot),
                this.confirm.nPrepared,
                this.confirm.nCommit,
                this.confirm.nH);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Externalize`
private struct ExternalizeFmt
{
    private const(Statement.Pledges.Externalize) externalize;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink,
                "Externalize { commitQset: %s, commit: %s, nh: %s }",
                QuorumFmt(this.externalize.commit_quorum_hash, this.getQSet),
                SCPBallotFmt(this.externalize.commit),
                this.externalize.nH);
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Nomination`, deserializes Value types as ConsensusData
private struct SCPNominationFmt
{
    private const(Nomination) nominate;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @trusted nothrow
    {
        try
        {
            formattedWrite(sink,
                "Nominate { qset: %s, ",
                QuorumFmt(this.nominate.quorum_hash));

            try
            {
                formattedWrite(sink,
                    "votes: %s, ",
                    this.nominate.votes[]
                        .map!(cd => prettify(
                            // cast: deserializer should take const(ubyte)[]
                            (cast(ubyte[])cd[]).deserializeFull!ConsensusData)));
            }
            catch (Exception ex)
            {
                formattedWrite(sink, "votes: <un-deserializable>, ");
            }

            try
            {
                formattedWrite(sink,
                    "accepted: %s }",
                    this.nominate.accepted[]
                        .map!(cd => prettify(
                            // cast: deserializer should take const(ubyte)[]
                            (cast(ubyte[])cd[]).deserializeFull!ConsensusData)));
            }
            catch (Exception ex)
            {
                formattedWrite(sink, "accepted: <un-deserializable> }");
            }
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Pledges`
private struct PledgesFmt
{
    private const(Statement.Pledges) pledges;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @trusted nothrow
    {
        try
        {
            final switch (pledges.type_)
            {
                case StatementType.Prepare:
                    formattedWrite(sink, "%s", PrepareFmt(this.pledges.prepare_, this.getQSet));
                    break;
                case StatementType.Confirm:
                    formattedWrite(sink, "%s", ConfirmFmt(this.pledges.confirm_, this.getQSet));
                    break;
                case StatementType.Externalize:
                    formattedWrite(sink, "%s", ExternalizeFmt(this.pledges.externalize_, this.getQSet));
                    break;
                case StatementType.Nominate:
                    formattedWrite(sink, "%s", SCPNominationFmt(this.pledges.nominate_, this.getQSet));
                    break;
            }
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Statement`
private struct SCPStatementFmt
{
    private const(Statement) statement;
    private const(GetQSetDg) getQSet;

    public void toString (scope void delegate (in char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink,
                "{ node: %s, slot_idx: %s, pledge: %s }",
                prettify(PublicKey(this.statement.nodeID[])),
                cast(ulong)this.statement.slot_idx,  // cast: consistent cross-platform output
                PledgesFmt(this.statement.pledges, getQSet));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// Formatting struct for `Envelope`
private struct SCPEnvelopeFmt
{
    /// Pointer to Envelope
    private const Envelope* envelope;

    /// QuorumSet getter
    private const(GetQSetDg) getQSet;

    /***************************************************************************

        Constructor

        Params:
            env = pointer to an Envelope
            get_qset = getter for quorum sets. If null it won't be used.

    ***************************************************************************/

    public this (const Envelope* env, const GetQSetDg getQSet)
        @nogc @trusted nothrow
    {
        assert(env !is null);
        this.envelope = env;
        this.getQSet = getQSet;
    }

    /***************************************************************************

        Stringification support

        Params:
            sink = the delegate to use as a sink

    ***************************************************************************/

    public void toString (scope void delegate (in char[]) @safe sink) @safe nothrow
    {
        try
        {
            formattedWrite(sink,
                "{ statement: %s, sig: %s }",
                SCPStatementFmt(this.envelope.statement, this.getQSet),
                prettify(this.envelope.signature));
        }
        catch (Exception ex)
        {
            assert(0, ex.msg);
        }
    }
}

/// ditto
version (none) unittest
{
    import agora.common.Config;
    import agora.common.Hash;
    import agora.common.Serializer;
    import agora.common.Set;
    import agora.consensus.data.Enrollment;
    import agora.consensus.data.genesis.Test;

    Hash quorum_hash;

    Hash key = Hash("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f" ~
                    "1b60a8ce26f000000000019d6689c085ae165831e934ff763ae46a2" ~
                    "a6c172b3f1b60a8ce26f");
    Hash seed = Hash("0X4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB212" ~
                     "7B7AFDEDA33B4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E" ~
                     "2CC77AB2127B7AFDEDA33B");
    Signature sig = Signature("0x000000000000000000016f605ea9638d7bff58d2c0c" ~
                              "c2467c18e38b36367be78000000000000000000016f60" ~
                              "5ea9638d7bff58d2c0cc2467c18e38b36367be78");
    const Enrollment record =
    {
        utxo_key: key,
        random_seed: seed,
        cycle_length: 1008,
        enroll_sig: sig,
    };

    const(ConsensusData) cd =
    {
        tx_set:  GenesisBlock.txs[1 .. $],
        enrolls: [ record, record, ],
    };

    Ballot ballot;
    ballot.counter = 42;
    ballot.value = cd.serializeFull[].toVec();

    auto pair = KeyPair.fromSeed(Seed.fromString("SCFPAX2KQEMBHCG6SJ77YTHVOYKUVHEFDROVFCKTZUG7Z6Q5IKSNG6NQ"));

    auto qc = QuorumConfig(2,
        [PublicKey.fromString("GBFDLGQQDDE2CAYVELVPXUXR572ZT5EOTMGJQBPTIHSLPEOEZYQQCEWN"),
         PublicKey.fromString("GBYK4I37MZKLL4A2QS7VJCTDIIJK7UXWQWKXKTQ5WZGT2FPCGIVIQCY5")]);

    auto scp_quorum = toSCPQuorumSet(qc);
    auto qset = makeSharedSCPQuorumSet(scp_quorum);
    auto quorum_hash = hashFull(*qset);
    QuorumSet*[Hash] qmap;

    QuorumSet* getQSet (ref const(Hash) hash)
    {
        if (auto qset = hash in qmap)
            return *qset;

        return QuorumSet*.init;
    }

    Envelope env;
    env.statement.nodeID = NodeID(uint256(pair.address));

    /** SCP PREPARE */
    env.statement.pledges.type_ = StatementType.Prepare;
    env.statement.pledges.prepare_ = Statement.Pledges.Prepare.init; // must initialize
    env.statement.pledges.prepare_.quorum_hash = quorum_hash;
    env.statement.pledges.prepare_.ballot = ballot;
    env.statement.pledges.prepare_.nC = 100;
    env.statement.pledges.prepare_.nH = 200;

    // missing signature
    env.signature = typeof(env.signature).init;

    // missing signature
    static immutable MissingSig = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Prepare { qset: { hash: 0xc048...6205, quorum: <unknown> }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prep: <null>, prepPrime: <null>, nc: 100, nH: 200 } }, sig: 0x0000...0000 }`;

    assert(MissingSig == format("%s", scpPrettify(&env)),
                         format("%s", scpPrettify(&env)));

    env.signature = pair.secret.sign(hashFull(0)[]);

    // null quorum (hash not found)
    static immutable PrepareRes1 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Prepare { qset: { hash: 0xc048...6205, quorum: <unknown> }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prep: <null>, prepPrime: <null>, nc: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // with quorum mapping
    static immutable PrepareRes2 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Prepare { qset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prep: <null>, prepPrime: <null>, nc: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // 'prep' pointer is set
    static immutable PrepareRes3 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Prepare { qset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prep: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prepPrime: <null>, nc: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // 'prepared_prime' pointer is set
    static immutable PrepareRes4 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Prepare { qset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prep: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, prepPrime: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, nc: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    assert(PrepareRes1 == format("%s", scpPrettify(&env)),
                          format("%s", scpPrettify(&env)));

    assert(PrepareRes1 == format("%s", scpPrettify(&env, null)),
                          format("%s", scpPrettify(&env, null)));

    assert(PrepareRes1 == format("%s", scpPrettify(&env, &getQSet)),
                          format("%s", scpPrettify(&env, &getQSet)));

    // add the quorum hash mapping, it should change the output
    qmap[quorum_hash] = qset;
    assert(PrepareRes2 == format("%s", scpPrettify(&env, &getQSet)),
                          format("%s", scpPrettify(&env, &getQSet)));

    // set 'prepared' pointer
    env.statement.pledges.prepare_.prepared = &env.statement.pledges.prepare_.ballot;
    assert(PrepareRes3 == format("%s", scpPrettify(&env, &getQSet)),
                          format("%s", scpPrettify(&env, &getQSet)));

    // set 'prepared_prime' pointer
    env.statement.pledges.prepare_.prepared_prime = &env.statement.pledges.prepare_.ballot;
    assert(PrepareRes4 == format("%s", scpPrettify(&env, &getQSet)),
                          format("%s", scpPrettify(&env, &getQSet)));

    /** SCP CONFIRM */
    env.statement.pledges.type_ = StatementType.Confirm;
    env.statement.pledges.confirm_ = Statement.Pledges.Confirm.init; // must initialize
    env.statement.pledges.confirm_.ballot = ballot;
    env.statement.pledges.confirm_.nPrepared = 42;
    env.statement.pledges.confirm_.nCommit = 100;
    env.statement.pledges.confirm_.nH = 200;

    // confirm without a known hash
    static immutable ConfirmRes1 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Confirm { qset: { hash: 0x0000...0000, quorum: <unknown> }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, nPrep: 42, nComm: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // confirm with a known hash
    static immutable ConfirmRes2 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Confirm { qset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, ballot: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, nPrep: 42, nComm: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // un-deserializable value
    static immutable ConfirmRes3 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Confirm { qset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, ballot: { counter: 0, value: <un-deserializable> }, nPrep: 42, nComm: 100, nH: 200 } }, sig: 0x0af7...b5ab }`;

    // unknown hash
    assert(ConfirmRes1 == format("%s", scpPrettify(&env, &getQSet)),
                         format("%s", scpPrettify(&env, &getQSet)));

    // known hash
    env.statement.pledges.confirm_.quorum_hash = quorum_hash;
    assert(ConfirmRes2 == format("%s", scpPrettify(&env, &getQSet)),
                         format("%s", scpPrettify(&env, &getQSet)));

    // un-deserializable value
    env.statement.pledges.confirm_.ballot = Ballot.init;
    assert(ConfirmRes3 == format("%s", scpPrettify(&env, &getQSet)),
                         format("%s", scpPrettify(&env, &getQSet)));

    // unknown hash
    static immutable ExtRes1 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Externalize { commitQset: { hash: 0x0000...0000, quorum: <unknown> }, commit: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, nh: 100 } }, sig: 0x0af7...b5ab }`;

    // known hash
    static immutable ExtRes2 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Externalize { commitQset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, commit: { counter: 42, value: { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] } }, nh: 100 } }, sig: 0x0af7...b5ab }`;

    // un-deserializable value
    static immutable ExtRes3 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Externalize { commitQset: { hash: 0xc048...6205, quorum: { thresh: 2, nodes: [GBFD...CEWN, GBYK...QCY5], subqs: [] } }, commit: { counter: 0, value: <un-deserializable> }, nh: 100 } }, sig: 0x0af7...b5ab }`;

    /** SCP EXTERNALIZE */
    env.statement.pledges.type_ = StatementType.Externalize;
    env.statement.pledges.externalize_ = Statement.Pledges.Externalize.init; // must initialize
    env.statement.pledges.externalize_.commit = ballot;
    env.statement.pledges.externalize_.nH = 100;

    // unknown hash
    assert(ExtRes1 == format("%s", scpPrettify(&env, &getQSet)),
                      format("%s", scpPrettify(&env, &getQSet)));

    // known hash
    env.statement.pledges.externalize_.commit_quorum_hash = quorum_hash;
    assert(ExtRes2 == format("%s", scpPrettify(&env, &getQSet)),
                      format("%s", scpPrettify(&env, &getQSet)));

    // un-deserializable value
    env.statement.pledges.externalize_.commit = Ballot.init;
    assert(ExtRes3 == format("%s", scpPrettify(&env, &getQSet)),
                      format("%s", scpPrettify(&env, &getQSet)));

    // unknown hash
    static immutable NomRes1 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Nominate { qset: { hash: 0x0000...0000, quorum: <unknown> }, votes: [{ tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }, { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }], accepted: [{ tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }, { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }] } }, sig: 0x0af7...b5ab }`;

    // known hash
    static immutable NomRes2 = `{ statement: { node: GBUV...KOEK, slot_idx: 0, pledge: Nominate { qset: { hash: 0xc048...6205, quorum: <unknown> }, votes: [{ tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }, { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }], accepted: [{ tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }, { tx_set: [Type : Payment, Inputs: None
Outputs (8): GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000),
GCOQ...LRIJ(61,000,000), GCOQ...LRIJ(61,000,000)], enrolls: [{ utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }, { utxo: 0x0000...e26f, seed: 0x4a5e...a33b, cycles: 1008, sig: 0x0000...be78 }] }] } }, sig: 0x0af7...b5ab }`;

    /** SCP NOMINATE */
    env.statement.pledges.type_ = StatementType.Nominate;
    env.statement.pledges.nominate_ = Nomination.init; // must initialize

    auto value = cd.serializeFull[].toVec();

    env.statement.pledges.nominate_.votes ~= value;
    env.statement.pledges.nominate_.votes ~= value;
    env.statement.pledges.nominate_.accepted ~= value;
    env.statement.pledges.nominate_.accepted ~= value;

    // unknown hash
    assert(NomRes1 == format("%s", scpPrettify(&env, &getQSet)),
                      format("%s", scpPrettify(&env, &getQSet)));

    // known hash
    env.statement.pledges.nominate_.quorum_hash = quorum_hash;
    assert(NomRes2 == format("%s", scpPrettify(&env, &getQSet)),
                      format("%s", scpPrettify(&env, &getQSet)));
}
