/*******************************************************************************

    Contains the SCP consensus driver implementation.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.protocol.Nominator;

import agora.common.crypto.Key;
import agora.common.Deserializer;
import agora.common.Hash : Hash, HashDg, hashPart, hashFull;
import agora.common.Serializer;
import agora.common.Set;
import agora.common.Task;
import agora.common.Types : Signature;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.network.NetworkClient;
import agora.node.Ledger;
import agora.utils.Log;
import agora.utils.PrettyPrinter;

import scpd.Cpp;
import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.scp.Slot;
import scpd.scp.Utils;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;
import scpd.Util;

import core.stdc.stdint;
import core.time;

mixin AddLogger!();

/// Ditto
public extern (C++) class Nominator : SCPDriver
{
    /// SCP instance
    private SCP* scp;

    /// Key pair of this node
    private KeyPair key_pair;

    /// Task manager
    private TaskManager taskman;

    /// Ledger instance
    private Ledger ledger;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] peers;

    /// The set of active timers
    /// Todo: SCPTests.cpp uses fake timers,
    /// Similar to how we use FakeClockBanManager!
    private Set!ulong timers;

    /// The set of externalized slot indices
    private Set!uint64_t externalized_slots;

    /// The quorum set
    private SCPQuorumSetPtr[StellarHash] quorum_set;

    private alias TimerType = Slot.timerIDs;
    static assert(TimerType.max == 1);

    /// Tracks unique incremental timer IDs
    private ulong[TimerType.max + 1] last_timer_id;

    /// Timer IDs with >= of the active timer will be allowed to run
    private ulong[TimerType.max + 1] active_timer_ids;

extern(D):

    /***************************************************************************

        Constructor

        Params:
            key_pair = the key pair of this node
            ledger = needed for SCP state restoration & block validation
            taskman = used to run timers
            peers = the set of clients to the peers in the quorum
            quorum_set = the quorum set of this node

    ***************************************************************************/

    public this (KeyPair key_pair, Ledger ledger,
        TaskManager taskman, NetworkClient[PublicKey] peers,
        SCPQuorumSet quorum_set)
    {
        this.key_pair = key_pair;
        auto node_id = NodeID(StellarHash(key_pair.address[]));
        const IsValidator = true;
        this.scp = createSCP(this, node_id, IsValidator, quorum_set);
        this.taskman = taskman;
        this.ledger = ledger;
        this.peers = peers;

        // cast: see makeSharedSCPQuorumSet() in Cpp.d
        auto local_quorum_set = this.scp.getLocalQuorumSet();
        auto localQSet = makeSharedSCPQuorumSet(local_quorum_set);

        const bytes = ByteSlice.make(XDRToOpaque(*localQSet));
        auto quorum_hash = sha256(bytes);
        this.quorum_set[quorum_hash] = localQSet;

        this.restoreSCPState(ledger);
        this.ledger.setNominator(&this.nominateTransactionSet);
    }

    /***************************************************************************

        Nominate a new transaction set to the quorum.
        Failure to nominate is only logged.

        Params:
            slot_idx = the index of the slot to nominate for
            prev = the transaction set of the previous slot
            next = the proposed transaction set for the provided slot index

    ***************************************************************************/

    private void nominateTransactionSet (ulong slot_idx, Set!Transaction prev,
        Set!Transaction next) @trusted
    {
        log.info("{}(): Proposing tx set for slot {}", __FUNCTION__, slot_idx);

        auto prev_value = prev.serializeFull().toVec();
        auto next_value = next.serializeFull().toVec();
        if (this.scp.nominate(slot_idx, next_value, prev_value))
        {
            log.info("{}(): Tx set nominated", __FUNCTION__);
        }
        else
        {
            log.info("{}(): Tx set rejected nomination", __FUNCTION__);
        }
    }

    /***************************************************************************

        Restore SCP's internal state based on the provided ledger state

        Params:
            ledger = the ledger instance

    ***************************************************************************/

    private void restoreSCPState (Ledger ledger)
    {
        import agora.common.Serializer;
        import scpd.types.Stellar_SCP;
        import scpd.types.Utils;
        import scpd.types.Stellar_types : StellarHash = Hash, NodeID;
        import std.range;

        auto key = StellarHash(this.key_pair.address[]);
        auto pub_key = NodeID(key);

        foreach (block_idx, block; ledger.getBlocksFrom(0).enumerate)
        {
            Value block_value = block.serializeFull().toVec();

            SCPStatement statement =
            {
                nodeID: pub_key,
                slotIndex: block_idx,
                pledges: {
                    type_: SCPStatementType.SCP_ST_EXTERNALIZE,
                    externalize_: {
                        commit: {
                            counter: 0,
                            value: block_value,
                        },
                        nH: 0,
                    },
                },
            };

            SCPEnvelope env = SCPEnvelope(statement);
            this.scp.setStateFromEnvelope(block_idx, env);
            if (!this.scp.isSlotFullyValidated(block_idx))
                assert(0);
        }

        // there should at least be a genesis block
        if (this.scp.empty())
            assert(0);
    }

    /***************************************************************************

        Called when a new SCP Envelope is received from the network.

        Params:
            envelope = the SCP envelope

        Returns:
            true if the SCP protocol accepted this envelope

    ***************************************************************************/

    public bool receiveEnvelope (SCPEnvelope envelope) @trusted
    {
        PublicKey key = PublicKey(envelope.statement.nodeID);
        const msg = toHash(envelope.statement)[];
        if (!key.verify(Signature(envelope.signature[]), msg))
        {
            log.trace("Envelope signature is invalid for {}: {}", key, envelope);
            return false;
        }

        return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
    }

    extern (C++):

    /***************************************************************************

        Signs the SCPEnvelope with the node's private key.

        todo: Currently not signing yet. To be done.

        Params:
            envelope = the SCPEnvelope to sign

    ***************************************************************************/

    public override void signEnvelope (ref SCPEnvelope envelope)
    {
        scope (failure) assert(0);
        import core.stdc.stdlib;

        // note: SCP seems to free() this, it has to be malloc-allocated
        auto msg = toHash(envelope.statement)[];
        auto sig = this.key_pair.secret.sign(msg)[];
        auto mem = cast(ubyte*)malloc(sig.length);
        mem[0 .. sig.length] = sig[];

        envelope.signature = mem[0 .. sig.length].toVec();
    }

    /***************************************************************************

        Validates the provided transaction set for the provided slot index,
        and returns a status code of the validation.

        Params:
            slot_idx = the slot index we're currently reaching consensus for
            value = the transaction set to validate
            nomination = unused, seems to be stellar-specific

    ***************************************************************************/

    public override ValidationLevel validateValue (uint64_t slot_idx,
        ref const(Value) value, bool nomination) nothrow
    {
        scope (failure) assert(0);

        try
        {
            auto tx_set = deserializeFull!(Set!Transaction)(
                cast(ubyte[])value[]);

            if (auto fail_reason = this.ledger.validateTxSet(tx_set))
            {
                log.error("validateValue(): Invalid tx set: {}", fail_reason);
                return ValidationLevel.kInvalidValue;
            }
        }
        catch (Exception ex)
        {
            log.error("{}: Received invalid tx set. Error: {}",
                __FUNCTION__, ex.message);

            return ValidationLevel.kInvalidValue;
        }

        return ValidationLevel.kFullyValidatedValue;
    }

    /***************************************************************************

        Called when consenus has been reached for the provided slot index and
        the transaction set.

        Params:
            slot_idx = the slot index
            value = the transaction set

    ***************************************************************************/

    public override void valueExternalized (uint64_t slot_idx,
        ref const(Value) value)
    {
        scope (failure) assert(0);

        if (slot_idx in this.externalized_slots)
            return;  // slot was already externalized
        this.externalized_slots.put(slot_idx);

        auto bytes = cast(ubyte[])value[];
        auto tx_set = deserializeFull!(Set!Transaction)(bytes);

        if (tx_set.length == 0)
            assert(0, "Transaction set empty");

        log.info("Externalized transaction set at {}: {}", slot_idx, tx_set);
        if (!this.ledger.onTXSetExternalized(tx_set))
            assert(0);
    }

    /***************************************************************************

        Params:
            qSetHash = the hash of the quorum set

        Returns:
            the SCPQuorumSet pointer for the provided quorum set hash

    ***************************************************************************/

    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        if (auto scp_quroum = qSetHash in this.quorum_set)
            return *scp_quroum;

        return SCPQuorumSetPtr.init;
    }

    /***************************************************************************

        Floods the given SCPEnvelope to the network of connected peers.

        Params:
            envelope = the SCPEnvelope to flood to the network.

    ***************************************************************************/

    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        try
        {
            foreach (key, node; this.peers)
            {
                // note: cannot deal with const parameter types in the API
                auto env = cast()envelope;

                // note: several error-cases not considered here yet:
                // A) request failure after N attepts => we might have to retry,
                // but exactly how much time do we have before the next round??
                // B) Node rejects the envelope. Possible in circular scenarios,
                // e.g. A => B => C => A (A rejects the envelope because it sent it first)
                node.sendEnvelope(env);
            }
        }
        catch (Exception ex)
        {
            import std.conv;
            assert(0, ex.to!string);
        }
    }

    /***************************************************************************

        Combine a set of transaction sets into a single transaction set.
        This may be done in arbitrary ways, as long as it's consistent
        (for a given input, the combined output is predictable).

        For simplicity we currently only pick the first transaction set
        to become the "combined" transaction set.

        Params:
            slot_idx = the slot index we're currently reaching consensus for
            candidates = a set of a set of transactions

    ***************************************************************************/

    public override Value combineCandidates (uint64_t slot_idx,
        ref const(set!Value) candidates)
    {
        scope (failure) assert(0);

        foreach (ref const(Value) candidate; candidates)
        {
            auto tx_set = deserializeFull!(Set!Transaction)(
                cast(ubyte[])candidate[]);

            if (auto msg = this.ledger.validateTxSet(tx_set))
            {
                log.error("combineCandidates(): Invalid tx set: {}", msg);
                continue;
            }
            else
            {
                log.info("combineCandidates: {}", slot_idx);
            }

            // todo: currently we just pick the first of the candidate values,
            // but we should ideally pick tx's out of the combined set
            return tx_set.serializeFull().toVec();
        }

        assert(0);  // should not reach here
    }

    /***************************************************************************

        Used for setting and clearing C++ callbacks which fire after a
        given timeout.

        On the D side we spawn a new task which waits until a timer expires.

        The callback is a C++ delegate, we use a helper function to invoke it.

        Params:
            slot_idx = the slot index we're currently reaching consensus for.
            timer_type = the timer type (see Slot.timerIDs).
            timeout = the timeout of the timer, in milliseconds.
            callback = the C++ callback to call.

    ***************************************************************************/

    public override void setupTimer (ulong slot_idx, int timer_type,
        milliseconds timeout, CPPDelegate!SCPCallback* callback)
    {
        scope (failure) assert(0);

        const type = cast(TimerType) timer_type;
        assert(type >= TimerType.min && type <= TimerType.max);
        if (callback is null || timeout == 0)
        {
            // signal deactivation of all current timers with this timer type
            this.active_timer_ids[type] = this.last_timer_id[type] + 1;
            return;
        }

        const timer_id = ++this.last_timer_id[type];
        this.taskman.runTask(
        {
            this.taskman.wait(timeout.msecs);

            // timer was cancelled
            if (timer_id < this.active_timer_ids[type])
                return;

            callCPPDelegate(callback);
        });
    }
}

///
private Hash toHash (const scope ref SCPStatement st) nothrow @safe @nogc
{
    static struct Hashed
    {
        const SCPStatement st;

        // trusted due to union access
        void computeHash (scope HashDg dg) const nothrow @trusted @nogc
        {
            hashPart(st.nodeID, dg);
            hashPart(st.slotIndex, dg);
            hashPart(st.pledges.type_, dg);

            switch (st.pledges.type_)
            {
                case SCPStatementType.SCP_ST_PREPARE:
                    computeHash(st.pledges.prepare_, dg);
                    break;

                case SCPStatementType.SCP_ST_CONFIRM:
                    computeHash(st.pledges.confirm_, dg);
                    break;

                case SCPStatementType.SCP_ST_EXTERNALIZE:
                    computeHash(st.pledges.externalize_, dg);
                    break;

                case SCPStatementType.SCP_ST_NOMINATE:
                    computeHash(st.pledges.nominate_, dg);
                    break;

                default:
                    assert(0);
            }
        }

        void computeHash (const ref SCPStatement._pledges_t._prepare_t prep,
            scope HashDg dg) const nothrow @trusted @nogc
        {
            hashPart(prep.quorumSetHash[], dg);
            hashPart(prep.ballot, dg);

            if (prep.prepared !is null)
                hashPart(*prep.prepared, dg);

            if (prep.preparedPrime !is null)
                hashPart(*prep.preparedPrime, dg);

            hashPart(prep.nC, dg);
            hashPart(prep.nH, dg);
        }

        void computeHash (const ref SCPStatement._pledges_t._confirm_t conf,
            scope HashDg dg) const nothrow @trusted @nogc
        {
            hashPart(conf.ballot, dg);
            hashPart(conf.nPrepared, dg);
            hashPart(conf.nCommit, dg);
            hashPart(conf.nH, dg);
            hashPart(conf.quorumSetHash[], dg);
        }

        void computeHash (const ref SCPStatement._pledges_t._externalize_t ext,
            scope HashDg dg) const nothrow @trusted @nogc
        {
            hashPart(ext.commit, dg);
            hashPart(ext.nH, dg);
            hashPart(ext.commitQuorumSetHash[], dg);
        }

        void computeHash (const ref SCPNomination nom, scope HashDg dg)
            const nothrow @trusted @nogc
        {
            hashPart(nom.quorumSetHash[], dg);
            hashPart(nom.votes[], dg);
            hashPart(nom.accepted[], dg);
        }
    }

    return Hashed(st).hashFull();
}

///
unittest
{
    SCPStatement st;
    SCPBallot ballot;

    st.pledges.prepare_ = SCPStatement._pledges_t._prepare_t.init;
    st.pledges.prepare_.prepared = &ballot;
    st.pledges.prepare_.preparedPrime = &ballot;
    st.pledges.type_ = SCPStatementType.SCP_ST_PREPARE;
    assert(st.toHash() == Hash.fromString(
        "0x266223f3385aecddc64e02e21cb655d1693002d5da8e49e2c9a73afe0cf3ceac4" ~
        "90b28fdfb42b0d67e7796593907947fb227b1045cf9b14785ba7d34c4305dbf"));

    st.pledges.nominate_ = SCPNomination.init;
    st.pledges.type_ = SCPStatementType.SCP_ST_NOMINATE;
    assert(st.toHash() == Hash.fromString(
        "0xc359847b8ddce220c896386c6b05fd12acb36fb850bd4b3959cf97516b9360eda" ~
        "98f9728911e678c342e23e38e300b1872faeddfa4ccd619404f3d9b7fc17439"));

    st.pledges.confirm_ = SCPStatement._pledges_t._confirm_t.init;
    st.pledges.type_ = SCPStatementType.SCP_ST_CONFIRM;
    assert(st.toHash() == Hash.fromString(
        "0x118121cc790639f11190bb5ea1f8023c7889f8484b69b2d13b7056f831b2b5741" ~
        "afe7511a59d24f193fcce5c19080a5ca74ebc8487f1f340d70092066cd11f90"));

    st.pledges.externalize_ = SCPStatement._pledges_t._externalize_t.init;
    st.pledges.type_ = SCPStatementType.SCP_ST_EXTERNALIZE;
    assert(st.toHash() == Hash.fromString(
        "0x3c5a1a66ecf0c1e8992f448718fb1f4a6cbfb9527adba408644caefda8c1b1353" ~
        "98dbc0c33174280e8b0a5fb835dc707f06394c1205f8be545e5f70c771b421d"));
}
